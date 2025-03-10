const std = @import("std");
const xev = @import("xev");

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const addr: std.net.Address = try .parseIp4("127.0.0.1", 2113);
    const tcp: xev.TCP = try .init(addr);
    try tcp.bind(addr);
    try tcp.listen(256);
    var tcp_c: xev.Completion = .{};

    var server: Server = .init(gpa.allocator());
    defer server.deinit();
    tcp.accept(&loop, &tcp_c, Server, &server, Server.onAccept);

    std.log.info("Listening on :{d}", .{addr.getPort()});
    try loop.run(.until_done);
}

const Server = struct {
    const log = std.log.scoped(.server);
    gpa: std.mem.Allocator,
    connections: std.AutoHashMapUnmanaged(xev.TCP, *Connection),

    fn init(gpa: std.mem.Allocator) Server {
        return .{
            .gpa = gpa,
            .connections = .empty,
        };
    }

    fn deinit(self: *Server) void {
        log.info("shutting down", .{});
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            const tcp = entry.key_ptr.*;
            std.posix.close(tcp.fd);
            const conn = entry.value_ptr.*;
            conn.deinit();
            self.gpa.destroy(conn);
        }
        self.connections.deinit(self.gpa);
    }

    /// xev callback when a connection occurs
    fn onAccept(
        ud: ?*Server,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.AcceptError!xev.TCP,
    ) xev.CallbackAction {
        const self = ud.?;

        // Accept the connection
        const client = result catch |err| {
            log.err("accept error: {}", .{err});
            return .rearm;
        };
        log.debug("accepted connection: fd={d}", .{client.fd});

        self.accept(loop, client) catch |err| {
            log.err("couldn't accept connection: fd={d}", .{client.fd});
            switch (err) {
                error.OutOfMemory => return .disarm,
            }
        };

        return .rearm;
    }

    // Initializes the connection
    fn accept(self: *Server, loop: *xev.Loop, client: xev.TCP) Allocator.Error!void {
        const conn = try self.gpa.create(Connection);
        conn.init(self.gpa, client);

        try self.connections.put(self.gpa, client, conn);

        conn.tcp.read(
            loop,
            &conn.read_c,
            .{ .slice = &conn.read_buf },
            Server,
            self,
            Server.onRead,
        );
    }

    fn onRead(
        ud: ?*Server,
        loop: *xev.Loop,
        _: *xev.Completion,
        client: xev.TCP,
        rb: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = ud.?;
        const conn = self.connections.get(client) orelse {
            log.warn("client not found: {d}", .{client.fd});
            // TODO: do we need to try and close the fd?
            return .disarm;
        };
        const n = result catch |err| {
            switch (err) {
                error.EOF => { // client disconnected
                    log.info("client disconnected: fd={d}", .{client.fd});
                    conn.deinit();
                    _ = self.connections.remove(client);
                    self.gpa.destroy(conn);
                    return .disarm;
                },
                error.Canceled,
                error.Unexpected,
                error.ConnectionReset,
                => {},
            }
            std.log.err("err: {}", .{err});
            return .disarm;
        };
        if (n == 0) {
            // client disconnected
            log.info("client disconnected: fd={d}", .{client.fd});
            conn.deinit();
            _ = self.connections.remove(client);
            self.gpa.destroy(conn);
            return .disarm;
        }
        const bytes = rb.slice[0..n];
        conn.processRead(bytes) catch |err| {
            log.err("couldn't process message: fd={d}", .{client.fd});
            switch (err) {
                error.OutOfMemory => return .disarm,
            }
        };

        conn.queueWrite(loop) catch |err| {
            log.err("couldn't queue write: fd={d}", .{client.fd});
            switch (err) {
                error.OutOfMemory => return .disarm,
            }
        };
        return .rearm;
    }
};

const Connection = struct {
    const log = std.log.scoped(.conn);
    gpa: Allocator,
    tcp: xev.TCP,
    read_c: xev.Completion,
    read_buf: [1024]u8,
    read_queue: std.ArrayListUnmanaged(u8),

    write_c: xev.Completion,
    write_buf: std.ArrayListUnmanaged(u8),

    fn init(self: *Connection, gpa: Allocator, tcp: xev.TCP) void {
        self.* = .{
            .gpa = gpa,
            .tcp = tcp,

            .read_c = .{},
            .read_buf = undefined,
            .read_queue = .empty,

            .write_c = .{},
            .write_buf = .empty,
        };
    }

    fn deinit(self: *Connection) void {
        self.read_queue.deinit(self.gpa);
        self.write_buf.deinit(self.gpa);
    }

    /// Process the bytes
    fn processRead(self: *Connection, bytes: []const u8) Allocator.Error!void {
        log.debug("read: {s}", .{bytes});

        // If our queue is empty and this is a full message, we can process without allocating
        if (self.read_queue.items.len == 0 and endsWithCRLF(bytes)) {} else {
            try self.read_queue.appendSlice(self.gpa, bytes);
        }
    }

    fn write(self: *Connection, bytes: []const u8) Allocator.Error!void {
        try self.write_buf.appendSlice(self.gpa, bytes);
    }

    /// queues a write of the pending buffer. If there is nothing to queue, this is a noop
    fn queueWrite(self: *Connection, loop: *xev.Loop) Allocator.Error!void {
        if (self.write_buf.items.len == 0) return;
        const buf = try self.write_buf.toOwnedSlice(self.gpa);
        self.tcp.write(
            loop,
            &self.write_c,
            .{ .slice = buf },
            Connection,
            self,
            Connection.onWrite,
        );
    }

    fn onWrite(
        ud: ?*Connection,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        wb: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self = ud.?;
        defer self.gpa.free(wb.slice);

        const n = result catch |err| {
            switch (err) {
                error.Canceled,
                error.BrokenPipe,
                error.ConnectionReset,
                error.Unexpected,
                => {},
            }
            log.err("write error: {}", .{err});
            return .disarm;
        };
        log.debug("write: {s}", .{wb.slice[0..n]});

        // Incomplete write. Insert the unwritten portion at the front of the list and we'll requeue
        if (n < wb.slice.len) {
            self.write_buf.insertSlice(self.gpa, 0, wb.slice[n..]) catch |err| {
                log.err("couldn't insert unwritten bytes: {}", .{err});
                return .disarm;
            };
        }
        self.queueWrite(loop) catch {};
        return .disarm;
    }
};

/// Flexible detection of ending with CRLF. From https://modern.ircdocs.horse/#message-format:
///     Servers SHOULD handle single \n character, and MAY handle a single \r character, as if it
///     was a \r\n pair, to support existing clients that might send this.
fn endsWithCRLF(bytes: []const u8) bool {
    return std.mem.endsWith(u8, bytes, "\r") or std.mem.endsWith(u8, bytes, "\n");
}
