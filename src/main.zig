const std = @import("std");
const xev = @import("xev");

const Allocator = std.mem.Allocator;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const addr: std.net.Address = try .parseIp4("127.0.0.1", 2113);
    const tcp: xev.TCP = try .init(addr);
    try tcp.bind(addr);
    try tcp.listen(128);
    var tcp_c: xev.Completion = .{};

    var server: Server = .{ .gpa = gpa.allocator(), .connections = .empty };
    tcp.accept(&loop, &tcp_c, Server, &server, Server.onAccept);

    std.log.info("Listening on :{d}", .{addr.getPort()});
    try loop.run(.until_done);
}

const Server = struct {
    gpa: std.mem.Allocator,
    connections: std.ArrayListUnmanaged(*Connection),

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
            std.log.err("Accept error: {}", .{err});
            return .rearm;
        };
        std.log.debug("Accepted connection.", .{});

        self.accept(loop, client) catch |err| {
            std.log.err("Couldn't accept connection: {}", .{err});
        };

        return .rearm;
    }

    // Initializes the connection
    fn accept(self: *Server, loop: *xev.Loop, client: xev.TCP) !void {
        const conn = try self.gpa.create(Connection);
        conn.init(self.gpa, client);

        try self.connections.append(self.gpa, conn);

        conn.tcp.read(
            loop,
            &conn.read_c,
            .{ .slice = &conn.read_buf },
            Connection,
            conn,
            Connection.onRead,
        );
    }
};

const Connection = struct {
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

    fn onRead(
        ud: ?*Connection,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: xev.TCP,
        rb: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const n = result catch |err| {
            switch (err) {
                error.EOF => {}, // client disconnected
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
            return .disarm;
        }
        const self = ud.?;
        const bytes = rb.slice[0..n];
        self.processRead(loop, bytes) catch |err| {
            switch (err) {
                error.OutOfMemory => return .disarm,
            }
        };
        return .rearm;
    }

    fn processRead(self: *Connection, loop: *xev.Loop, bytes: []const u8) Allocator.Error!void {
        std.log.info("read: {s}", .{bytes});
        try self.write("hey");
        try self.queueWrite(loop);
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
            std.log.err("write error: {}", .{err});
            return .disarm;
        };
        std.log.debug("write: {s}", .{wb.slice[0..n]});

        // Incomplete write. Insert the unwritten portion at the front of the list and we'll requeue
        if (n < wb.slice.len) {
            self.write_buf.insertSlice(self.gpa, 0, wb.slice[n..]) catch |err| {
                std.log.err("couldn't insert unwritten bytes: {}", .{err});
                return .disarm;
            };
        }
        self.queueWrite(loop) catch {};
        return .disarm;
    }
};
