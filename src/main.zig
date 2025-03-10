const std = @import("std");
const xev = @import("xev");

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const IrcError = error{
    InputTooLong, // 417
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    const addr: std.net.Address = try .parseIp4("127.0.0.1", 6667);
    const tcp: xev.TCP = try .init(addr);
    try tcp.bind(addr);
    try tcp.listen(256);
    var tcp_c: xev.Completion = .{};

    var server: Server = .init(gpa.allocator(), "localhost");
    defer server.deinit();
    tcp.accept(&loop, &tcp_c, Server, &server, Server.onAccept);

    std.log.info("Listening on :{d}", .{addr.getPort()});
    try loop.run(.until_done);
}

const Capability = enum {
    sasl,
};

const Server = struct {
    const log = std.log.scoped(.server);
    // We allow tags, so our maximum is 4096 + 512
    const max_message_len = 4096 + 512;
    gpa: std.mem.Allocator,
    connections: std.AutoHashMapUnmanaged(xev.TCP, *Connection),
    hostname: []const u8,

    fn init(gpa: std.mem.Allocator, hostname: []const u8) Server {
        return .{
            .gpa = gpa,
            .connections = .empty,
            .hostname = hostname,
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

    fn handleClientDisconnect(self: *Server, client: xev.TCP) void {
        log.info("client disconnected: fd={d}", .{client.fd});
        std.posix.close(client.fd);
        const conn = self.connections.get(client) orelse return;
        conn.deinit();
        _ = self.connections.remove(client);
        self.gpa.destroy(conn);
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

        // Get the read result
        const n = result catch |err| {
            switch (err) {
                error.EOF => {
                    // client disconnected
                    self.handleClientDisconnect(client);
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

        // Handle a disconnected client
        if (n == 0) {
            self.handleClientDisconnect(client);
            return .disarm;
        }

        // Get the client
        const conn = self.connections.get(client) orelse {
            log.warn("client not found: fd={d}", .{client.fd});
            self.handleClientDisconnect(client);
            return .disarm;
        };

        // Process the newly read bytes
        self.processMessages(conn, rb.slice[0..n]) catch |err| {
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

    fn processMessages(self: *Server, conn: *Connection, bytes: []const u8) Allocator.Error!void {
        const buf: []const u8 =
            // If we have no queue, and this message is complete, we can process without allocating
            if (conn.read_queue.items.len == 0 and std.mem.endsWith(u8, bytes, "\n"))
                bytes
            else blk: {
                try conn.read_queue.appendSlice(self.gpa, bytes);
                break :blk conn.read_queue.items;
            };

        var iter: MessageIterator = .{ .bytes = buf };
        while (iter.next()) |raw| {
            log.debug("read: {s}", .{raw});
            const msg: Message = .init(raw);
            const cmd = msg.command();

            const client_msg = ClientMessage.fromString(cmd) orelse {
                try self.errUnknownCommand(conn, cmd);
                continue;
            };

            switch (client_msg) {
                .CAP => try self.handleCap(conn, msg),
                .PING => try self.handlePing(conn, msg),
                else => {
                    log.err("unhandled message: {s}", .{@tagName(client_msg)});
                },
            }
        }

        // if our read_queue is empty, we are done
        if (conn.read_queue.items.len == 0) return;

        // Clean up the read_queue

        // Replace the amount we read
        conn.read_queue.replaceRangeAssumeCapacity(0, iter.bytesRead(), "");

        if (conn.read_queue.items.len == 0) {
            // If we consumed the entire thing, reclaim the memory
            conn.read_queue.clearAndFree(self.gpa);
        } else if (conn.read_queue.items.len > Server.max_message_len) {
            // If we have > max_message_size bytes, we send an error
            conn.read_queue.clearAndFree(self.gpa);
            // TODO: error.InputTooLong;
        }
    }

    fn handleCap(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        var iter = msg.paramIterator();
        const subcmd = iter.next() orelse return self.errNeedMoreParams(conn, "CAP");

        if (std.mem.eql(u8, subcmd, "LS")) {
            // LS lists available capabilities
            // We expect a 302, but we don't actually care
            if (iter.next()) |version| {
                log.debug("received cap ls version: {s}", .{version});
            }
            try conn.print(
                ":{s} CAP {s} LS :",
                .{ self.hostname, conn.nickname() },
            );
            for (std.meta.fieldNames(Capability), 0..) |cap, i| {
                if (i > 0) try conn.write(" ");
                try conn.write(cap);
            }
            try conn.write("\r\n");
        } else if (std.mem.eql(u8, subcmd, "LIST")) {
            // LIST lists enabled capabilities
        } else if (std.mem.eql(u8, subcmd, "REQ")) {
            // REQ tries to enable the given capability
            while (iter.next()) |cap_str| {
                const cap = std.meta.stringToEnum(Capability, cap_str) orelse {
                    try conn.print(
                        ":{s} CAP {s} NAK {s}\r\n",
                        .{ self.hostname, conn.nickname(), cap_str },
                    );
                    continue;
                };
                try conn.enableCap(cap);
                try conn.print(
                    ":{s} CAP {s} ACK {s}\r\n",
                    .{ self.hostname, conn.nickname(), cap_str },
                );
            }
        } else if (std.mem.eql(u8, subcmd, "END")) {
            // END signals the end of capability negotiation
        }
    }

    fn handlePing(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        try conn.write_buf.writer(conn.gpa).print(
            ":{s} PONG {s} :{s}\r\n",
            .{ self.hostname, self.hostname, msg.rawParameters() },
        );
    }

    fn errNeedMoreParams(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        try conn.write_buf.writer(conn.gpa).print(
            ":{s} 461 {s} {s} :Not enough paramaters\r\n",
            .{ self.hostname, conn.nickname(), cmd },
        );
    }

    fn errUnknownCommand(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        try conn.write_buf.writer(conn.gpa).print(
            ":{s} 421 {s} {s} :Unknown command",
            .{ self.hostname, conn.nickname(), cmd },
        );
    }
};

/// an irc message
const Message = struct {
    bytes: []const u8,
    timestamp_s: u32 = 0,

    pub fn init(bytes: []const u8) Message {
        return .{
            .bytes = bytes,
            .timestamp_s = @intCast(std.time.timestamp()),
        };
    }

    pub const ParamIterator = struct {
        params: ?[]const u8,
        index: usize = 0,

        pub fn next(self: *ParamIterator) ?[]const u8 {
            const params = self.params orelse return null;
            if (self.index >= params.len) return null;

            // consume leading whitespace
            while (self.index < params.len) {
                if (params[self.index] != ' ') break;
                self.index += 1;
            }

            const start = self.index;
            if (start >= params.len) return null;

            // If our first byte is a ':', we return the rest of the string as a
            // single param (or the empty string)
            if (params[start] == ':') {
                self.index = params.len;
                if (start == params.len - 1) {
                    return "";
                }
                return params[start + 1 ..];
            }

            // Find the first index of space. If we don't have any, the reset of
            // the line is the last param
            self.index = std.mem.indexOfScalarPos(u8, params, self.index, ' ') orelse {
                defer self.index = params.len;
                return params[start..];
            };

            return params[start..self.index];
        }
    };

    pub const Tag = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const TagIterator = struct {
        tags: []const u8,
        index: usize = 0,

        // tags are a list of key=value pairs delimited by semicolons.
        // key[=value] [; key[=value]]
        pub fn next(self: *TagIterator) ?Tag {
            if (self.index >= self.tags.len) return null;

            // find next delimiter
            const end = std.mem.indexOfScalarPos(u8, self.tags, self.index, ';') orelse self.tags.len;
            var kv_delim = std.mem.indexOfScalarPos(u8, self.tags, self.index, '=') orelse end;
            // it's possible to have tags like this:
            //     @bot;account=botaccount;+typing=active
            // where the first tag doesn't have a value. Guard against the
            // kv_delim being past the end position
            if (kv_delim > end) kv_delim = end;

            defer self.index = end + 1;

            return .{
                .key = self.tags[self.index..kv_delim],
                .value = if (end == kv_delim) "" else self.tags[kv_delim + 1 .. end],
            };
        }
    };

    pub fn tagIterator(msg: Message) TagIterator {
        const src = msg.bytes;
        if (src[0] != '@') return .{ .tags = "" };

        assert(src.len > 1);
        const n = std.mem.indexOfScalarPos(u8, src, 1, ' ') orelse src.len;
        return .{ .tags = src[1..n] };
    }

    pub fn source(msg: Message) ?[]const u8 {
        const src = msg.bytes;
        var i: usize = 0;

        // get past tags
        if (src[0] == '@') {
            assert(src.len > 1);
            i = std.mem.indexOfScalarPos(u8, src, 1, ' ') orelse return null;
        }

        // consume whitespace
        while (i < src.len) : (i += 1) {
            if (src[i] != ' ') break;
        }

        // Start of source
        if (src[i] == ':') {
            assert(src.len > i);
            i += 1;
            const end = std.mem.indexOfScalarPos(u8, src, i, ' ') orelse src.len;
            return src[i..end];
        }

        return null;
    }

    pub fn command(msg: Message) []const u8 {
        const src = msg.bytes;
        var i: usize = 0;

        // get past tags
        if (src[0] == '@') {
            assert(src.len > 1);
            i = std.mem.indexOfScalarPos(u8, src, 1, ' ') orelse return "";
        }
        // consume whitespace
        while (i < src.len) : (i += 1) {
            if (src[i] != ' ') break;
        }

        // get past source
        if (src[i] == ':') {
            assert(src.len > i);
            i += 1;
            i = std.mem.indexOfScalarPos(u8, src, i, ' ') orelse return "";
        }
        // consume whitespace
        while (i < src.len) : (i += 1) {
            if (src[i] != ' ') break;
        }

        assert(src.len > i);
        // Find next space
        const end = std.mem.indexOfScalarPos(u8, src, i, ' ') orelse src.len;

        return src[i..end];
    }

    pub fn paramIterator(msg: Message) ParamIterator {
        return .{ .params = msg.rawParameters() };
    }

    pub fn rawParameters(msg: Message) []const u8 {
        const src = msg.bytes;
        var i: usize = 0;

        // get past tags
        if (src[0] == '@') {
            i = std.mem.indexOfScalarPos(u8, src, 0, ' ') orelse return "";
        }
        // consume whitespace
        while (i < src.len) : (i += 1) {
            if (src[i] != ' ') break;
        }

        // get past source
        if (src[i] == ':') {
            assert(src.len > i);
            i += 1;
            i = std.mem.indexOfScalarPos(u8, src, i, ' ') orelse return "";
        }
        // consume whitespace
        while (i < src.len) : (i += 1) {
            if (src[i] != ' ') break;
        }

        // get past command
        i = std.mem.indexOfScalarPos(u8, src, i, ' ') orelse return "";

        assert(src.len > i);
        return src[i + 1 ..];
    }

    /// Returns the value of the tag 'key', if present
    pub fn getTag(self: Message, key: []const u8) ?[]const u8 {
        var tag_iter = self.tagIterator();
        while (tag_iter.next()) |tag| {
            if (!std.mem.eql(u8, tag.key, key)) continue;
            return tag.value;
        }
        return null;
    }

    pub fn compareTime(_: void, lhs: Message, rhs: Message) bool {
        return lhs.timestamp_s < rhs.timestamp_s;
    }
};

const ClientMessage = enum {
    // Connection Messages
    CAP,
    AUTHENTICATE,
    PASS,
    NICK,
    USER,
    PING,
    PONG,
    OPER,
    QUIT,
    ERROR,

    // Channel Ops
    JOIN,
    PART,
    TOPIC,
    NAMES,
    LIST,
    INVITE,
    KICK,

    // Server queries and commands
    MOTD,
    VERSION,
    ADMIN,
    CONNECT,
    LUSERS,
    TIME,
    STATS,
    HELP,
    INFO,
    MODE,

    // Sending messages
    PRIVMSG,
    NOTICE,

    // User-based queries
    WHO,
    WHOIS,
    WHOWAS,

    // Operator messages
    KILL,
    REHASH,
    RESTART,
    SQUIT,

    // Optional messages
    AWAY,
    LINKS,
    USERHOST,
    WALLOPS,

    fn fromString(str: []const u8) ?ClientMessage {
        inline for (@typeInfo(ClientMessage).@"enum".fields) |enumField| {
            if (std.ascii.eqlIgnoreCase(str, enumField.name)) {
                return @field(ClientMessage, enumField.name);
            }
        }
        return null;
    }
};

const Connection = struct {
    const log = std.log.scoped(.conn);

    const State = enum {
        pre_registration,
        registered,
    };
    gpa: Allocator,
    tcp: xev.TCP,

    state: State,

    read_c: xev.Completion,
    read_buf: [1024]u8,
    read_queue: std.ArrayListUnmanaged(u8),

    write_c: xev.Completion,
    write_buf: std.ArrayListUnmanaged(u8),

    nick: []const u8,

    caps: std.AutoHashMapUnmanaged(Capability, bool),

    fn init(self: *Connection, gpa: Allocator, tcp: xev.TCP) void {
        self.* = .{
            .gpa = gpa,
            .tcp = tcp,

            .state = .pre_registration,

            .read_c = .{},
            .read_buf = undefined,
            .read_queue = .empty,

            .write_c = .{},
            .write_buf = .empty,

            .nick = "",
            .caps = .empty,
        };
    }

    fn nickname(self: *Connection) []const u8 {
        switch (self.state) {
            .pre_registration => return "*",
            .registered => return self.nick,
        }
    }

    fn deinit(self: *Connection) void {
        self.read_queue.deinit(self.gpa);
        self.write_buf.deinit(self.gpa);
    }

    /// Process the read queue
    fn processReadQueue(self: *Connection, bytes: []const u8, server: *Server) Allocator.Error!void {
        _ = server;
        const buf: []const u8 =
            // If we have no queue, and this message is complete, we can process without allocating
            if (self.read_queue.items.len == 0 and std.mem.endsWith(u8, bytes, "\n"))
                bytes
            else blk: {
                try self.read_queue.appendSlice(self.gpa, bytes);
                break :blk self.read_queue.items;
            };

        var iter: MessageIterator = .{ .bytes = buf };
        while (iter.next()) |msg| {
            log.debug("read: {s}", .{msg});
        }

        // if our read_queue is empty, we are done
        if (self.read_queue.items.len == 0) return;

        // Clean up the read_queue

        // Replace the amount we read
        self.read_queue.replaceRangeAssumeCapacity(0, iter.bytesRead(), "");

        if (self.read_queue.items.len == 0) {
            // If we consumed the entire thing, reclaim the memory
            self.read_queue.clearAndFree(self.gpa);
        } else if (self.read_queue.items.len > Server.max_message_len) {
            // If we have > max_message_size bytes, we send an error
            self.read_queue.clearAndFree(self.gpa);
            // TODO: error.InputTooLong;
        }
    }

    fn write(self: *Connection, bytes: []const u8) Allocator.Error!void {
        try self.write_buf.appendSlice(self.gpa, bytes);
    }

    fn print(self: *Connection, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        return self.write_buf.writer(self.gpa).print(fmt, args);
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

    fn processMessage(self: *Connection, message: []const u8) IrcError!void {
        // First, we check if message is valid length
        if (message.len > Server.max_message_len) return error.InputTooLong;
        _ = self;
    }

    fn enableCap(self: *Connection, cap: Capability) Allocator.Error!void {
        try self.caps.put(self.gpa, cap, true);
    }
};

const MessageIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    /// Returns the next message. Trailing \r\n is is removed
    fn next(self: *MessageIterator) ?[]const u8 {
        if (self.index >= self.bytes.len) return null;
        const n = std.mem.indexOfScalarPos(u8, self.bytes, self.index, '\n') orelse return null;
        defer self.index = n + 1;
        return std.mem.trimRight(u8, self.bytes[self.index..n], "\r\n");
    }

    fn bytesRead(self: MessageIterator) usize {
        return self.index;
    }
};
