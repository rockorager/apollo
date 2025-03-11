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

    var server: Server = undefined;
    try server.init(gpa.allocator(), "localhost", 0);
    defer server.deinit();

    try server.loop.run(.until_done);
}

const Capability = enum {
    sasl,
};

const Sasl = union(enum) {
    plain: struct {
        username: []const u8,
        password: []const u8,
    },
    oauthbearer: []const u8,
};

const WakeupResult = union(enum) {
    atproto_auth: struct {
        conn: *Connection,
        result: std.http.Client.FetchResult,
        response: []const u8,
    },
};

const Server = struct {
    const log = std.log.scoped(.server);
    // We allow tags, so our maximum is 4096 + 512
    const max_message_len = 4096 + 512;

    gpa: std.mem.Allocator,
    loop: xev.Loop,
    connections: std.AutoHashMapUnmanaged(xev.TCP, *Connection),
    hostname: []const u8,

    pds_server: []const u8,

    thread_pool: std.Thread.Pool,
    wakeup: xev.Async,
    wakeup_results: std.ArrayListUnmanaged(WakeupResult),
    wakeup_mutex: std.Thread.Mutex,

    completion_pool: std.heap.MemoryPool(xev.Completion),

    fn init(
        self: *Server,
        gpa: std.mem.Allocator,
        hostname: []const u8,
        port: u16,
    ) !void {
        self.* = .{
            .gpa = gpa,
            .loop = try xev.Loop.init(.{}),
            .connections = .empty,
            .hostname = hostname,
            .pds_server = "https://bsky.social",
            .thread_pool = undefined,
            .wakeup = try .init(),
            .wakeup_results = .empty,
            .wakeup_mutex = .{},
            .completion_pool = .init(gpa),
        };
        try self.thread_pool.init(.{ .allocator = gpa });

        // Resolve hostname to an ip
        var list = try std.net.getAddressList(gpa, hostname, port);
        defer list.deinit();

        if (list.addrs.len == 0) {
            return error.NoAddressFound;
        }

        // Start listening at addr
        const addr = list.addrs[0];
        const tcp: xev.TCP = try .init(addr);
        try tcp.bind(addr);
        try tcp.listen(256);
        const tcp_c = try self.completion_pool.create();
        tcp.accept(&self.loop, tcp_c, Server, self, Server.onAccept);
        std.log.info("Listening at {}", .{addr});

        // Start listening for our wakeup
        const wakeup_c = try self.completion_pool.create();
        self.wakeup.wait(&self.loop, wakeup_c, Server, self, Server.onWakeup);
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
        while (self.wakeup_results.pop()) |result| {
            switch (result) {
                .atproto_auth => |atproto_auth| {
                    self.gpa.free(atproto_auth.response);
                },
            }
        }
        self.wakeup_results.deinit(self.gpa);
        self.connections.deinit(self.gpa);
        self.completion_pool.deinit();
        self.loop.deinit();
        self.thread_pool.deinit();
    }

    fn onWakeup(
        ud: ?*Server,
        _: *xev.Loop,
        _: *xev.Completion,
        r: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        const self = ud.?;
        _ = r catch |err| {
            log.err("wait error: {}", .{err});
        };

        // Drain anything that may have woken us up
        self.wakeup_mutex.lock();
        defer self.wakeup_mutex.unlock();
        while (self.wakeup_results.pop()) |result| {
            switch (result) {
                .atproto_auth => |response| {
                    self.handleAtprotoAuth(response.conn, response.result, response.response) catch |err| {
                        log.err("couldn't handle atproto auth: {}", .{err});
                        continue;
                    };
                },
            }
        }
        return .rearm;
    }

    fn handleAtprotoAuth(
        self: *Server,
        conn: *Connection,
        result: std.http.Client.FetchResult,
        payload: []const u8,
    ) !void {
        defer self.gpa.free(payload);
        switch (result.status) {
            .ok,
            .bad_request,
            .unauthorized,
            => {},
            else => {
                log.err("sasl failure {s} {d}", .{ @tagName(result.status), result.status });
                return self.errSaslFail(conn, @tagName(result.status));
            },
        }
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            self.gpa,
            payload,
            .{ .allocate = .alloc_always },
        );
        switch (result.status) {
            .ok => {},
            .bad_request => {
                defer parsed.deinit();
                const msg = parsed.value.object.get("error") orelse {
                    return self.errSaslFail(conn, "bad atproto response");
                };
                return self.errSaslFail(conn, msg.string);
            },
            .unauthorized => {
                defer parsed.deinit();
                const msg = parsed.value.object.get("message") orelse {
                    return self.errSaslFail(conn, "bad atproto response");
                };
                return self.errSaslFail(conn, msg.string);
            },
            else => unreachable,
        }

        // Now that we are authenticated, we check the nicknames for collisions
        try self.checkNickForCollisions(conn);
        try std.json.stringify(parsed.value, .{ .whitespace = .indent_2 }, std.io.getStdErr().writer());
        conn.state = .authenticated;
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

        const completion = try self.completion_pool.create();

        conn.tcp.read(
            loop,
            completion,
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
        c: *xev.Completion,
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
                    self.completion_pool.destroy(c);
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
            self.completion_pool.destroy(c);
            return .disarm;
        }

        // Get the client
        const conn = self.connections.get(client) orelse {
            log.warn("client not found: fd={d}", .{client.fd});
            self.handleClientDisconnect(client);
            self.completion_pool.destroy(c);
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
                .NICK => try self.handleNick(conn, msg),
                .USER => try self.handleUser(conn, msg),
                .AUTHENTICATE => try self.handleAuthenticate(conn, msg),
                .PING => try self.handlePing(conn, msg),
                else => try self.errUnknownCommand(conn, cmd),
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
        switch (conn.state) {
            .pre_registration => conn.state = .cap_negotiation,
            else => {},
        }
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
                if (std.mem.eql(u8, "sasl", cap)) try conn.write("=PLAIN");
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
            if (conn.nick.len == 0 or conn.user.len == 0) {
                return self.errUnknownError(conn, "CAP END", "No nick or username given");
            }
            conn.state = .registered;
        }
    }

    fn handleNick(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        var iter = msg.paramIterator();
        const nick = iter.next() orelse {
            return conn.print(
                ":{s} 431 {s} :No nickname given\r\n",
                .{ self.hostname, conn.nickname() },
            );
        };
        if (!nickIsValid(nick))
            return conn.print(
                ":{s} 432 {s} :Erroneous nickname\r\n",
                .{ self.hostname, conn.nickname() },
            );

        try conn.setNick(nick);

        if (conn.state == .authenticated) {
            try self.checkNickForCollisions(conn);
        }
    }

    fn checkNickForCollisions(self: *Server, conn: *Connection) Allocator.Error!void {
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |c| {
            // If the nicknames aren't equal, keep going
            if (!std.mem.eql(u8, conn.nick, c.*.nickname())) continue;
            // The nicknames are equal. Check if the account is the same

            if (std.mem.eql(u8, conn.user, c.*.user)) {
                // The account *is* the same. We allow the same nick to be used again
                return;
            }

            defer {
                self.gpa.free(conn.nick);
                conn.nick = "";
            }
            return conn.print(
                ":{s} 433 {s} {s} :Nickname is already in user\r\n",
                .{ self.hostname, conn.nickname(), conn.nick },
            );
        }
    }

    fn handleUser(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        switch (conn.state) {
            .pre_registration => conn.state = .registered,
            .cap_negotiation,
            .sasl_plain,
            .sasl_oauthbearer,
            => {},
            .registered,
            .authenticated,
            => return conn.print(
                ":{s} 462 {s} : You may not reregister\r\n",
                .{ self.hostname, conn.nickname() },
            ),
        }
        var iter = msg.paramIterator();
        const username = iter.next() orelse return self.errNeedMoreParams(conn, "USER");
        // "0"
        _ = iter.next() orelse return self.errNeedMoreParams(conn, "USER");
        // "*"
        _ = iter.next() orelse return self.errNeedMoreParams(conn, "USER");

        const realname = iter.next() orelse return self.errNeedMoreParams(conn, "USER");
        try conn.setUsernameAndRealname(username, realname);

        if (conn.state == .pre_registration) {
            // If we didn't do cap negotiation, we are now registered
            conn.state = .registered;
            // TODO: complete registration
        }
    }

    fn handleAuthenticate(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        var iter = msg.paramIterator();
        switch (conn.state) {
            .pre_registration,
            .cap_negotiation,
            .registered,
            .authenticated,
            => {
                // We first must get AUTHENTICATE <mechanism>
                const mechanism = iter.next() orelse
                    return self.errNeedMoreParams(conn, "AUTHENTICATE");
                if (std.ascii.eqlIgnoreCase("PLAIN", mechanism)) {
                    conn.state = .sasl_plain;
                    return conn.write("AUTHENTICATE +\r\n");
                }
                if (std.ascii.eqlIgnoreCase("OAUTHBEARER", mechanism)) {
                    conn.state = .sasl_oauthbearer;
                    return conn.write("AUTHENTICATE +\r\n");
                }

                return conn.print(
                    ":{s} 908 {s} PLAIN :are available SASL mechanisms\r\n",
                    .{ self.hostname, conn.nickname() },
                );
            },
            .sasl_oauthbearer,
            .sasl_plain,
            => {},
        }
        // This is our username + password
        const str = iter.next() orelse return self.errNeedMoreParams(conn, "AUTHENTICATE");

        var buf: [1024]u8 = undefined;
        const Decoder = std.base64.standard.Decoder;
        const len = Decoder.calcSizeForSlice(str) catch |err| {
            switch (err) {
                error.InvalidPadding => return self.errSaslFail(conn, "invalid padding"),
                else => unreachable,
            }
        };
        const decode_buf = buf[0..len];
        std.base64.standard.Decoder.decode(decode_buf, str) catch |err| {
            switch (err) {
                error.InvalidPadding => return self.errSaslFail(conn, "invalid padding"),
                error.InvalidCharacter => return self.errSaslFail(conn, "invalid character"),
                error.NoSpaceLeft => return self.errSaslFail(conn, "auth too long"),
            }
        };

        var sasl_iter = std.mem.splitScalar(u8, decode_buf, 0x00);

        // Authorized as is the identity we will act as. We generally ignore this
        const authorized_as = sasl_iter.next() orelse
            return self.errSaslFail(conn, "invalid SASL message");
        _ = authorized_as;

        // Authenticate as is the identity that belongs to the password
        const authenticate_as = sasl_iter.next() orelse
            return self.errSaslFail(conn, "invalid SASL message");

        // The password
        const password = sasl_iter.next() orelse
            return self.errSaslFail(conn, "invalid SASL message");

        const payload = try std.fmt.allocPrint(
            self.gpa,
            "{{ \"identifier\": \"{s}\", \"password\": \"{s}\" }}",
            .{ authenticate_as, password },
        );

        self.thread_pool.spawn(Server.atprotoCreateSession, .{ self, conn, payload }) catch |err| {
            log.err("couldn't spawn thread: {}", .{err});
            return;
        };
    }

    /// Wrapper which authenticates with atproto
    fn atprotoCreateSession(self: *Server, conn: *Connection, payload: []const u8) void {
        self.doAtprotoCreateSession(conn, payload) catch |err| {
            log.err("couldn't create atproto session: {}", .{err});
        };
    }

    fn doAtprotoCreateSession(self: *Server, conn: *Connection, payload: []const u8) !void {
        defer self.gpa.free(payload);

        const endpoint = try std.fmt.allocPrint(
            self.gpa,
            "{s}/xrpc/com.atproto.server.createSession",
            .{self.pds_server},
        );
        defer self.gpa.free(endpoint);

        var storage = std.ArrayList(u8).init(self.gpa);
        defer storage.deinit();

        var http_client: std.http.Client = .{ .allocator = self.gpa };
        const result = try http_client.fetch(.{
            .response_storage = .{ .dynamic = &storage },
            .location = .{ .url = endpoint },
            .method = .POST,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
            .payload = payload,
        });

        const response = try storage.toOwnedSlice();

        {
            self.wakeup_mutex.lock();
            defer self.wakeup_mutex.unlock();
            try self.wakeup_results.append(self.gpa, .{
                .atproto_auth = .{
                    .conn = conn,
                    .result = result,
                    .response = response,
                },
            });
        }

        try self.wakeup.notify();
    }

    fn handlePing(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        try conn.write_buf.writer(conn.gpa).print(
            ":{s} PONG {s} :{s}\r\n",
            .{ self.hostname, self.hostname, msg.rawParameters() },
        );
    }

    fn errNeedMoreParams(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        try conn.print(
            ":{s} 461 {s} {s} :Not enough paramaters\r\n",
            .{ self.hostname, conn.nickname(), cmd },
        );
    }

    fn errUnknownCommand(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        log.err("unknown command: {s}", .{cmd});
        try conn.print(
            ":{s} 421 {s} {s} :Unknown command\r\n",
            .{ self.hostname, conn.nickname(), cmd },
        );
    }

    fn errUnknownError(
        self: *Server,
        conn: *Connection,
        cmd: []const u8,
        err: []const u8,
    ) Allocator.Error!void {
        try conn.print(
            ":{s} 400 {s} {s} :{s}\r\n",
            .{ self.hostname, conn.nickname(), cmd, err },
        );
    }

    fn errSaslFail(self: *Server, conn: *Connection, msg: []const u8) Allocator.Error!void {
        try conn.print(
            ":{s} 904 {s} :SASL authenticated failed: {s}\r\n",
            .{ self.hostname, conn.nickname(), msg },
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
        cap_negotiation,
        sasl_plain,
        sasl_oauthbearer,
        registered,
        authenticated,
    };

    gpa: Allocator,
    tcp: xev.TCP,

    state: State,

    read_buf: [1024]u8,
    read_queue: std.ArrayListUnmanaged(u8),

    write_c: xev.Completion,
    write_buf: std.ArrayListUnmanaged(u8),

    nick: []const u8,
    user: []const u8,
    real: []const u8,

    caps: std.AutoHashMapUnmanaged(Capability, bool),

    fn init(self: *Connection, gpa: Allocator, tcp: xev.TCP) void {
        self.* = .{
            .gpa = gpa,
            .tcp = tcp,

            .state = .pre_registration,

            .read_buf = undefined,
            .read_queue = .empty,

            .write_c = .{},
            .write_buf = .empty,

            .nick = "",
            .user = "",
            .real = "",

            .caps = .empty,
        };
    }

    fn nickname(self: *Connection) []const u8 {
        switch (self.state) {
            .pre_registration => return "*",
            .cap_negotiation => return "*",
            .sasl_oauthbearer,
            .sasl_plain,
            => return "*",
            .registered => return "*",
            .authenticated => return self.nick,
        }
    }

    fn setNick(self: *Connection, nick: []const u8) Allocator.Error!void {
        if (self.nick.len > 0) self.gpa.free(self.nick);
        self.nick = try self.gpa.dupe(u8, nick);
    }

    fn setUsernameAndRealname(
        self: *Connection,
        username: []const u8,
        realname: []const u8,
    ) Allocator.Error!void {
        assert(self.user.len == 0);
        assert(self.real.len == 0);
        self.user = try self.gpa.dupe(u8, username);
        self.real = try self.gpa.dupe(u8, realname);
    }

    fn deinit(self: *Connection) void {
        self.read_queue.deinit(self.gpa);
        self.write_buf.deinit(self.gpa);
        self.gpa.free(self.nick);
        self.gpa.free(self.user);
        self.gpa.free(self.real);
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
        log.debug("write: {s}", .{std.mem.trimRight(u8, wb.slice[0..n], "\r\n")});

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

fn nickIsValid(nick: []const u8) bool {
    if (std.mem.startsWith(u8, nick, "#")) return false;
    if (std.mem.startsWith(u8, nick, ":")) return false;
    if (std.mem.indexOfScalar(u8, nick, ' ')) |_| return false;
    return true;
}

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
