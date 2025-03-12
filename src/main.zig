const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev");
const zeit = @import("zeit");

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const gpa, const is_debug = gpa: {
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        _ = debug_allocator.deinit();
    };

    var server: Server = undefined;
    try server.init(gpa, "localhost", 6667);
    defer server.deinit();

    try server.loop.run(.until_done);
}

const Capability = enum {
    sasl,
    @"message-tags",
    @"server-time",
};

const Sasl = union(enum) {
    plain: struct {
        username: []const u8,
        password: []const u8,
    },
    oauthbearer: []const u8,
};

const WakeupResult = union(enum) {
    auth_success: struct {
        conn: *Connection,
        avatar_url: []const u8,
        nick: []const u8,
        user: []const u8,
        realname: []const u8,
    },
    auth_failure: struct {
        conn: *Connection,
        msg: []const u8,
    },
};

const Server = struct {
    const log = std.log.scoped(.server);
    // We allow tags, so our maximum is 4096 + 512
    const max_message_len = 4096 + 512;

    const garbage_collect_ms = 5 * std.time.ms_per_min;

    gpa: std.mem.Allocator,
    loop: xev.Loop,
    address: std.net.Address,
    tcp: xev.TCP,
    // maps a tcp connection to a connection object
    connections: std.AutoArrayHashMapUnmanaged(xev.TCP, *Connection),
    /// maps a nick to a user
    nick_map: std.StringArrayHashMapUnmanaged(*User),
    hostname: []const u8,

    garbage_collect_timer: xev.Timer,

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
        const addr = try std.net.Address.parseIp4("127.0.0.1", port);

        self.* = .{
            .gpa = gpa,
            .loop = try xev.Loop.init(.{ .entries = 1024 }),
            .tcp = try .init(addr),
            .address = addr,
            .connections = .empty,
            .nick_map = .empty,
            .hostname = hostname,
            .garbage_collect_timer = try .init(),
            .thread_pool = undefined,
            .wakeup = try .init(),
            .wakeup_results = .empty,
            .wakeup_mutex = .{},
            .completion_pool = .init(gpa),
        };
        try self.thread_pool.init(.{ .allocator = gpa });

        try self.tcp.bind(addr);
        try self.tcp.listen(256);

        // get the bound port
        var sock_len = self.address.getOsSockLen();
        try std.posix.getsockname(self.tcp.fd, &self.address.any, &sock_len);

        const tcp_c = try self.completion_pool.create();
        self.tcp.accept(&self.loop, tcp_c, Server, self, Server.onAccept);
        std.log.info("Listening at {}", .{self.address});

        // Start listening for our wakeup
        const wakeup_c = try self.completion_pool.create();
        self.wakeup.wait(&self.loop, wakeup_c, Server, self, Server.onWakeup);

        // Start the rehash timer. This is a timer to rehash our hashmaps
        const rehash_c = try self.completion_pool.create();
        self.garbage_collect_timer.run(&self.loop, rehash_c, garbage_collect_ms, Server, self, Server.onGarbageCollect);
    }

    fn onGarbageCollect(
        ud: ?*Server,
        _: *xev.Loop,
        c: *xev.Completion,
        r: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const self = ud.?;
        _ = r catch |err| {
            log.err("timer error: {}", .{err});
        };
        log.debug("collecting garbage", .{});
        const start = std.time.milliTimestamp();
        defer log.debug("garbage collection took {d}ms", .{std.time.milliTimestamp() - start});

        self.garbage_collect_timer.run(&self.loop, c, garbage_collect_ms, Server, self, Server.onGarbageCollect);

        // Close unauthenticated connections
        {
            var iter = self.connections.iterator();
            const now = std.time.timestamp();
            while (iter.next()) |entry| {
                const conn = entry.value_ptr.*;
                if (conn.state == .authenticated) continue;
                // If it's been more than 60 seconds since this connection connected and it isn't
                // authenticated, we close it
                if (conn.connected_at + 60 < now) {
                    self.handleClientDisconnect(conn.client);
                }
            }
        }
        // Clean up connections hash map
        connections: {
            const keys = self.gpa.dupe(xev.TCP, self.connections.keys()) catch break :connections;
            defer self.gpa.free(keys);
            const values = self.gpa.dupe(*Connection, self.connections.values()) catch break :connections;
            defer self.gpa.free(values);
            self.connections.reinit(self.gpa, keys, values) catch break :connections;
        }
        // Clean up connections nick hash map
        nick_map: {
            const keys = self.gpa.dupe([]const u8, self.nick_map.keys()) catch break :nick_map;
            defer self.gpa.free(keys);
            const values = self.gpa.dupe(*User, self.nick_map.values()) catch break :nick_map;
            defer self.gpa.free(values);
            self.nick_map.reinit(self.gpa, keys, values) catch break :nick_map;
        }

        return .disarm;
    }

    fn deinit(self: *Server) void {
        log.info("shutting down", .{});
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            const tcp = entry.key_ptr.*;
            std.posix.close(tcp.fd);
            const conn = entry.value_ptr.*;
            conn.deinit(self.gpa);
            self.gpa.destroy(conn);
        }
        while (self.wakeup_results.pop()) |result| {
            switch (result) {
                .auth_success => |v| {
                    self.gpa.free(v.avatar_url);
                    self.gpa.free(v.nick);
                    self.gpa.free(v.realname);
                    self.gpa.free(v.user);
                },
                .auth_failure => |v| {
                    self.gpa.free(v.msg);
                },
            }
        }
        for (self.nick_map.values()) |v| {
            v.deinit(self.gpa);
            self.gpa.destroy(v);
        }
        self.nick_map.deinit(self.gpa);
        self.wakeup_results.deinit(self.gpa);
        self.connections.deinit(self.gpa);
        self.completion_pool.deinit();
        self.loop.deinit();
        self.thread_pool.deinit();
    }

    // Runs while value is true
    fn runUntil(self: *Server, value: *const std.atomic.Value(bool), wg: *std.Thread.WaitGroup) !void {
        wg.finish();
        while (value.load(.unordered)) {
            try self.loop.run(.once);
        }
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
                .auth_success => |v| {
                    log.debug("github auth={s}", .{v.nick});
                    self.onSuccessfulAuth(
                        v.conn,
                        v.nick,
                        v.user,
                        v.realname,
                        v.avatar_url,
                    ) catch |err| {
                        log.err("could finish auth: {}", .{err});
                        v.conn.state = .registered;
                        self.errSaslFail(v.conn, "failed to finish authentication") catch {};
                    };
                },
                .auth_failure => |v| {
                    log.debug("auth response={s}", .{v.msg});
                    self.errSaslFail(v.conn, v.msg) catch {};
                },
            }
        }
        return .rearm;
    }

    fn onSuccessfulAuth(
        self: *Server,
        conn: *Connection,
        nick: []const u8,
        username: []const u8,
        realname: []const u8,
        avatar_url: []const u8,
    ) Allocator.Error!void {
        conn.state = .authenticated;

        // If we don't have a user in the map, we will create one and insert it
        if (!self.nick_map.contains(nick)) {
            const user = try self.gpa.create(User);
            user.* = .init();
            user.real = realname;
            user.username = username;
            user.avatar_url = avatar_url;
            user.nick = nick;
            try self.nick_map.put(self.gpa, nick, user);
        }
        const user = self.nick_map.get(nick) orelse unreachable;
        try user.connections.append(self.gpa, conn);
        conn.user = user;

        try conn.print(
            self.gpa,
            ":{s} 900 {s} {s}!{s}@github.com {s} :You are now logged in\r\n",
            .{
                self.hostname,
                nick,
                nick,
                nick,
                nick,
            },
        );
        try conn.print(self.gpa, ":{s} 903 {s} :SASL successful\r\n", .{ self.hostname, nick });
        // RPL_WELCOME
        try conn.print(self.gpa, ":{s} 001 {s} :Good Apollo, I'm burning Star IV!\r\n", .{ self.hostname, nick });
        // RPL_YOURHOST
        try conn.print(self.gpa, ":{s} 002 {s} :Your host is {s}\r\n", .{ self.hostname, nick, self.hostname });
        // ISUPPORT
        try conn.print(self.gpa, ":{s} 005 {s} WHOX :are supported\r\n", .{ self.hostname, nick });

        try self.queueWrite(conn.client, conn);
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
        conn.init(client);

        try self.connections.put(self.gpa, client, conn);

        const completion = try self.completion_pool.create();

        client.read(
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
        // Signal EOF to the fd. We will close the fd in the read callback. This is the only place
        // we ever close the file descriptor
        std.posix.shutdown(client.fd, .both) catch {};

        const conn = self.connections.get(client) orelse {
            log.warn("connection not found: fd={d}", .{client.fd});
            return;
        };

        if (conn.user) |user| {
            // Remove this connection from the nick_map
            if (self.nick_map.get(user.nick)) |v| {
                for (v.connections.items, 0..) |c, i| {
                    if (c == conn) {
                        _ = v.connections.swapRemove(i);
                        break;
                    }
                }

                // No more connections
                if (v.connections.items.len == 0) {
                    _ = self.nick_map.swapRemove(v.nick);
                    v.deinit(self.gpa);
                    self.gpa.destroy(v);
                    // TODO: send AWAY, PART?
                }
            }
        }
        conn.deinit(self.gpa);
        _ = self.connections.swapRemove(client);
        self.gpa.destroy(conn);
    }

    /// queues a write of the pending buffer. If there is nothing to queue, this is a noop
    fn queueWrite(self: *Server, tcp: xev.TCP, conn: *Connection) Allocator.Error!void {
        if (conn.write_buf.items.len == 0) return;
        const buf = try conn.write_buf.toOwnedSlice(self.gpa);
        const write_c = try self.completion_pool.create();
        tcp.write(
            &self.loop,
            write_c,
            .{ .slice = buf },
            Server,
            self,
            Server.onWrite,
        );
    }

    fn onWrite(
        ud: ?*Server,
        _: *xev.Loop,
        c: *xev.Completion,
        tcp: xev.TCP,
        wb: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self = ud.?;
        self.completion_pool.destroy(c);
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

        const conn = self.connections.get(tcp) orelse {
            log.err("connection not found: {d}", .{tcp.fd});
            return .disarm;
        };

        // Incomplete write. Insert the unwritten portion at the front of the list and we'll requeue
        if (n < wb.slice.len) {
            conn.write_buf.insertSlice(self.gpa, 0, wb.slice[n..]) catch |err| {
                log.err("couldn't insert unwritten bytes: {}", .{err});
                return .disarm;
            };
        }
        self.queueWrite(tcp, conn) catch {};
        return .disarm;
    }

    fn onRead(
        ud: ?*Server,
        _: *xev.Loop,
        c: *xev.Completion,
        client: xev.TCP,
        rb: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = ud.?;

        // Get the read result
        const n = result catch |err| {
            switch (err) {
                error.Canceled,
                error.Unexpected,
                error.ConnectionReset,
                error.EOF,
                => {},
            }
            // client disconnected
            self.handleClientDisconnect(client);
            self.completion_pool.destroy(c);
            std.posix.close(client.fd);
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

        self.queueWrite(client, conn) catch |err| {
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

                .PRIVMSG => try self.handlePrivMsg(conn, msg),
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
            return self.errInputTooLong(conn);
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
                self.gpa,
                ":{s} CAP {s} LS :",
                .{ self.hostname, conn.nickname() },
            );
            for (std.meta.fieldNames(Capability), 0..) |cap, i| {
                if (i > 0) try conn.write(self.gpa, " ");
                try conn.write(self.gpa, cap);
                if (std.mem.eql(u8, "sasl", cap)) try conn.write(self.gpa, "=PLAIN");
            }
            try conn.write(self.gpa, "\r\n");
        } else if (std.mem.eql(u8, subcmd, "LIST")) {
            // LIST lists enabled capabilities
        } else if (std.mem.eql(u8, subcmd, "REQ")) {
            // REQ tries to enable the given capability
            while (iter.next()) |cap_str| {
                const cap = std.meta.stringToEnum(Capability, cap_str) orelse {
                    try conn.print(
                        self.gpa,
                        ":{s} CAP {s} NAK {s}\r\n",
                        .{ self.hostname, conn.nickname(), cap_str },
                    );
                    continue;
                };
                try conn.enableCap(self.gpa, cap);
                try conn.print(
                    self.gpa,
                    ":{s} CAP {s} ACK {s}\r\n",
                    .{ self.hostname, conn.nickname(), cap_str },
                );
            }
        } else if (std.mem.eql(u8, subcmd, "END")) {
            // END signals the end of capability negotiation
            conn.state = .registered;
        }
    }

    fn handleNick(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        // Silently ignore nick commands. We get this from the Github auth
        _ = self;
        _ = conn;
        _ = msg;
    }

    fn handleUser(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        // Silently ignore user commands. We get this from the Github auth
        _ = self;
        _ = conn;
        _ = msg;
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
                    return conn.write(self.gpa, "AUTHENTICATE +\r\n");
                }
                if (std.ascii.eqlIgnoreCase("OAUTHBEARER", mechanism)) {
                    conn.state = .sasl_oauthbearer;
                    return conn.write(self.gpa, "AUTHENTICATE +\r\n");
                }

                return conn.print(
                    self.gpa,
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

        // If we are testing, we fake the auth.
        if (builtin.is_test) {
            if (std.ascii.eqlIgnoreCase(str, "pass")) {
                try self.wakeup_results.append(self.gpa, .{
                    .auth_success = .{
                        .conn = conn,
                        .nick = try self.gpa.dupe(u8, "test"),
                        .user = try self.gpa.dupe(u8, "test"),
                        .realname = try self.gpa.dupe(u8, "Testy McTestFace"),
                        .avatar_url = try self.gpa.dupe(u8, "http://localhost:8080/avatar.png"),
                    },
                });
            } else {
                try self.wakeup_results.append(self.gpa, .{
                    .auth_failure = .{
                        .conn = conn,
                        .msg = try self.gpa.dupe(u8, "invalid password"),
                    },
                });
            }
            self.wakeup.notify() catch @panic("test failure for OOM");
            return;
        }
        var buf: [1024]u8 = undefined;
        const Decoder = std.base64.standard.Decoder;
        const len = Decoder.calcSizeForSlice(str) catch |err| {
            switch (err) {
                error.InvalidPadding => return self.errSaslFail(conn, "invalid base64 encoding"),
                else => unreachable,
            }
        };
        const decode_buf = buf[0..len];
        std.base64.standard.Decoder.decode(decode_buf, str) catch |err| {
            switch (err) {
                error.InvalidPadding => return self.errSaslFail(conn, "invalid base64 encoding"),
                error.InvalidCharacter => return self.errSaslFail(conn, "invalid base64 encoding"),
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
        _ = authenticate_as;

        // The password
        const password = sasl_iter.next() orelse
            return self.errSaslFail(conn, "invalid SASL message");

        const auth_header = try std.fmt.allocPrint(
            self.gpa,
            "Bearer {s}",
            .{password},
        );

        self.thread_pool.spawn(Server.githubCheckAuth, .{ self, conn, auth_header }) catch |err| {
            log.err("couldn't spawn thread: {}", .{err});
            return;
        };
    }

    /// Wrapper which authenticates with github
    fn githubCheckAuth(self: *Server, conn: *Connection, auth_header: []const u8) void {
        self.doGithubCheckAuth(conn, auth_header) catch |err| {
            log.err("couldn't authenticate token: {}", .{err});
        };
    }

    fn doGithubCheckAuth(self: *Server, conn: *Connection, auth_header: []const u8) !void {
        defer self.gpa.free(auth_header);

        const endpoint = "https://api.github.com/user";

        var storage = std.ArrayList(u8).init(self.gpa);
        defer storage.deinit();

        var http_client: std.http.Client = .{ .allocator = self.gpa };
        const result = try http_client.fetch(.{
            .response_storage = .{ .dynamic = &storage },
            .location = .{ .url = endpoint },
            .method = .GET,
            .headers = .{
                .content_type = .{ .override = "application/json" },
                .authorization = .{ .override = auth_header },
            },
        });

        switch (result.status) {
            .ok => {
                const parsed = try std.json.parseFromSlice(std.json.Value, self.gpa, storage.items, .{});
                defer parsed.deinit();
                assert(parsed.value == .object);
                const resp = parsed.value.object;
                const login = resp.get("login").?.string;
                const avatar_url = resp.get("avatar_url").?.string;
                const realname = resp.get("name").?.string;
                self.wakeup_mutex.lock();
                defer self.wakeup_mutex.unlock();
                try self.wakeup_results.append(self.gpa, .{
                    .auth_success = .{
                        .conn = conn,
                        .nick = try self.gpa.dupe(u8, login),
                        .user = try self.gpa.dupe(u8, login),
                        .realname = try self.gpa.dupe(u8, realname),
                        .avatar_url = try self.gpa.dupe(u8, avatar_url),
                    },
                });
            },
            .unauthorized, .forbidden => {
                self.wakeup_mutex.lock();
                defer self.wakeup_mutex.unlock();
                try self.wakeup_results.append(self.gpa, .{
                    .auth_failure = .{
                        .conn = conn,
                        .msg = try storage.toOwnedSlice(),
                    },
                });
            },
            else => log.warn("unexpected github response: {s}", .{storage.items}),
        }

        try self.wakeup.notify();
    }

    fn handlePing(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} PONG {s} :{s}\r\n",
            .{ self.hostname, self.hostname, msg.rawParameters() },
        );
    }

    fn handlePrivMsg(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        // TODO: store the message in database
        var iter = msg.paramIterator();
        const target = iter.next() orelse return self.errNoRecipient(conn);
        const text = iter.next() orelse return self.errNoTextToSend(conn);

        if (target.len == 0) return self.errNoRecipient(conn);
        switch (target[0]) {
            '#' => {},
            else => {
                // Get the connections for this nick
                const user = self.nick_map.get(target) orelse {
                    return self.errNoSuchNick(conn, target);
                };

                for (user.connections.items) |c| {
                    if (c.caps.contains(.@"server-time")) {
                        // TODO: tags
                        const inst = zeit.instant(.{
                            .source = .{ .unix_nano = @as(i128, msg.timestamp_ms) * std.time.ns_per_ms },
                        }) catch unreachable;
                        const time = inst.time();
                        const writer = c.write_buf.writer(self.gpa);
                        try writer.writeAll("@time=");
                        time.gofmt(writer, "2006-01-02T15:04:05.000") catch |err| {
                            switch (err) {
                                error.OutOfMemory => return error.OutOfMemory,
                                else => unreachable,
                            }
                        };
                        try writer.writeByte('Z');
                        try writer.writeByte(' ');
                    }

                    try c.print(self.gpa, ":{s} PRIVMSG {s} :{s}\r\n", .{ user.nick, target, text });
                    try self.queueWrite(c.client, c);
                }
            },
        }
    }

    fn errNoSuchNick(self: *Server, conn: *Connection, nick_or_chan: []const u8) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 401 {s} {s} :No such nick/channel\r\n",
            .{ self.hostname, conn.nickname(), nick_or_chan },
        );
    }

    fn errNoRecipient(self: *Server, conn: *Connection) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 411 {s} :No recipient given\r\n",
            .{ self.hostname, conn.nickname() },
        );
    }

    fn errNoTextToSend(self: *Server, conn: *Connection) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 412 {s} :No text to send\r\n",
            .{ self.hostname, conn.nickname() },
        );
    }

    fn errInputTooLong(self: *Server, conn: *Connection) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 417 {s} :Input too long\r\n",
            .{ self.hostname, conn.nickname() },
        );
    }

    fn errNeedMoreParams(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 461 {s} {s} :Not enough paramaters\r\n",
            .{ self.hostname, conn.nickname(), cmd },
        );
    }

    fn errUnknownCommand(self: *Server, conn: *Connection, cmd: []const u8) Allocator.Error!void {
        log.err("unknown command: {s}", .{cmd});
        try conn.print(
            self.gpa,
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
            self.gpa,
            ":{s} 400 {s} {s} :{s}\r\n",
            .{ self.hostname, conn.nickname(), cmd, err },
        );
    }

    fn errSaslFail(self: *Server, conn: *Connection, msg: []const u8) Allocator.Error!void {
        try conn.print(
            self.gpa,
            ":{s} 904 {s} :SASL authenticated failed: {s}\r\n",
            .{ self.hostname, conn.nickname(), msg },
        );
    }
};

/// an irc message
const Message = struct {
    bytes: []const u8,
    timestamp_ms: i64 = 0,

    pub fn init(bytes: []const u8) Message {
        return .{
            .bytes = bytes,
            .timestamp_ms = std.time.milliTimestamp(),
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
        return lhs.timestamp_ms < rhs.timestamp_ms;
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

const User = struct {
    nick: []const u8,
    username: []const u8,
    real: []const u8,
    avatar_url: []const u8,

    connections: std.ArrayListUnmanaged(*Connection),

    fn init() User {
        return .{
            .nick = "",
            .username = "",
            .real = "",
            .avatar_url = "",
            .connections = .empty,
        };
    }

    fn deinit(self: *User, gpa: Allocator) void {
        gpa.free(self.nick);
        gpa.free(self.username);
        gpa.free(self.real);
        gpa.free(self.avatar_url);
        self.connections.deinit(gpa);
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

    client: xev.TCP,
    state: State,

    read_buf: [512]u8,
    read_queue: std.ArrayListUnmanaged(u8),

    write_buf: std.ArrayListUnmanaged(u8),

    user: ?*User,

    caps: std.AutoHashMapUnmanaged(Capability, bool),
    // Time the connection started
    connected_at: u32,

    fn init(self: *Connection, client: xev.TCP) void {
        self.* = .{
            .client = client,
            .state = .pre_registration,

            .read_buf = undefined,
            .read_queue = .empty,

            .write_buf = .empty,

            .user = null,

            .caps = .empty,
            .connected_at = @intCast(std.time.timestamp()),
        };
    }

    fn nickname(self: *Connection) []const u8 {
        if (self.user) |user| return user.nick;
        return "*";
    }

    fn deinit(self: *Connection, gpa: Allocator) void {
        self.read_queue.deinit(gpa);
        self.write_buf.deinit(gpa);
        self.caps.deinit(gpa);
    }

    fn write(self: *Connection, gpa: Allocator, bytes: []const u8) Allocator.Error!void {
        try self.write_buf.appendSlice(gpa, bytes);
    }

    fn print(self: *Connection, gpa: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        return self.write_buf.writer(gpa).print(fmt, args);
    }

    fn enableCap(self: *Connection, gpa: Allocator, cap: Capability) Allocator.Error!void {
        try self.caps.put(gpa, cap, true);
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

/// Reads one line from the stream. If the command does not match, we fail the test
fn expectResponse(stream: std.net.Stream, response: []const u8) !void {
    var buf: [512]u8 = undefined;
    const actual = try stream.reader().readUntilDelimiter(&buf, '\n');
    try std.testing.expectEqualStrings(response, std.mem.trimRight(u8, actual, "\r\n"));
}

const TestServer = struct {
    server: Server,
    cond: std.atomic.Value(bool),
    thread: std.Thread,

    fn init(self: *TestServer, gpa: Allocator) !void {
        self.* = .{
            .server = undefined,
            .cond = .init(true),
            .thread = undefined,
        };
        try self.server.init(gpa, "localhost", 0);
        var wg: std.Thread.WaitGroup = .{};
        wg.start();
        self.thread = try std.Thread.spawn(.{}, Server.runUntil, .{ &self.server, &self.cond, &wg });
        wg.wait();
    }

    fn deinit(self: *TestServer) void {
        // Close the connection
        self.cond.store(false, .unordered);

        if (self.server.wakeup.notify()) {
            self.thread.join();
        } else |err| {
            std.log.err("Failed to notify wakeup: {}", .{err});
            self.thread.detach();
        }
        self.server.deinit();
        self.* = undefined;
    }

    fn port(self: *TestServer) u16 {
        return self.server.address.getPort();
    }
};

test "Server: basic connection" {
    var server: TestServer = undefined;
    try server.init(std.testing.allocator);
    defer server.deinit();

    const stream = try std.net.tcpConnectToHost(std.testing.allocator, "localhost", server.port());
    defer stream.close();

    try stream.writeAll("CAP LS 302\r\n");
    try expectResponse(stream, ":localhost CAP * LS :sasl=PLAIN");
    try stream.writeAll("CAP REQ :sasl\r\n");
    try expectResponse(stream, ":localhost CAP * ACK sasl");
    try stream.writeAll("AUTHENTICATE PLAIN\r\n");
    try expectResponse(stream, "AUTHENTICATE +");
    try stream.writeAll("AUTHENTICATE pass\r\n");
    try expectResponse(stream, ":localhost 900 test test!test@github.com test :You are now logged in");

    // By now we should have one connection
    try std.testing.expectEqual(1, server.server.connections.count());
}
