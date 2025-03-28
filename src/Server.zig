const Server = @This();

const builtin = @import("builtin");
const httpz = @import("httpz");
const std = @import("std");
const sqlite = @import("sqlite");
const uuid = @import("uuid");
const xev = @import("xev");
const zeit = @import("zeit");

const atproto = @import("atproto.zig");
const db = @import("db.zig");
const github = @import("github.zig");
const http = @import("http.zig");
const irc = @import("irc.zig");
const log = @import("log.zig");

const Allocator = std.mem.Allocator;
const Capability = irc.Capability;
const Channel = irc.Channel;
const ChannelPrivileges = irc.ChannelPrivileges;
const ChatHistory = irc.ChatHistory;
const ClientMessage = irc.ClientMessage;
const HeapArena = @import("HeapArena.zig");
const Http = @import("http.zig");
const Message = irc.Message;
const MessageIterator = irc.MessageIterator;
const Queue = @import("queue.zig").Queue;
const Sanitize = @import("sanitize.zig");
const SaslMechanism = irc.SaslMechanism;
const ThreadPool = @import("ThreadPool.zig");
const Timestamp = irc.Timestamp;
const User = irc.User;

const assert = std.debug.assert;

// We allow tags, so our maximum is 4096 + 512
const max_message_len = 4096 + 512;

const garbage_collect_ms = 1 * std.time.ms_per_min;

const max_chathistory: u16 = 100;

const ProcessMessageError = error{ClientQuit} || Allocator.Error;

pub const WakeupResult = union(enum) {
    auth_success: AuthSuccess,
    auth_failure: struct {
        arena: HeapArena,
        fd: xev.TCP,
        msg: []const u8,
    },
    history_batch: ChatHistory.HistoryBatch,
    history_targets: ChatHistory.TargetBatch,
    mark_read: struct {
        arena: HeapArena,
        fd: xev.TCP,
        target: []const u8,
        timestamp: ?Timestamp,
    },
    // a new event stream has connected. This happens in another thread, so we coalesce in the main
    // via wakeup
    event_stream: *http.EventStream,

    pub const AuthSuccess = struct {
        arena: HeapArena,
        fd: xev.TCP,
        avatar_url: []const u8,
        nick: []const u8,
        user: []const u8,
        realname: []const u8,
    };
};

pub const WorkerQueue = Queue(WakeupResult, 128);

pub const Options = struct {
    hostname: []const u8 = "localhost",
    irc_port: u16 = 6667,
    /// If http_port is null, the http server will not be started
    http_port: ?u16 = 8080,
    auth: AuthProvider = .none,
    db_path: [:0]const u8 = "apollo.db",
};

const Capabilities = packed struct {
    @"away-notify": bool = false,
    @"draft/chathistory": bool = false,
    @"draft/read-marker": bool = false,
    @"draft/no-implicit-names": bool = false,
    @"echo-message": bool = false,
    @"message-tags": bool = false,
    @"server-time": bool = false,
    @"standard-replies": bool = false,
};

const AuthProvider = enum {
    none,
    github,
    atproto,
};

const PendingAuth = struct {
    conn: *Connection,
    mechanism: SaslMechanism,
};

gpa: std.mem.Allocator,
loop: xev.Loop,
address: std.net.Address,
tcp: xev.TCP,
hostname: []const u8,
auth: AuthProvider,

http_client: std.http.Client,

http_server: Http.Server,
httpz_server: httpz.Server(*Http.Server),
http_server_thread: ?std.Thread,

/// maps a tcp connection to an EventStream object
event_streams: std.AutoArrayHashMapUnmanaged(xev.TCP, *http.EventStream),
/// maps a tcp connection to a connection object
connections: std.AutoArrayHashMapUnmanaged(xev.TCP, *Connection),
/// maps a nick to a user
nick_map: std.StringArrayHashMapUnmanaged(*User),
/// maps channel name to channel
channels: std.StringArrayHashMapUnmanaged(*Channel),

pending_auth: std.ArrayListUnmanaged(PendingAuth),

garbage_collect_timer: xev.Timer,
gc_cycle: u8,

thread_pool: ThreadPool,
db_pool: *sqlite.Pool,
wakeup: xev.Async,
wakeup_queue: WorkerQueue,

completion_pool: MemoryPoolUnmanaged,
next_batch: u32,

pub fn init(
    self: *Server,
    gpa: std.mem.Allocator,
    opts: Options,
) !void {
    const addr = try std.net.Address.parseIp4("127.0.0.1", opts.irc_port);

    const core_count = if (builtin.is_test) 1 else @max(4, std.Thread.getCpuCount() catch 0);
    const db_config: sqlite.Pool.Config = .{
        .size = core_count,
        .path = opts.db_path,
        .flags = sqlite.OpenFlags.Create |
            sqlite.OpenFlags.EXResCode |
            sqlite.OpenFlags.ReadWrite,
        .on_first_connection = db.createTables,
        .on_connection = db.setPragmas,
    };

    const n_jobs: u16 = @intCast(core_count);

    const db_pool: *sqlite.Pool = try .init(gpa, db_config);

    self.* = .{
        .gpa = gpa,
        .loop = try xev.Loop.init(.{ .entries = 1024 }),
        .tcp = try .init(addr),
        .address = addr,
        .event_streams = .empty,
        .connections = .empty,
        .nick_map = .empty,
        .channels = .empty,
        .hostname = opts.hostname,
        .auth = opts.auth,
        .http_client = .{ .allocator = gpa },
        .http_server = undefined,
        .httpz_server = undefined,
        .http_server_thread = null,
        .garbage_collect_timer = try .init(),
        .gc_cycle = 0,
        .thread_pool = undefined,
        .db_pool = db_pool,
        .wakeup = try .init(),
        .wakeup_queue = .{},
        .completion_pool = .empty,
        .next_batch = 0,
        .pending_auth = .empty,
    };

    if (opts.http_port) |http_port| {
        // If we have an http port, we start the server and spawn it's thread
        self.http_server = .{
            .gpa = gpa,
            .channels = &self.channels,
            .db_pool = db_pool,
            .irc_server = self,
        };

        self.httpz_server = try httpz.Server(*Http.Server).init(
            gpa,
            .{
                .port = http_port,
                .request = .{ .max_form_count = 1 },
                .thread_pool = .{ .count = n_jobs },
            },
            &self.http_server,
        );
        self.http_server_thread = try .spawn(
            .{},
            webMain,
            .{ self, http_port },
        );
    }
    try self.thread_pool.init(.{ .allocator = gpa, .n_jobs = n_jobs });
    self.wakeup_queue.eventfd = self.wakeup.fd;

    const tcp_c = try self.completion_pool.create(self.gpa);
    self.tcp.accept(&self.loop, tcp_c, Server, self, Server.onAccept);
    log.info("Listening at {}", .{self.address});

    // Start listening for our wakeup
    const wakeup_c = try self.completion_pool.create(self.gpa);
    self.wakeup.wait(&self.loop, wakeup_c, Server, self, Server.onWakeup);

    // Start the rehash timer. This is a timer to rehash our hashmaps
    const rehash_c = try self.completion_pool.create(self.gpa);
    self.garbage_collect_timer.run(&self.loop, rehash_c, garbage_collect_ms, Server, self, Server.onGarbageCollect);

    try self.tcp.bind(addr);
    try self.tcp.listen(256);

    // get the bound port
    var sock_len = self.address.getOsSockLen();
    try std.posix.getsockname(self.tcp.fd, &self.address.any, &sock_len);

    // Load initial db data
    try db.loadChannels(self);
    try db.loadUsers(self);
    try db.loadChannelMembership(self);

    log.info("{d} users in {d} channels", .{ self.nick_map.count(), self.channels.count() });
}

fn onGarbageCollect(
    ud: ?*Server,
    _: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    const self = ud.?;
    defer self.gc_cycle +|= 1;
    _ = r catch |err| {
        log.err("timer error: {}", .{err});
    };

    self.garbage_collect_timer.run(
        &self.loop,
        c,
        garbage_collect_ms,
        Server,
        self,
        Server.onGarbageCollect,
    );

    // Close unauthenticated connections. Every cycle we do this
    {
        var iter = self.connections.iterator();
        const now = std.time.timestamp();
        while (iter.next()) |entry| {
            const conn = entry.value_ptr.*;
            if (conn.isAuthenticated()) continue;
            // If it's been more than 60 seconds since this connection connected and it isn't
            // authenticated, we close it
            if (conn.connected_at + 60 < now) {
                log.debug("closing unauthenticated connection: {d}", .{conn.client.fd});
                // Cancel the read completion. One cancelled, we close and clean up the
                // connection
                const close_c = self.completion_pool.create(self.gpa) catch {
                    @panic("Out of memory");
                };
                self.loop.cancel(conn.read_c, close_c, Server, self, Server.onCancel);
            }
        }
    }

    // Increment this in each GC block so we stagger the cycles
    var stagger: u8 = 0;

    if ((self.gc_cycle + stagger) % 10 == 0) {
        stagger += 1;
        // Clean up connections hash map. Every 10th cycle
        connections: {
            const keys = self.gpa.dupe(xev.TCP, self.connections.keys()) catch break :connections;
            defer self.gpa.free(keys);
            const values = self.gpa.dupe(*Connection, self.connections.values()) catch break :connections;
            defer self.gpa.free(values);
            self.connections.shrinkAndFree(self.gpa, keys.len);
            self.connections.reinit(self.gpa, keys, values) catch break :connections;
        }
    }

    if ((self.gc_cycle + stagger) % 10 == 0) {
        stagger += 1;
        // Clean up pending auth list. We shrink it to the size of items it has (effecitvely
        // clearing it's capacity)
        const len = self.pending_auth.items.len;
        self.pending_auth.shrinkAndFree(self.gpa, len);
    }

    // TODO: GC completion memory pool
    // TODO: GC Event stream hash map
    // TODO: rehash all hashmaps

    return .disarm;
}

pub fn deinit(self: *Server) void {
    log.info("shutting down", .{});
    {
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            const tcp = entry.key_ptr.*;
            std.posix.close(tcp.fd);
            const conn = entry.value_ptr.*;
            conn.deinit(self.gpa);
            self.gpa.destroy(conn);
        }
    }
    {
        var iter = self.event_streams.iterator();
        while (iter.next()) |entry| {
            const tcp = entry.key_ptr.*;
            std.posix.close(tcp.fd);
            const es = entry.value_ptr.*;
            es.write_buf.deinit(self.gpa);
            self.gpa.destroy(es);
        }
    }
    self.wakeup_queue.lock();
    defer self.wakeup_queue.unlock();
    while (self.wakeup_queue.drain()) |result| {
        switch (result) {
            .event_stream => |v| self.gpa.destroy(v),
            inline else => |v| v.arena.deinit(),
        }
    }
    for (self.nick_map.values()) |v| {
        v.deinit(self.gpa);
        self.gpa.destroy(v);
    }
    self.nick_map.deinit(self.gpa);
    self.connections.deinit(self.gpa);
    self.event_streams.deinit(self.gpa);
    self.completion_pool.deinit(self.gpa);
    self.loop.deinit();
    self.http_client.deinit();
    if (self.http_server_thread) |thread| {
        // We have an http server. Clean it up
        self.httpz_server.stop();
        self.httpz_server.deinit();
        thread.join();
    }
    self.thread_pool.deinit();

    // Do a couple last minute pragmas
    {
        const conn = self.db_pool.acquire();
        defer self.db_pool.release(conn);
        conn.execNoArgs("PRAGMA analysis_limit = 400") catch {};
        conn.execNoArgs("PRAGMA optimize") catch {};
    }
    self.db_pool.deinit();
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
    self.wakeup_queue.lock();
    defer self.wakeup_queue.unlock();
    while (self.wakeup_queue.drain()) |result| {
        switch (result) {
            .auth_success => |v| {
                defer v.arena.deinit();
                self.onSuccessfulAuth(
                    v.fd,
                    v.nick,
                    v.user,
                    v.realname,
                    v.avatar_url,
                ) catch |err| {
                    log.err("could finish auth: {}", .{err});
                    const conn = self.connections.get(v.fd) orelse continue;
                    self.errSaslFail(conn, "failed to finish authentication") catch {};
                };
            },
            .auth_failure => |v| {
                defer v.arena.deinit();
                log.debug("auth response={s}", .{v.msg});
                const conn = self.connections.get(v.fd) orelse continue;
                self.errSaslFail(conn, v.msg) catch {};
            },
            .history_batch => |v| {
                defer v.arena.deinit();
                const conn = self.connections.get(v.fd) orelse continue;
                const batch_id = self.next_batch;
                self.next_batch +|= 1;
                conn.print(
                    self.gpa,
                    ":{s} BATCH +{d} chathistory {s}\r\n",
                    .{ self.hostname, batch_id, v.target },
                ) catch @panic("TODO");
                for (v.items) |msg| {
                    conn.print(
                        self.gpa,
                        "@time={};batch={d};msgid={s} :{s} {s}\r\n",
                        .{
                            msg.timestamp,
                            batch_id,
                            msg.uuid,
                            msg.sender,
                            msg.message,
                        },
                    ) catch @panic("TODO");
                }
                conn.print(
                    self.gpa,
                    ":{s} BATCH -{d} chathistory {s}\r\n",
                    .{ self.hostname, batch_id, v.target },
                ) catch @panic("TODO");

                self.queueWrite(conn.client, conn) catch {};
            },
            .history_targets => |v| {
                defer v.arena.deinit();
                const conn = self.connections.get(v.fd) orelse continue;
                const batch_id = self.next_batch;
                self.next_batch +|= 1;
                conn.print(
                    self.gpa,
                    ":{s} BATCH +{d} draft/chathistory-targets\r\n",
                    .{ self.hostname, batch_id },
                ) catch @panic("TODO");
                for (v.items) |target| {
                    conn.print(
                        self.gpa,
                        "@batch={d} CHATHISTORY TARGETS {s} {s}\r\n",
                        .{
                            batch_id,
                            target.nick_or_channel,
                            target.latest_timestamp,
                        },
                    ) catch @panic("TODO");
                }
                conn.print(
                    self.gpa,
                    ":{s} BATCH -{d} draft/chathistory-targets\r\n",
                    .{ self.hostname, batch_id },
                ) catch @panic("TODO");

                self.queueWrite(conn.client, conn) catch {};
            },
            .mark_read => |v| {
                defer v.arena.deinit();
                const c = self.connections.get(v.fd) orelse continue;
                const user = c.user orelse continue;
                // We report the markread to all connections
                for (user.connections.items) |conn| {
                    if (v.timestamp) |timestamp| {
                        conn.print(
                            self.gpa,
                            ":{s} MARKREAD {s} timestamp={s}\r\n",
                            .{ self.hostname, v.target, timestamp },
                        ) catch @panic("TODO");
                    } else {
                        conn.print(
                            self.gpa,
                            ":{s} MARKREAD {s} *\r\n",
                            .{ self.hostname, v.target },
                        ) catch @panic("TODO");
                    }
                }
            },
            .event_stream => |v| {
                self.event_streams.put(self.gpa, v.stream, v) catch @panic("OOM");
                v.channel.streams.append(self.gpa, v) catch @panic("OOM");
            },
        }
    }
    return .rearm;
}

fn onSuccessfulAuth(
    self: *Server,
    fd: xev.TCP,
    nick: []const u8,
    username: []const u8,
    realname: []const u8,
    avatar_url: []const u8,
) Allocator.Error!void {
    const conn = self.connections.get(fd) orelse {
        log.warn("connection not found: fd={d}", .{fd.fd});
        return;
    };

    // If we don't have a user in the map, we will create one and insert it
    if (!self.nick_map.contains(nick)) {
        const user = try self.gpa.create(User);
        user.* = .init();
        user.real = try self.gpa.dupe(u8, realname);
        user.username = try self.gpa.dupe(u8, username);
        user.avatar_url = try self.gpa.dupe(u8, avatar_url);
        user.nick = try self.gpa.dupe(u8, nick);
        try self.nick_map.put(self.gpa, nick, user);
    }
    const user = self.nick_map.get(nick).?;

    // Store or update the user in the db. We do this in a worker thread
    try self.thread_pool.spawn(db.storeUser, .{ self.db_pool, user });
    try user.connections.append(self.gpa, conn);
    conn.user = user;

    try conn.print(
        self.gpa,
        ":{s} 900 {s} {s}!{s}@{s} {s} :You are now logged in\r\n",
        .{
            self.hostname,
            user.nick,
            user.nick,
            user.username,
            self.hostname,
            user.nick,
        },
    );
    try conn.print(self.gpa, ":{s} 903 {s} :SASL successful\r\n", .{ self.hostname, user.nick });
    // RPL_WELCOME
    try conn.print(self.gpa, ":{s} 001 {s} :Good Apollo, I'm burning Star IV!\r\n", .{ self.hostname, user.nick });
    // RPL_YOURHOST
    try conn.print(self.gpa, ":{s} 002 {s} :Your host is {s}\r\n", .{ self.hostname, user.nick, self.hostname });
    // RPL_CREATED
    try conn.print(self.gpa, ":{s} 003 {s} :This server exists\r\n", .{ self.hostname, user.nick });
    // RPL_MYINFO
    // TODO: include any user or channel modes?
    try conn.print(self.gpa, ":{s} 004 {s} apollo v0.0.0 \r\n", .{ self.hostname, user.nick });
    // ISUPPORT
    try conn.print(
        self.gpa,
        ":{s} 005 {s} WHOX CHATHISTORY={d} MSGREFTYPES=timestamp PREFIX=(o)@ :are supported\r\n",
        .{ self.hostname, user.nick, max_chathistory },
    );

    // MOTD. Some clients check for these, so we need to send them unilaterally (eg goguma)
    try conn.print(self.gpa, ":{s} 375 {s} :Message of the day -\r\n", .{ self.hostname, user.nick });
    try conn.print(self.gpa, ":{s} 376 {s} :End of Message of the day -\r\n", .{ self.hostname, user.nick });

    // If this is the only connection the user has, we notify all channels they are a member of
    // that they are back
    if (user.connections.items.len == 1) {
        for (user.channels.items) |chan| {
            try chan.notifyBack(self, user);
        }
    }

    // Send a join to the user for all of their channels
    for (user.channels.items) |chan| {
        var buf: [128]u8 = undefined;
        const m = std.fmt.bufPrint(&buf, "JOIN {s}", .{chan.name}) catch unreachable;
        try self.handleJoin(conn, .init(m));
    }

    // If the client isn't part of any channels, we'll force them into #apollo
    if (user.channels.items.len == 0) {
        try self.handleJoin(conn, .init("JOIN #apollo"));
    }

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
    log.debug("accepted connection: fd={d}", .{client.fd});
    const completion = try self.completion_pool.create(self.gpa);
    const conn = try self.gpa.create(Connection);
    conn.init(client, completion);

    try self.connections.put(self.gpa, client, conn);

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

    const conn = self.connections.get(client) orelse {
        log.warn("connection not found: fd={d}", .{client.fd});
        return;
    };

    // Remove this connection from any pending auth state
    for (self.pending_auth.items, 0..) |v, i| {
        if (v.conn == conn) {
            _ = self.pending_auth.swapRemove(i);
        }
    }

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
                for (v.channels.items) |chan| {
                    chan.notifyAway(self, v) catch {};
                }
            }
        }
    }
    conn.deinit(self.gpa);
    _ = self.connections.swapRemove(client);
    self.gpa.destroy(conn);
}

/// queues a write of the pending buffer. If there is nothing to queue, this is a noop
pub fn queueWrite(self: *Server, tcp: xev.TCP, conn: *Connection) Allocator.Error!void {
    if (conn.write_buf.items.len == 0) return;
    const buf = try conn.write_buf.toOwnedSlice(self.gpa);
    const write_c = try self.completion_pool.create(self.gpa);
    tcp.write(
        &self.loop,
        write_c,
        .{ .slice = buf },
        Server,
        self,
        Server.onWrite,
    );
}

pub fn queueWriteEventStream(self: *Server, stream: *http.EventStream) Allocator.Error!void {
    if (stream.write_buf.items.len == 0) return;
    const buf = try stream.write_buf.toOwnedSlice(self.gpa);
    const tcp: xev.TCP = .{ .fd = stream.stream.fd };
    tcp.write(
        &self.loop,
        &stream.write_c,
        .{ .slice = buf },
        Server,
        self,
        Server.onEventStreamWrite,
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

fn onEventStreamWrite(
    ud: ?*Server,
    _: *xev.Loop,
    _: *xev.Completion,
    tcp: xev.TCP,
    wb: xev.WriteBuffer,
    result: xev.WriteError!usize,
) xev.CallbackAction {
    const self = ud.?;
    defer self.gpa.free(wb.slice);

    const n = result catch |err| {
        log.warn("Event stream error, probably closed: {}", .{err});
        // Clean up the stream. We remove it from the Server streams, and the channel streams
        const kv = self.event_streams.fetchSwapRemove(tcp) orelse return .disarm;
        const es = kv.value;
        const channel = es.channel;
        for (channel.streams.items, 0..) |item, i| {
            if (item == es) {
                _ = channel.streams.swapRemove(i);
                break;
            }
        }
        std.posix.close(es.stream.fd);
        es.write_buf.deinit(self.gpa);
        self.gpa.destroy(es);
        return .disarm;
    };

    log.debug("event stream write: {s}", .{std.mem.trimRight(u8, wb.slice[0..n], "\r\n")});

    const es = self.event_streams.get(tcp) orelse {
        log.err("event_stream not found: {d}", .{tcp.fd});
        std.posix.close(tcp.fd);
        return .disarm;
    };

    // Incomplete write. Insert the unwritten portion at the front of the list and we'll requeue
    if (n < wb.slice.len) {
        es.write_buf.insertSlice(self.gpa, 0, wb.slice[n..]) catch |err| {
            log.err("couldn't insert unwritten bytes: {}", .{err});
            return .disarm;
        };
    }
    self.queueWriteEventStream(es) catch {};
    return .disarm;
}

/// queues a write of the pending buffer. On completion, closes the conenction
fn queueFinalWrite(self: *Server, tcp: xev.TCP, conn: *Connection) Allocator.Error!void {
    if (conn.write_buf.items.len == 0) {
        // client disconnected. Close the fd
        const write_c = try self.completion_pool.create(self.gpa);
        conn.client.close(&self.loop, write_c, Server, self, Server.onClose);
        return;
    }
    const buf = try conn.write_buf.toOwnedSlice(self.gpa);
    const write_c = try self.completion_pool.create(self.gpa);
    tcp.write(
        &self.loop,
        write_c,
        .{ .slice = buf },
        Server,
        self,
        Server.onFinalWrite,
    );
}

fn onFinalWrite(
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
    self.queueFinalWrite(tcp, conn) catch {};
    return .disarm;
}

fn onCancel(
    ud: ?*Server,
    _: *xev.Loop,
    c: *xev.Completion,
    result: xev.CancelError!void,
) xev.CallbackAction {
    log.debug("cancelled completion {x}", .{@intFromPtr(c)});
    const self = ud.?;
    self.completion_pool.destroy(c);
    _ = result catch |err| {
        log.err("close error: {}", .{err});
    };
    return .disarm;
}

fn onClose(
    ud: ?*Server,
    _: *xev.Loop,
    c: *xev.Completion,
    client: xev.TCP,
    result: xev.CloseError!void,
) xev.CallbackAction {
    const self = ud.?;
    _ = result catch |err| {
        log.err("close error: {}", .{err});
    };
    self.handleClientDisconnect(client);
    self.completion_pool.destroy(c);
    return .disarm;
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
            error.Canceled => log.info("read canceled: fd={d}", .{client.fd}),
            error.EOF => log.info("client eof: fd={d}", .{client.fd}),
            else => log.err("read error: {}", .{err}),
        }
        // client disconnected. Close the fd
        client.close(loop, c, Server, self, Server.onClose);
        return .disarm;
    };

    // Handle a disconnected client
    if (n == 0) {
        client.close(loop, c, Server, self, Server.onClose);
        return .disarm;
    }

    // Get the client
    const conn = self.connections.get(client) orelse {
        log.warn("client not found: fd={d}", .{client.fd});
        client.close(loop, c, Server, self, Server.onClose);
        return .disarm;
    };

    // Process the newly read bytes
    self.processMessages(conn, rb.slice[0..n]) catch |err| {
        log.err("couldn't process message: fd={d}", .{client.fd});
        switch (err) {
            error.OutOfMemory => return .disarm,
            error.ClientQuit => {
                self.queueFinalWrite(client, conn) catch {
                    // On error, we just close the fd
                    client.close(loop, c, Server, self, Server.onClose);
                };
                return .disarm;
            },
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

fn processMessages(self: *Server, conn: *Connection, bytes: []const u8) ProcessMessageError!void {
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
        try self.handleMessage(conn, msg);
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

fn handleMessage(self: *Server, conn: *Connection, msg: Message) ProcessMessageError!void {
    const cmd = msg.command();

    const client_msg = ClientMessage.fromString(cmd) orelse {
        return self.errUnknownCommand(conn, cmd);
    };

    switch (client_msg) {
        .CAP => try self.handleCap(conn, msg),
        .NICK => try self.handleNick(conn, msg),
        .USER => try self.handleUser(conn, msg),
        .AUTHENTICATE => try self.handleAuthenticate(conn, msg),
        .PASS => {},
        .PING => try self.handlePing(conn, msg),
        .QUIT => try self.handleQuit(conn, msg),
        .MODE => try self.handleMode(conn, msg),

        .JOIN => try self.handleJoin(conn, msg),
        .TOPIC => try self.handleTopic(conn, msg),
        .PART => try self.handlePart(conn, msg),
        .NAMES => try self.handleNames(conn, msg),
        .LIST => try self.handleList(conn, msg),

        .PRIVMSG => try self.handlePrivMsg(conn, msg),
        .TAGMSG => try self.handleTagMsg(conn, msg),

        .WHO => try self.handleWho(conn, msg),

        .AWAY => try self.handleAway(conn, msg),
        .CHATHISTORY => try self.handleChathistory(conn, msg),
        .MARKREAD => try self.handleMarkread(conn, msg),
        else => try self.errUnknownCommand(conn, cmd),
    }
}

fn handleCap(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    var iter = msg.paramIterator();
    const subcmd = iter.next() orelse return self.errNeedMoreParams(conn, "CAP");

    if (std.mem.eql(u8, subcmd, "LS")) {
        // LS lists available capabilities
        // We expect a 302, but we don't actually care
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
        const caps = iter.next() orelse return;
        var cap_iter = std.mem.splitScalar(u8, caps, ' ');
        while (cap_iter.next()) |cap_str| {
            const cap = std.meta.stringToEnum(Capability, cap_str) orelse {
                try conn.print(
                    self.gpa,
                    ":{s} CAP {s} NAK {s}\r\n",
                    .{ self.hostname, conn.nickname(), cap_str },
                );
                continue;
            };
            try conn.enableCap(cap);
            try conn.print(
                self.gpa,
                ":{s} CAP {s} ACK {s}\r\n",
                .{ self.hostname, conn.nickname(), cap_str },
            );
        }
    } else if (std.mem.eql(u8, subcmd, "END")) {
        // END signals the end of capability negotiation. It's possible to be authenticated
        // already if it happened really fast
    } else return conn.print(
        self.gpa,
        ":{s} 410 {s} {s} :Invalid CAP command\r\n",
        .{ self.hostname, conn.nickname(), subcmd },
    );
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
    const pending_mech: ?SaslMechanism = for (self.pending_auth.items, 0..) |pending_conn, i| {
        if (pending_conn.conn == conn) {
            // This connection is already pending auth. We can remove it from the list now
            _ = self.pending_auth.swapRemove(i);
            break pending_conn.mechanism;
        }
    } else null;

    if (pending_mech == null) {
        // We "unauthenticate" the connection by setting it's user field to null. We do this
        // even for failure
        conn.user = null;
        // If we aren't pending auth, this should be AUTHENTICATE <mechanism>
        // We first must get AUTHENTICATE <mechanism>
        const mechanism = iter.next() orelse
            return self.errNeedMoreParams(conn, "AUTHENTICATE");
        if (std.ascii.eqlIgnoreCase("PLAIN", mechanism)) {
            const pending: PendingAuth = .{ .mechanism = .plain, .conn = conn };
            try self.pending_auth.append(self.gpa, pending);
            return conn.write(self.gpa, "AUTHENTICATE +\r\n");
        }
        return conn.print(
            self.gpa,
            ":{s} 908 {s} PLAIN :are available SASL mechanisms\r\n",
            .{ self.hostname, conn.nickname() },
        );
    }

    // This is our username + password
    const str = iter.next() orelse return self.errNeedMoreParams(conn, "AUTHENTICATE");

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

    // The password
    const password = sasl_iter.next() orelse
        return self.errSaslFail(conn, "invalid SASL message");

    const arena: HeapArena = try .init(self.gpa);
    errdefer arena.deinit();
    switch (self.auth) {
        .none => {
            self.wakeup_queue.push(.{
                .auth_success = .{
                    .arena = arena,
                    .fd = conn.client,
                    .nick = try arena.allocator().dupe(u8, authenticate_as),
                    .user = try arena.allocator().dupe(u8, authenticate_as),
                    .realname = try arena.allocator().dupe(u8, authenticate_as),
                    .avatar_url = "",
                },
            });
        },
        .github => {
            const auth_header = try std.fmt.allocPrint(
                arena.allocator(),
                "Bearer {s}",
                .{password},
            );
            try self.thread_pool.spawn(github.authenticate, .{
                arena,
                &self.http_client,
                &self.wakeup_queue,
                conn.client,
                auth_header,
            });
        },
        .atproto => {
            const handle = try arena.allocator().dupe(u8, authenticate_as);
            const dupe_pass = try arena.allocator().dupe(u8, password);
            try self.thread_pool.spawn(
                atproto.authenticateConnection,
                .{
                    arena,
                    &self.http_client,
                    &self.wakeup_queue,
                    self.db_pool,
                    conn.client,
                    handle,
                    dupe_pass,
                },
            );
        },
    }
}

fn handlePing(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    try conn.print(
        self.gpa,
        ":{s} PONG {s} :{s}\r\n",
        .{ self.hostname, self.hostname, msg.rawParameters() },
    );
}

fn handleQuit(self: *Server, conn: *Connection, msg: Message) error{ClientQuit}!void {
    _ = msg;
    conn.print(self.gpa, ":{s} ERROR :Client quit\r\n", .{self.hostname}) catch {};
    return error.ClientQuit;
}

fn handleMode(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, "MODE");
    if (target.len == 0) return self.errNeedMoreParams(conn, "MODE");

    if (target[0] != '#') {
        // User MODE
        const source = conn.user orelse
            return self.errUnknownError(conn, "MODE", "must be authenticated for MODE");
        _ = source;
        // TODO: implement this
        return;
    }

    // Target is a channel
    const channel = self.channels.get(target) orelse {
        return self.errNoSuchChannel(conn, target);
    };

    const modestring = iter.next() orelse {
        // TODO: send the channel mode. We don't have any right now
        return;
    };

    // If we have a modestring, we also have to be authenticated
    const user = conn.user orelse {
        return self.errChanOpPrivsNeeded(conn, channel.name);
    };

    const privs = channel.getPrivileges(user);

    if (!user.modes.operator and !privs.operator) {
        // User either needs to be global ops or chanops
        return self.errChanOpPrivsNeeded(conn, channel.name);
    }

    // We have the right privileges. Get the arguments (we should have one, a nickname)
    const arg = iter.next() orelse return self.errNeedMoreParams(conn, "MODE");

    // Validate the argument
    if (arg.len == 0) return self.errNeedMoreParams(conn, "MODE");
    if (arg[0] == '#') return self.errUnknownError(conn, "MODE", "argument cannot be a channel");

    // Get the target user we are modifying the mode of
    const target_user = self.nick_map.get(arg) orelse {
        return self.errNoSuchNick(conn, arg);
    };

    // Get the target_users current privileges
    var target_privs = channel.getPrivileges(target_user);

    // Parse and apply the privileges
    const State = enum { none, add, remove };
    var state: State = .none;
    for (modestring) |b| {
        switch (b) {
            '+' => state = .add,
            '-' => state = .remove,
            'o' => {
                switch (state) {
                    .add => target_privs.operator = true,
                    .remove => target_privs.operator = false,
                    .none => {},
                }
            },
            else => log.warn("unsupported mode byte: {c}", .{b}),
        }
    }

    // Update the state in mem and db
    return channel.storePrivileges(self, target_user, target_privs);
}

fn handlePrivMsg(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const source = conn.user orelse
        return self.errUnknownError(conn, "PRIVMSG", "cannot PRIVMSG before authentication");

    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNoRecipient(conn);
    const text = iter.next() orelse return self.errNoTextToSend(conn);

    if (target.len == 0) return self.errNoRecipient(conn);
    switch (target[0]) {
        '#' => {
            const channel = self.channels.get(target) orelse {
                return self.errNoSuchChannel(conn, target);
            };

            {
                // store the message
                const arena: HeapArena = try .init(self.gpa);
                errdefer arena.deinit();
                const sender_nick = try arena.allocator().dupe(u8, source.nick);
                const target_name = try arena.allocator().dupe(u8, target);
                const msg_dupe = try msg.copy(arena.allocator());
                try self.thread_pool.spawn(
                    db.storeChannelMessage,
                    .{ arena, self.db_pool, sender_nick, target_name, msg_dupe },
                );
            }

            // Send message to any http clients.
            try channel.sendPrivMsgToStreams(self, source, msg);

            for (channel.members.items) |m| {
                const u = m.user;
                for (u.connections.items) |c| {
                    // If this is our account, we only send if we have echo-message enabled
                    if (u == source and !c.caps.@"echo-message") continue;
                    if (c.caps.@"server-time" or c.caps.@"message-tags") {
                        const urn = uuid.urn.serialize(msg.uuid);
                        try c.print(
                            self.gpa,
                            "@time={};msgid={s} ",
                            .{ msg.timestamp, &urn },
                        );
                    }

                    try c.print(self.gpa, ":{s} PRIVMSG {s} :{s}\r\n", .{ source.nick, target, text });
                    try self.queueWrite(c.client, c);
                }
            }
        },
        else => {
            // Get the connections for this nick
            const user = self.nick_map.get(target) orelse {
                return self.errNoSuchNick(conn, target);
            };

            {
                // store the message
                const arena: HeapArena = try .init(self.gpa);
                errdefer arena.deinit();
                const sender_nick = try arena.allocator().dupe(u8, source.nick);
                const target_name = try arena.allocator().dupe(u8, target);
                const msg_dupe = try msg.copy(arena.allocator());
                try self.thread_pool.spawn(
                    db.storePrivateMessage,
                    .{ arena, self.db_pool, sender_nick, target_name, msg_dupe },
                );
            }

            for (user.connections.items) |c| {
                if (c.caps.@"server-time" or c.caps.@"message-tags") {
                    const urn = uuid.urn.serialize(msg.uuid);
                    try c.print(
                        self.gpa,
                        "@time={};msgid={s} ",
                        .{ msg.timestamp, &urn },
                    );
                }

                try c.print(self.gpa, ":{s} PRIVMSG {s} :{s}\r\n", .{ source.nick, target, text });
                try self.queueWrite(c.client, c);
            }

            for (source.connections.items) |c| {
                if (!c.caps.@"echo-message") continue;
                if (c.caps.@"server-time" or c.caps.@"message-tags") {
                    const urn = uuid.urn.serialize(msg.uuid);
                    try c.print(
                        self.gpa,
                        "@time={};msgid={s} ",
                        .{ msg.timestamp, &urn },
                    );
                }

                try c.print(self.gpa, ":{s} PRIVMSG {s} :{s}\r\n", .{ source.nick, target, text });
                try self.queueWrite(c.client, c);
            }
        },
    }
}

fn handleTagMsg(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const source = conn.user orelse
        return self.errUnknownError(conn, "TAGMSG", "cannot TAGMSG before authentication");
    // TODO: store the message in database
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNoRecipient(conn);

    if (target.len == 0) return self.errNoRecipient(conn);
    switch (target[0]) {
        '#' => {
            const channel = self.channels.get(target) orelse {
                return self.errNoSuchChannel(conn, target);
            };
            for (channel.members.items) |m| {
                const u = m.user;
                for (u.connections.items) |c| {
                    // We don't send tag messages to connections which haven't enabled
                    // message-tags
                    if (!c.caps.@"message-tags") continue;
                    // If this is our account, we only send if we have echo-message enabled
                    if (u == source and !c.caps.@"echo-message") continue;

                    if (c.caps.@"server-time") {
                        try c.print(self.gpa, "@time={}", .{msg.timestamp});
                    }

                    var tag_iter = msg.tagIterator();
                    while (tag_iter.next()) |tag| {
                        try c.write(self.gpa, ";");
                        try c.write(self.gpa, tag.key);
                        try c.write(self.gpa, "=");
                        try c.write(self.gpa, tag.value);
                    }
                    try c.write(self.gpa, " ");

                    try c.print(self.gpa, ":{s} TAGMSG {s}\r\n", .{ source.nick, target });
                    try self.queueWrite(c.client, c);
                }
            }
        },
        else => {
            // Get the connections for this nick
            const user = self.nick_map.get(target) orelse {
                return self.errNoSuchNick(conn, target);
            };

            for (user.connections.items) |c| {
                // We don't send tag messages to connections which haven't enabled
                // message-tags
                if (!c.caps.@"message-tags") continue;
                if (c.caps.@"server-time") {
                    try c.print(self.gpa, "@time={}", .{msg.timestamp});
                }

                var tag_iter = msg.tagIterator();
                while (tag_iter.next()) |tag| {
                    try c.write(self.gpa, ";");
                    try c.write(self.gpa, tag.key);
                    try c.write(self.gpa, "=");
                    try c.write(self.gpa, tag.value);
                }
                try c.write(self.gpa, " ");

                try c.print(self.gpa, ":{s} TAGMSG {s}\r\n", .{ source.nick, target });
                try self.queueWrite(c.client, c);
            }

            for (source.connections.items) |c| {
                if (!c.caps.@"echo-message") continue;
                if (c.caps.@"server-time") {
                    try c.print(self.gpa, "@time={}", .{msg.timestamp});
                }

                var tag_iter = msg.tagIterator();
                while (tag_iter.next()) |tag| {
                    try c.write(self.gpa, ";");
                    try c.write(self.gpa, tag.key);
                    try c.write(self.gpa, "=");
                    try c.write(self.gpa, tag.value);
                }
                try c.write(self.gpa, " ");

                try c.print(self.gpa, ":{s} TAGMSG {s}\r\n", .{ source.nick, target });
                try self.queueWrite(c.client, c);
            }
        },
    }
}

fn handleJoin(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const user = conn.user orelse
        return self.errUnknownError(conn, "JOIN", "cannot join before authentication");
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, "JOIN");

    if (target.len > 32) {
        return conn.print(
            self.gpa,
            ":{s} 476 {s} :Channel name is too long\r\n",
            .{ self.hostname, target },
        );
    }

    if (target.len == 0) return self.errNeedMoreParams(conn, "JOIN");
    switch (target[0]) {
        '#' => {},
        else => return self.errNoSuchChannel(conn, target),
    }

    if (!self.channels.contains(target)) {
        const arena: HeapArena = try .init(self.gpa);
        const target_dupe = try arena.allocator().dupe(u8, target);
        // Create the channel in the db
        try self.thread_pool.spawn(db.createChannel, .{ arena, self.db_pool, target_dupe });

        const channel = try self.gpa.create(Channel);
        const name = try self.gpa.dupe(u8, target);
        channel.* = .init(name, "");
        try self.channels.put(self.gpa, name, channel);
    }

    const channel = self.channels.get(target).?;
    try channel.addUser(self, user, conn);

    // drafts/read-marker requires us to send a MARKREAD on join
    if (conn.caps.@"draft/read-marker") {
        const arena: HeapArena = try .init(self.gpa);
        const target2 = try arena.allocator().dupe(u8, target);
        const nick = try arena.allocator().dupe(u8, user.nick);

        try self.thread_pool.spawn(db.getMarkRead, .{
            arena,
            self.db_pool,
            &self.wakeup_queue,
            conn.client,
            nick,
            target2,
        });
    }
}

fn handleTopic(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, "TOPIC");
    const topic = iter.next() orelse "";
    if (topic.len > 0 and conn.user == null) {
        return self.errUnknownError(conn, "TOPIC", "cannot set topic without authentication");
    }

    const channel = self.channels.get(target) orelse {
        return self.errNoSuchChannel(conn, target);
    };
    try channel.setTopic(self, conn, topic);
}

fn handlePart(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const user = conn.user orelse
        return self.errUnknownError(conn, "PART", "cannot part before authentication");
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, "JOIN");

    var chan_iter = std.mem.splitScalar(u8, target, ',');
    while (chan_iter.next()) |chan| {
        const channel = self.channels.get(chan) orelse continue;
        try channel.removeUser(self, user);
    }
}

fn handleNames(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const cmd = "NAMES";
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, cmd);

    if (target.len == 0) return self.errNeedMoreParams(conn, cmd);
    switch (target[0]) {
        '#' => {},
        else => return self.errUnknownError(conn, cmd, "not a valid channel name"),
    }

    const channel = self.channels.get(target) orelse {
        return self.errNoSuchChannel(conn, target);
    };

    try channel.names(self, conn);
}

fn handleList(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    // TODO: handle masks
    _ = msg;
    try conn.print(
        self.gpa,
        ":{s} 321 {s} Channel :Start of LIST\r\n",
        .{ self.hostname, conn.nickname() },
    );

    for (self.channels.values()) |channel| {
        try conn.print(
            self.gpa,
            ":{s} 322 {s} {s} {d} :{s}\r\n",
            .{
                self.hostname,
                conn.nickname(),
                channel.name,
                channel.members.items.len,
                channel.topic,
            },
        );
    }

    try conn.print(
        self.gpa,
        ":{s} 323 {s} :End of LIST\r\n",
        .{ self.hostname, conn.nickname() },
    );
}

fn handleWho(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const cmd = "WHO";
    var iter = msg.paramIterator();
    const target = iter.next() orelse return self.errNeedMoreParams(conn, cmd);

    if (target.len == 0) return self.errNeedMoreParams(conn, cmd);
    switch (target[0]) {
        '#' => {
            const channel = self.channels.get(target) orelse {
                return self.errNoSuchChannel(conn, target);
            };

            try channel.who(self, conn, msg);
        },
        else => {
            const client: []const u8 = if (conn.user) |user| user.nick else "*";
            const user = self.nick_map.get(target) orelse {
                return self.errNoSuchNick(conn, target);
            };
            const args = iter.next() orelse "";
            const token = iter.next();
            if (args.len == 0) {
                try conn.print(
                    self.gpa,
                    ":{s} 352 {s} * {s} {s} {s} {s} {s} :0 {s}\r\n",
                    .{
                        self.hostname,
                        client,
                        user.username,
                        self.hostname,
                        self.hostname,
                        user.nick,
                        "H", // TODO: flags, now we just always say the user is H="here"
                        user.real,
                    },
                );
            } else {
                try conn.print(
                    self.gpa,
                    ":{s} 354 {s}",
                    .{ self.hostname, client },
                );

                // Find the index of the standard field indicator
                const std_idx = std.mem.indexOfScalar(u8, args, '%') orelse args.len;
                // TODO: any nonstandard fields

                // Handle standard fields, in order. The order is tcuihsnfdlaor
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 't')) |_| {
                    if (token) |t| try conn.print(self.gpa, " {s}", .{t});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'c')) |_| {
                    try conn.print(self.gpa, " *", .{});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'u')) |_| {
                    try conn.print(self.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'i')) |_| {
                    try conn.print(self.gpa, " {s}", .{"127.0.0.1"});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'h')) |_| {
                    try conn.print(self.gpa, " {s}", .{self.hostname});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 's')) |_| {
                    try conn.print(self.gpa, " {s}", .{self.hostname});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'n')) |_| {
                    try conn.print(self.gpa, " {s}", .{user.nick});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'f')) |_| {
                    // TODO: user flags
                    try conn.print(self.gpa, " H", .{});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'd')) |_| {
                    try conn.write(self.gpa, " 0");
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'l')) |_| {
                    try conn.write(self.gpa, " 0");
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'a')) |_| {
                    try conn.print(self.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'o')) |_| {
                    // TODO: chan op level
                    try conn.print(self.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'r')) |_| {
                    try conn.print(self.gpa, " :{s}", .{user.real});
                }
                try conn.write(self.gpa, "\r\n");
            }
            try conn.print(
                self.gpa,
                ":{s} 315 {s} * :End of WHO list\r\n",
                .{ self.hostname, client },
            );
            try self.queueWrite(conn.client, conn);
        },
    }
}

fn handleAway(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const user = conn.user orelse
        return self.errUnknownError(conn, "AWAY", "cannot set AWAY without authentication");

    var iter = msg.paramIterator();
    if (iter.next()) |_| {
        user.away = true;
        for (user.channels.items) |chan| {
            try chan.notifyAway(self, user);
        }
        for (user.connections.items) |c| {
            try c.print(
                self.gpa,
                ":{s} 306 {s} :You have been marked as away\r\n",
                .{ self.hostname, c.nickname() },
            );
            try self.queueWrite(c.client, c);
        }
    } else {
        user.away = false;
        for (user.channels.items) |chan| {
            try chan.notifyBack(self, user);
        }
        for (user.connections.items) |c| {
            try c.print(
                self.gpa,
                ":{s} 305 {s} :You are no longer marked as away\r\n",
                .{ self.hostname, c.nickname() },
            );
            try self.queueWrite(c.client, c);
        }
    }
}

fn handleChathistory(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const user = conn.user orelse return self.errUnknownError(
        conn,
        "CHATHISTORY TARGETS",
        "cannot CHATHISTORY without authentication",
    );
    const cmd = "CHATHISTORY";
    var iter = msg.paramIterator();

    const subcmd = iter.next() orelse return self.errNeedMoreParams(conn, cmd);

    if (std.ascii.eqlIgnoreCase("TARGETS", subcmd)) {
        const sub = "TARGETS";
        // "TARGETS <ts_one> <ts_two> <limit>". There is no requirement that ts_one < ts_two
        const ts_one = iter.next() orelse return self.errNeedMoreParams(conn, cmd ++ " " ++ sub);
        const ts_two = iter.next() orelse return self.errNeedMoreParams(conn, cmd ++ " " ++ sub);
        const limit = iter.next() orelse return self.errNeedMoreParams(conn, cmd ++ " " ++ sub);

        const ts_one_str = blk: {
            var ts_iter = std.mem.splitScalar(u8, ts_one, '=');
            _ = ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "invalid param");
            break :blk ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "invalid param");
        };
        const ts_two_str = blk: {
            var ts_iter = std.mem.splitScalar(u8, ts_two, '=');
            _ = ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "invalid param");
            break :blk ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "invalid param");
        };

        const ts_one_inst = zeit.instant(.{ .source = .{ .iso8601 = ts_one_str } }) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid timestamp");
        };
        const ts_two_inst = zeit.instant(.{ .source = .{ .iso8601 = ts_two_str } }) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid timestamp");
        };
        // NOTE: For TARGETS, we don't have an internal limit
        const limit_int: u16 = std.fmt.parseUnsigned(u16, limit, 10) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        };

        const from = if (ts_one_inst.timestamp < ts_two_inst.timestamp) ts_one_inst else ts_two_inst;
        const to = if (ts_one_inst.timestamp > ts_two_inst.timestamp) ts_one_inst else ts_two_inst;

        const req: ChatHistory.TargetsRequest = .{
            .from = .{ .milliseconds = @intCast(from.milliTimestamp()) },
            .to = .{ .milliseconds = @intCast(to.milliTimestamp()) },
            .limit = limit_int,
        };
        const arena: HeapArena = try .init(self.gpa);
        const nick = try arena.allocator().dupe(u8, user.nick);
        // Spawn a db query
        try self.thread_pool.spawn(
            db.chathistoryTargets,
            .{ arena, self.db_pool, &self.wakeup_queue, conn.client, nick, req },
        );
        return;
    }

    if (std.ascii.eqlIgnoreCase("AFTER", subcmd)) {
        const target = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        if (target.len == 0) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid target");
        }

        const ts = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        const ts_str = blk: {
            var ts_iter = std.mem.splitScalar(u8, ts, '=');
            _ = ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "no timestamp param");
            break :blk ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "no '=' separator");
        };
        const ts_inst = zeit.instant(.{ .source = .{ .iso8601 = ts_str } }) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid timestamp");
        };

        const limit_str = iter.next() orelse return self.errNeedMoreParams(conn, cmd);

        const limit_int: u16 = std.fmt.parseUnsigned(u16, limit_str, 10) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        };
        if (limit_int > max_chathistory) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        }

        const arena: HeapArena = try .init(self.gpa);
        const req: ChatHistory.AfterRequest = .{
            .after_ms = .{ .milliseconds = @intCast(ts_inst.milliTimestamp()) },
            .limit = limit_int,
            .target = try arena.allocator().dupe(u8, target),
        };
        try self.thread_pool.spawn(
            db.chathistoryAfter,
            .{ arena, self.db_pool, &self.wakeup_queue, conn.client, req },
        );
        return;
    }

    if (std.ascii.eqlIgnoreCase("BEFORE", subcmd)) {
        const target = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        if (target.len == 0) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid target");
        }

        const ts = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        const ts_str = blk: {
            var ts_iter = std.mem.splitScalar(u8, ts, '=');
            _ = ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "no timestamp param");
            break :blk ts_iter.next() orelse return self.fail(conn, cmd, "INVALID_PARAMS", "no '=' separator");
        };
        const ts_inst = zeit.instant(.{ .source = .{ .iso8601 = ts_str } }) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid timestamp");
        };

        const limit_str = iter.next() orelse return self.errNeedMoreParams(conn, cmd);

        const limit_int: u16 = std.fmt.parseUnsigned(u16, limit_str, 10) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        };
        if (limit_int > max_chathistory) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        }

        const arena: HeapArena = try .init(self.gpa);
        const req: ChatHistory.BeforeRequest = .{
            .conn = conn,
            .before_ms = .{ .milliseconds = @intCast(ts_inst.milliTimestamp()) },
            .limit = limit_int,
            .target = try arena.allocator().dupe(u8, target),
        };
        try self.thread_pool.spawn(
            db.chathistoryBefore,
            .{ arena, self.db_pool, &self.wakeup_queue, conn.client, req },
        );
        return;
    }

    if (std.ascii.eqlIgnoreCase("LATEST", subcmd)) {
        const target = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        if (target.len == 0) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid target");
        }

        const restriction = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        // TODO: handle the restriction. This could be "*", or a timestamp, or a msgid
        _ = restriction;

        const limit_str = iter.next() orelse return self.errNeedMoreParams(conn, cmd);
        const limit_int: u16 = std.fmt.parseUnsigned(u16, limit_str, 10) catch {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        };
        if (limit_int > max_chathistory) {
            return self.fail(conn, cmd, "INVALID_PARAMS", "invalid limit");
        }

        const arena: HeapArena = try .init(self.gpa);
        const req: ChatHistory.LatestRequest = .{
            .conn = conn,
            .limit = limit_int,
            .target = try arena.allocator().dupe(u8, target),
        };
        try self.thread_pool.spawn(
            db.chathistoryLatest,
            .{ arena, self.db_pool, &self.wakeup_queue, conn.client, req },
        );
        return;
    }
}

fn handleMarkread(self: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
    const user = conn.user orelse return;
    var iter = msg.paramIterator();
    const target = iter.next() orelse
        return self.fail(conn, "MARKREAD", "NEED_MORE_PARAMS", "Missing parameters");
    if (iter.next()) |timestamp| {
        const ts_str = blk: {
            var ts_iter = std.mem.splitScalar(u8, timestamp, '=');
            _ = ts_iter.next() orelse return self.fail(conn, "MARKREAD", "INVALID_PARAMS", "no timestamp param");
            break :blk ts_iter.next() orelse return self.fail(conn, "MARKREAD", "INVALID_PARAMS", "no '=' separator");
        };
        const ts_inst = zeit.instant(.{ .source = .{ .iso8601 = ts_str } }) catch {
            return self.fail(conn, "MARKREAD", "INVALID_PARAMS", "invalid timestamp");
        };

        const arena: HeapArena = try .init(self.gpa);
        const target_duped = try arena.allocator().dupe(u8, target);
        const ts_: Timestamp = .{ .milliseconds = @intCast(ts_inst.milliTimestamp()) };
        try self.thread_pool.spawn(db.setMarkRead, .{
            arena,
            self.db_pool,
            &self.wakeup_queue,
            conn.client,
            user.nick,
            target_duped,
            ts_,
        });
    }
}

/// Sends a "standard reply" FAIL
fn fail(
    self: *Server,
    conn: *Connection,
    cmd: []const u8,
    code: []const u8,
    description: []const u8,
) Allocator.Error!void {
    return self.standardReply(conn, "FAIL", cmd, code, description);
}

fn standardReply(
    self: *Server,
    conn: *Connection,
    kind: []const u8,
    cmd: []const u8,
    code: []const u8,
    description: []const u8,
) Allocator.Error!void {
    try conn.print(
        self.gpa,
        ":{s} {s} {s} {s} :{s}\r\n",
        .{ self.hostname, kind, cmd, code, description },
    );
}

fn errNoSuchNick(self: *Server, conn: *Connection, nick_or_chan: []const u8) Allocator.Error!void {
    try conn.print(
        self.gpa,
        ":{s} 401 {s} {s} :No such nick/channel\r\n",
        .{ self.hostname, conn.nickname(), nick_or_chan },
    );
}

fn errNoSuchChannel(self: *Server, conn: *Connection, chan: []const u8) Allocator.Error!void {
    try conn.print(
        self.gpa,
        ":{s} 403 {s} {s} :No such channel\r\n",
        .{ self.hostname, conn.nickname(), chan },
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

pub fn errChanOpPrivsNeeded(self: *Server, conn: *Connection, channel: []const u8) Allocator.Error!void {
    try conn.print(
        self.gpa,
        ":{s} 482 {s} {s} :You must be a channel operator to perform that command\r\n",
        .{ self.hostname, conn.nickname(), channel },
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

fn webMain(
    self: *Server,
    port: u16,
) !void {
    const server = &self.httpz_server;
    var router = try server.router(.{});
    router.get("/", Http.getIndex, .{});
    router.get("/assets/:type/:name", Http.getAsset, .{});
    router.get("/channels/:channel", Http.getChannel, .{});
    router.get("/channels/:channel/events", Http.startChannelEventStream, .{});
    router.get("/channels", Http.getChannels, .{});

    log.info("HTTP server listening on http://localhost:{d}", .{port});
    try self.httpz_server.listen();
}

pub const Connection = struct {
    client: xev.TCP,

    read_buf: [512]u8,
    read_queue: std.ArrayListUnmanaged(u8),
    read_c: *xev.Completion,

    write_buf: std.ArrayListUnmanaged(u8),

    /// User will always be non-null for authenticated connections
    user: ?*User,

    caps: Capabilities,
    // Time the connection started
    connected_at: u32,

    fn init(self: *Connection, client: xev.TCP, completion: *xev.Completion) void {
        self.* = .{
            .client = client,

            .read_buf = undefined,
            .read_queue = .empty,
            .read_c = completion,

            .write_buf = .empty,

            .user = null,

            .caps = .{},
            .connected_at = @intCast(std.time.timestamp()),
        };
    }

    fn isAuthenticated(self: *Connection) bool {
        return self.user != null;
    }

    pub fn nickname(self: *Connection) []const u8 {
        if (self.user) |user| return user.nick;
        return "*";
    }

    fn deinit(self: *Connection, gpa: Allocator) void {
        self.read_queue.deinit(gpa);
        self.write_buf.deinit(gpa);
    }

    pub fn write(self: *Connection, gpa: Allocator, bytes: []const u8) Allocator.Error!void {
        try self.write_buf.appendSlice(gpa, bytes);
    }

    pub fn print(self: *Connection, gpa: Allocator, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        return self.write_buf.writer(gpa).print(fmt, args);
    }

    fn enableCap(self: *Connection, cap: Capability) Allocator.Error!void {
        switch (cap) {
            .@"away-notify" => self.caps.@"away-notify" = true,
            .batch => {}, // TODO: do we care?
            .@"draft/chathistory" => self.caps.@"draft/chathistory" = true,
            .@"draft/read-marker" => self.caps.@"draft/read-marker" = true,
            .@"draft/no-implicit-names" => self.caps.@"draft/no-implicit-names" = true,
            .@"echo-message" => self.caps.@"echo-message" = true,
            .@"message-tags" => self.caps.@"message-tags" = true,
            .@"server-time" => self.caps.@"server-time" = true,
            .sasl => {}, // We don't track sasl as a requested cap, we just respond to AUTHENTICATE
        }
    }
};

// TODO: GC this. We need to move all used completions to the start, and then prune unused to some
// percentage
const MemoryPoolUnmanaged = struct {
    list: std.ArrayListUnmanaged(*xev.Completion),
    free_list: std.ArrayListUnmanaged(bool),

    const empty: MemoryPoolUnmanaged = .{ .list = .empty, .free_list = .empty };

    fn create(self: *MemoryPoolUnmanaged, gpa: Allocator) Allocator.Error!*xev.Completion {
        // Look in our list for the first free item
        for (self.free_list.items, 0..) |free, i| {
            if (free) {
                self.free_list.items[i] = false;
                return self.list.items[i];
            }
        }
        // Otherwise, we create a new node and add it to the list
        const c = try gpa.create(xev.Completion);
        c.* = .{};
        try self.list.append(gpa, c);
        try self.free_list.append(gpa, false);
        return c;
    }

    fn destroy(self: *MemoryPoolUnmanaged, item: *xev.Completion) void {
        for (self.list.items, 0..) |c, i| {
            if (c == item) {
                self.free_list.items[i] = true;
                return;
            }
        }
        unreachable;
    }

    fn deinit(self: *MemoryPoolUnmanaged, gpa: Allocator) void {
        for (self.list.items) |node| {
            gpa.destroy(node);
        }
        self.list.deinit(gpa);
        self.free_list.deinit(gpa);
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

    streams: std.ArrayListUnmanaged(std.net.Stream),

    fn init(self: *TestServer, gpa: Allocator) !void {
        self.* = .{
            .server = undefined,
            .cond = .init(true),
            .thread = undefined,
            .streams = .empty,
        };
        try self.server.init(gpa, .{
            .hostname = "localhost",
            .irc_port = 0,
            .http_port = null,
            .auth = .none,
            .db_path = ":memory:",
        });
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
            log.err("Failed to notify wakeup: {}", .{err});
            self.thread.detach();
        }
        self.server.deinit();
        for (self.streams.items) |stream| {
            stream.close();
        }
        self.streams.deinit(std.testing.allocator);
        self.* = undefined;
    }

    fn port(self: *TestServer) u16 {
        return self.server.address.getPort();
    }

    fn createConnections(self: *TestServer, n: usize) ![]*Connection {
        try self.streams.ensureUnusedCapacity(std.testing.allocator, n);
        for (0..n) |_| {
            const stream = try std.net.tcpConnectToHost(
                std.testing.allocator,
                "localhost",
                self.port(),
            );
            self.streams.appendAssumeCapacity(stream);
        }

        // Sleep for up to 1 second to wait for all the connections
        for (0..1_000) |_| {
            if (self.server.connections.count() == n) break;
            std.time.sleep(1 * std.time.ns_per_ms);
        } else return error.Timeout;

        return self.server.connections.values();
    }
};

test "Message: CAP" {
    var ts: TestServer = undefined;
    try ts.init(std.testing.allocator);
    defer ts.deinit();

    const conns = try ts.createConnections(1);
    const client = conns[0];

    {
        // Happy path
        try ts.server.handleMessage(client, .init("CAP LS 302"));
        try std.testing.expectStringStartsWith(client.write_buf.items, ":localhost CAP * LS");
        try std.testing.expectStringEndsWith(client.write_buf.items, "\r\n");
        client.write_buf.clearRetainingCapacity();

        // ACK
        try ts.server.handleMessage(client, .init("CAP REQ sasl"));
        try std.testing.expectStringStartsWith(client.write_buf.items, ":localhost CAP * ACK sasl\r\n");
        client.write_buf.clearRetainingCapacity();

        // NAK
        try ts.server.handleMessage(client, .init("CAP REQ foo"));
        try std.testing.expectStringStartsWith(client.write_buf.items, ":localhost CAP * NAK foo\r\n");
        client.write_buf.clearRetainingCapacity();
    }

    {
        // Not enough parameters
        try ts.server.handleMessage(client, .init("CAP"));
        try std.testing.expectStringStartsWith(client.write_buf.items, ":localhost 461 * CAP");
        try std.testing.expectStringEndsWith(client.write_buf.items, "\r\n");
        client.write_buf.clearRetainingCapacity();
    }

    {
        // Invalid Parameters
        try ts.server.handleMessage(client, .init("CAP foo"));
        try std.testing.expectStringStartsWith(client.write_buf.items, ":localhost 410 * foo");
        try std.testing.expectStringEndsWith(client.write_buf.items, "\r\n");
        client.write_buf.clearRetainingCapacity();
    }
}
