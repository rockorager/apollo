const std = @import("std");
const sqlite = @import("sqlite");
const uuid = @import("uuid");

const log = @import("log.zig");
const irc = @import("irc.zig");

const Allocator = std.mem.Allocator;
const Channel = irc.Channel;
const ChannelPrivileges = irc.ChannelPrivileges;
const ChatHistory = irc.ChatHistory;
const Connection = Server.Connection;
const Message = irc.Message;
const Server = @import("Server.zig");
const Timestamp = irc.Timestamp;
const User = irc.User;

const schema = @embedFile("schema.sql");

/// Called on first db connection
pub fn createTables(conn: sqlite.Conn) anyerror!void {
    try conn.execNoArgs(schema);
}

/// Called for each db connection
pub fn setPragmas(conn: sqlite.Conn) anyerror!void {
    try conn.busyTimeout(5000);
    try conn.execNoArgs("PRAGMA synchronous = normal");
    try conn.execNoArgs("PRAGMA journal_mode = wal");
    try conn.execNoArgs("PRAGMA foreign_keys = on");
}

/// Called in the main thread when the server starts. This loads all the channels in the server
/// and stores them in memory
pub fn loadChannels(server: *Server) !void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    var rows = try conn.rows("SELECT name FROM channels", .{});
    defer rows.deinit();
    while (rows.next()) |row| {
        const channel = try server.gpa.create(Channel);
        channel.* = .{
            .name = try server.gpa.dupe(u8, row.text(0)),
            .topic = "",
            .members = .empty,
            .event_streams = .empty,
        };
        try server.channels.put(server.gpa, channel.name, channel);
    }
}

/// Called in the main thread when the server starts. This loads all the users in the server
/// and stores them in memory
pub fn loadUsers(server: *Server) !void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    var rows = try conn.rows("SELECT did, nick, modes FROM users", .{});
    defer rows.deinit();
    while (rows.next()) |row| {
        const user = try server.gpa.create(User);
        const modes: u1 = @intCast(row.int(2));
        user.* = .{
            .username = try server.gpa.dupe(u8, row.text(0)),
            .nick = try server.gpa.dupe(u8, row.text(1)),
            .real = "",
            .avatar_url = "",
            .connections = .empty,
            .channels = .empty,
            .away = false,
            .modes = @bitCast(modes),
        };
        try server.nick_map.put(server.gpa, user.nick, user);
    }
}

/// Called in the main thread when the server starts. This loads all the channel memberships in
/// the server
pub fn loadChannelMembership(server: *Server) !void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    const sql =
        \\SELECT u.nick, c.name, cm.privileges
        \\FROM channel_membership cm
        \\JOIN users u ON cm.user_id = u.id
        \\JOIN channels c ON cm.channel_id = c.id;
    ;
    var rows = try conn.rows(sql, .{});
    defer rows.deinit();
    while (rows.next()) |row| {
        const nick = row.text(0);
        const ch_name = row.text(1);
        const privileges_val: u1 = @intCast(row.int(2));
        const privileges: ChannelPrivileges = @bitCast(privileges_val);

        const user = server.nick_map.get(nick) orelse {
            log.warn("user with nick {s} not found", .{nick});
            continue;
        };
        const channel = server.channels.get(ch_name) orelse {
            log.warn("channel with name {s} not found", .{ch_name});
            continue;
        };

        // Add the user to the channel
        try channel.members.append(server.gpa, .{ .user = user, .privileges = privileges });
        // Add the channel to the user
        try user.channels.append(server.gpa, channel);
    }
}

pub fn updatePrivileges(
    server: *Server,
    user: *User,
    privs: ChannelPrivileges,
    channel: []const u8,
) void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);

    const sql =
        \\UPDATE channel_membership
        \\SET privileges = ?
        \\WHERE channel_id = (
        \\    SELECT id FROM channels WHERE name = ?
        \\)
        \\AND user_id = (
        \\    SELECT id FROM users WHERE nick = ?
        \\);
    ;
    const privs_as_int: u1 = @bitCast(privs);
    conn.exec(sql, .{ privs_as_int, channel, user.nick }) catch |err| {
        log.err("updating privileges: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

/// Checks if a user is already in the db. If they are, checks their nick is the same. Updates
/// it as needed.
///
/// Creates a user if they don't exist
pub fn storeUser(server: *Server, user: *User) void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);

    // First we see if the user exists
    const maybe_row = conn.row("SELECT id, nick FROM users WHERE did = ?;", .{user.username}) catch |err| {
        log.err("finding user: {}: {s}", .{ err, conn.lastError() });
        return;
    };
    if (maybe_row) |row| {
        defer row.deinit();
        const nick = row.text(1);
        // If the nick is the same, we are done
        if (std.mem.eql(u8, nick, user.nick)) return;
        const id = row.int(0);
        // They aren't equal. Update the nick
        conn.exec("UPDATE users SET nick = ? WHERE id = ?;", .{ user.nick, id }) catch |err| {
            log.err("updating user nick: {}: {s}", .{ err, conn.lastError() });
            return;
        };
        return;
    }

    // This is a new user. Create them
    conn.exec("INSERT INTO users (did, nick) VALUES (?, ?);", .{ user.username, user.nick }) catch |err| {
        log.err("creating user: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

/// Creates a channel
pub fn createChannel(server: *Server, channel: []const u8) void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    conn.exec("INSERT OR IGNORE INTO channels (name) VALUES (?);", .{channel}) catch |err| {
        log.err("creating channel: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

pub fn createChannelMembership(server: *Server, channel: []const u8, nick: []const u8) void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    const sql =
        \\INSERT OR IGNORE INTO channel_membership (user_id, channel_id)
        \\SELECT u.id, c.id
        \\FROM users u
        \\JOIN channels c ON c.name = ?  -- Channel name
        \\WHERE u.nick = ?;              -- User nick
    ;
    conn.exec(sql, .{ channel, nick }) catch |err| {
        log.err("creating channel membership: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

pub fn removeChannelMembership(server: *Server, channel: []const u8, nick: []const u8) void {
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    const sql =
        \\DELETE FROM channel_membership
        \\WHERE user_id = (SELECT id FROM users WHERE nick = ?)
        \\  AND channel_id = (SELECT id FROM channels WHERE name = ?);
    ;
    conn.exec(sql, .{ nick, channel }) catch |err| {
        log.err("creating channel membership: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

/// Stores a message between two users
pub fn storePrivateMessage(server: *Server, sender: *User, target: *User, msg: Message) void {
    const sql =
        \\INSERT INTO messages (uuid, timestamp_ms, sender_id, sender_nick, recipient_id, recipient_type, message)
        \\VALUES (
        \\    ?, -- uuid
        \\    ?, -- timestamp_ms
        \\    (SELECT id FROM users WHERE nick = ?), -- sender_id
        \\    ?, -- sender_nick
        \\    (SELECT id FROM users WHERE nick = ?), -- recipient_id
        \\    1, -- recipient_type (user to user)
        \\    ?  -- message
        \\);
    ;

    const urn = uuid.urn.serialize(msg.uuid);
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    conn.exec(sql, .{
        &urn,
        msg.timestamp.milliseconds,
        sender.nick,
        sender.nick,
        target.nick,
        msg.bytes,
    }) catch |err| {
        log.err("storing message: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

/// Stores a message to a channel
pub fn storeChannelMessage(server: *Server, sender: *User, target: *Channel, msg: Message) void {
    const sql =
        \\INSERT INTO messages (uuid, timestamp_ms, sender_id, sender_nick, recipient_id, recipient_type, message)
        \\VALUES (
        \\    ?, -- uuid
        \\    ?, -- timestamp_ms
        \\    (SELECT id FROM users WHERE nick = ?), -- sender_id
        \\    ?, -- sender_nick
        \\    (SELECT id FROM channels WHERE name = ?), -- recipient_id
        \\    0, -- recipient_type (0 = channel message)
        \\    ?  -- message
        \\);
    ;

    const urn = uuid.urn.serialize(msg.uuid);
    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    conn.exec(sql, .{
        &urn,
        msg.timestamp.milliseconds,
        sender.nick,
        sender.nick,
        target.name,
        msg.bytes,
    }) catch |err| {
        log.err("storing message: {}: {s}", .{ err, conn.lastError() });
        return;
    };
}

pub fn chathistoryTargets(server: *Server, req: ChatHistory.TargetsRequest) void {
    // TODO: implement
    _ = server;
    _ = req;
}

pub fn chathistoryAfter(server: *Server, req: ChatHistory.AfterRequest) void {
    if (req.target.len == 0) return;

    const sql = switch (req.target[0]) {
        '#' =>
        \\SELECT
        \\  uuid,
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 0
        \\AND recipient_id = (SELECT id FROM channels WHERE name = ?)
        \\AND m.timestamp_ms > ?
        \\ORDER BY timestamp_ms ASC
        \\LIMIT ?;
        ,
        else =>
        \\SELECT
        \\  uuid,
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 1
        \\AND recipient_id = (SELECT id FROM users WHERE nick = ?)
        \\AND m.timestamp_ms > ?
        \\ORDER BY timestamp_ms ASC
        \\LIMIT ?;
        ,
    };

    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);

    var rows = conn.rows(sql, .{ req.target, req.after_ms.milliseconds, req.limit }) catch |err| {
        log.err("querying messages: {}: {s}", .{ err, conn.lastError() });
        return;
    };
    defer rows.deinit();

    collectChathistoryRows(&rows, server, req.target, req.conn, req.limit) catch |err| {
        log.err("querying messages: {}", .{err});
        return;
    };
}

pub fn chathistoryBefore(server: *Server, req: ChatHistory.BeforeRequest) void {
    if (req.target.len == 0) return;

    const sql = switch (req.target[0]) {
        '#' =>
        \\SELECT
        \\  uuid,
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 0
        \\AND recipient_id = (SELECT id FROM channels WHERE name = ?)
        \\AND m.timestamp_ms < ?
        \\ORDER BY timestamp_ms DESC
        \\LIMIT ?;
        ,
        else =>
        \\SELECT
        \\  uuid,
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 1
        \\AND recipient_id = (SELECT id FROM users WHERE nick = ?)
        \\AND m.timestamp_ms < ?
        \\ORDER BY timestamp_ms DESC
        \\LIMIT ?;
        ,
    };

    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);

    var rows = conn.rows(sql, .{ req.target, req.before_ms.milliseconds, req.limit }) catch |err| {
        log.err("querying messages: {}: {s}", .{ err, conn.lastError() });
        return;
    };
    defer rows.deinit();

    collectChathistoryRows(&rows, server, req.target, req.conn, req.limit) catch |err| {
        log.err("querying messages: {}", .{err});
        return;
    };
}

pub fn chathistoryLatest(server: *Server, req: ChatHistory.LatestRequest) void {
    if (req.target.len == 0) return;

    const sql = switch (req.target[0]) {
        '#' =>
        \\SELECT 
        \\  uuid, 
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 0
        \\AND recipient_id = (SELECT id FROM channels WHERE name = ?)
        \\ORDER BY m.timestamp_ms DESC
        \\LIMIT ?;
        ,
        else =>
        \\SELECT 
        \\  uuid, 
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 1
        \\AND recipient_id = (SELECT id FROM users WHERE nick = ?)
        \\ORDER BY m.timestamp_ms DESC
        \\LIMIT ?;
        ,
    };

    const conn = server.db_pool.acquire();
    defer server.db_pool.release(conn);
    var rows = conn.rows(sql, .{ req.target, req.limit }) catch |err| {
        log.err("querying messages: {}: {s}", .{ err, conn.lastError() });
        return;
    };
    defer rows.deinit();

    collectChathistoryRows(&rows, server, req.target, req.conn, req.limit) catch |err| {
        log.err("querying messages: {}", .{err});
        return;
    };
}

fn collectChathistoryRows(
    rows: *sqlite.Rows,
    server: *Server,
    target: []const u8,
    conn: *Connection,
    limit: u16,
) Allocator.Error!void {
    var arena = std.heap.ArenaAllocator.init(server.gpa);
    var msgs = try std.ArrayListUnmanaged(ChatHistory.HistoryMessage).initCapacity(
        arena.allocator(),
        limit,
    );

    while (rows.next()) |row| {
        const msg: ChatHistory.HistoryMessage = .{
            .uuid = try arena.allocator().dupe(u8, row.text(0)),
            .timestamp = .{ .milliseconds = row.int(1) },
            .sender = try arena.allocator().dupe(u8, row.text(2)),
            .message = try arena.allocator().dupe(u8, row.text(3)),
        };
        msgs.appendAssumeCapacity(msg);
    }

    // Sort to ascending
    std.sort.insertion(
        ChatHistory.HistoryMessage,
        msgs.items,
        {},
        ChatHistory.HistoryMessage.lessThan,
    );

    const batch: ChatHistory.HistoryBatch = .{
        .conn = conn,
        .arena = arena,
        .items = msgs.items,
        .target = target,
    };

    server.wakeup_mutex.lock();
    defer server.wakeup_mutex.unlock();
    try server.wakeup_results.append(server.gpa, .{ .history_batch = batch });
    server.wakeup.notify() catch {};
}

pub fn setMarkRead(server: *Server, conn: *Connection, target: []const u8, ts: Timestamp) void {
    if (target.len == 0) return;
    const user = conn.user.?;
    const sql = switch (target[0]) {
        '#' =>
        \\INSERT INTO read_marker (user_id, target_id, target_kind, timestamp_ms)
        \\VALUES (
        \\    (SELECT id FROM users WHERE nick = ?),
        \\    (SELECT id FROM channels WHERE name = ?),
        \\    0,
        \\    ?
        \\)
        \\ON CONFLICT(user_id, target_id, target_kind) 
        \\DO UPDATE SET timestamp_ms = excluded.timestamp_ms;
        ,
        else =>
        \\INSERT INTO read_marker (user_id, target_id, target_kind, timestamp_ms)
        \\VALUES (
        \\    (SELECT id FROM users WHERE nick = ?),
        \\    (SELECT id FROM users WHERE nick = ?),
        \\    1,
        \\    ?
        \\)
        \\ON CONFLICT(user_id, target_id, target_kind) 
        \\DO UPDATE SET timestamp_ms = excluded.timestamp_ms;
    };

    const db_conn = server.db_pool.acquire();
    defer server.db_pool.release(db_conn);

    db_conn.exec(sql, .{ user.nick, target, ts.milliseconds }) catch |err| {
        log.err("setting mark read: {}: {s}", .{ err, db_conn.lastError() });
        return;
    };

    server.wakeup_mutex.lock();
    defer server.wakeup_mutex.unlock();
    server.wakeup_results.append(server.gpa, .{ .mark_read = .{
        .conn = conn,
        .target = target,
        .timestamp = ts,
    } }) catch |err| {
        log.err("setting mark read: {}", .{err});
        return;
    };
    server.wakeup.notify() catch {};
}

pub fn getMarkRead(server: *Server, conn: *Connection, target: []const u8) void {
    if (target.len == 0) return;
    const user = conn.user orelse return;
    const sql = switch (target[0]) {
        '#' =>
        \\SELECT timestamp_ms 
        \\FROM read_marker 
        \\WHERE user_id = (SELECT id FROM users WHERE nick = ?) 
        \\AND target_id = (SELECT id FROM channels WHERE name = ?) 
        \\AND target_kind = 0;
        ,
        else =>
        \\SELECT timestamp_ms 
        \\FROM read_marker 
        \\WHERE user_id = (SELECT id FROM users WHERE nick = ?) 
        \\AND target_id = (SELECT id FROM users WHERE nick = ?) 
        \\AND target_kind = 1;
    };

    const db_conn = server.db_pool.acquire();
    defer server.db_pool.release(db_conn);

    const maybe_row = db_conn.row(sql, .{ user.nick, target }) catch |err| {
        log.err("setting mark read: {}: {s}", .{ err, db_conn.lastError() });
        return;
    };

    server.wakeup_mutex.lock();
    defer server.wakeup_mutex.unlock();

    const timestamp: ?Timestamp = if (maybe_row) |row| blk: {
        defer row.deinit();
        break :blk .{ .milliseconds = row.int(0) };
    } else null;

    server.wakeup_results.append(server.gpa, .{
        .mark_read = .{
            .conn = conn,
            .target = target,
            .timestamp = timestamp,
        },
    }) catch |err| {
        log.err("setting mark read: {}", .{err});
        return;
    };
    server.wakeup.notify() catch {};
}
