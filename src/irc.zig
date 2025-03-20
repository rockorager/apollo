const std = @import("std");
const uuid = @import("uuid");
const zeit = @import("zeit");

const db = @import("db.zig");
const log = @import("log.zig");

const Allocator = std.mem.Allocator;
const Connection = Server.Connection;
const Queue = @import("queue.zig").Queue;
const Sanitize = @import("sanitize.zig").Sanitize;
const Server = @import("Server.zig");

const assert = std.debug.assert;

// Global user modes
const UserMode = packed struct {
    operator: bool = false, // +o, global mod

    const none: UserMode = .{};
};

// Channel modes. We can add "private" channels for example
const ChannelMode = packed struct {};

pub const ChannelPrivileges = packed struct {
    operator: bool = false, // +o, channel mod

    const none: ChannelPrivileges = .{};
};

pub const SaslMechanism = enum {
    plain,
};

const Sasl = union(SaslMechanism) {
    plain: struct {
        username: []const u8,
        password: []const u8,
    },
};

pub const Capability = enum {
    @"away-notify",
    batch,
    @"draft/chathistory",
    @"draft/no-implicit-names",
    @"draft/read-marker",
    @"echo-message",
    @"message-tags",
    sasl,
    @"server-time",
};

pub const ChatHistory = struct {
    pub const TargetsRequest = struct {
        conn: *Connection,
        from: Timestamp,
        to: Timestamp,
        limit: u16,
    };

    pub const AfterRequest = struct {
        conn: *Connection,
        target: []const u8,
        after_ms: Timestamp,
        limit: u16,
    };

    pub const BeforeRequest = struct {
        conn: *Connection,
        target: []const u8,
        before_ms: Timestamp,
        limit: u16,
    };

    pub const LatestRequest = struct {
        conn: *Connection,
        target: []const u8,
        limit: u16,
    };

    pub const HistoryMessage = struct {
        uuid: []const u8,
        timestamp: Timestamp,
        sender: []const u8,
        message: []const u8,

        pub fn lessThan(_: void, lhs: HistoryMessage, rhs: HistoryMessage) bool {
            return lhs.timestamp.milliseconds < rhs.timestamp.milliseconds;
        }
    };

    pub const HistoryBatch = struct {
        arena: std.heap.ArenaAllocator,
        conn: *Connection,
        items: []HistoryMessage,
        target: []const u8,
    };
};

pub const Message = struct {
    bytes: []const u8,
    timestamp: Timestamp,
    uuid: uuid.Uuid,

    pub fn init(bytes: []const u8) Message {
        return .{
            .bytes = bytes,
            .timestamp = .init(),
            .uuid = uuid.v4.new(),
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
        if (msg.bytes.len == 0) return "";
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

pub const MessageIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    /// Returns the next message. Trailing \r\n is is removed
    pub fn next(self: *MessageIterator) ?[]const u8 {
        if (self.index >= self.bytes.len) return null;
        const n = std.mem.indexOfScalarPos(u8, self.bytes, self.index, '\n') orelse return null;
        defer self.index = n + 1;
        return std.mem.trimRight(u8, self.bytes[self.index..n], "\r\n");
    }

    pub fn bytesRead(self: MessageIterator) usize {
        return self.index;
    }
};

pub const ClientMessage = enum {
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
    TAGMSG,

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

    // Extensions
    CHATHISTORY,
    MARKREAD,

    pub fn fromString(str: []const u8) ?ClientMessage {
        inline for (@typeInfo(ClientMessage).@"enum".fields) |enumField| {
            if (std.ascii.eqlIgnoreCase(str, enumField.name)) {
                return @field(ClientMessage, enumField.name);
            }
        }
        return null;
    }
};

pub const User = struct {
    nick: []const u8,
    username: []const u8,
    real: []const u8,
    avatar_url: []const u8,
    modes: UserMode,

    away: bool,

    connections: std.ArrayListUnmanaged(*Connection),
    channels: std.ArrayListUnmanaged(*Channel),

    pub fn init() User {
        return .{
            .nick = "",
            .username = "",
            .real = "",
            .avatar_url = "",
            .connections = .empty,
            .channels = .empty,
            .away = false,
            .modes = .none,
        };
    }

    pub fn deinit(self: *User, gpa: Allocator) void {
        gpa.free(self.nick);
        gpa.free(self.username);
        gpa.free(self.real);
        gpa.free(self.avatar_url);
        self.connections.deinit(gpa);
        self.channels.deinit(gpa);
    }

    pub fn isAway(self: *User) bool {
        return self.away or self.connections.items.len == 0;
    }
};

pub const Channel = struct {
    name: []const u8,
    topic: []const u8,
    members: std.ArrayListUnmanaged(Member),
    event_streams: std.ArrayListUnmanaged(*Queue(Server.EventStreamMessage, 1024)),

    const Member = struct {
        user: *User,
        privileges: ChannelPrivileges,
    };

    pub fn init(name: []const u8, topic: []const u8) Channel {
        return .{
            .name = name,
            .topic = topic,
            .members = .empty,
            .event_streams = .empty,
        };
    }

    pub fn deinit(self: *Channel, gpa: Allocator) void {
        gpa.free(self.name);
        gpa.free(self.topic);
        self.members.deinit(gpa);
        self.event_streams.deinit(gpa);
    }

    pub fn addUser(self: *Channel, server: *Server, user: *User, new_conn: *Connection) Allocator.Error!void {
        log.debug("user={s} joining {s}", .{ user.nick, self.name });
        // First, we see if the User is already in this channel
        for (self.members.items) |u| {
            if (u.user == user) {
                // The user is already here. We just need to send the new connection a JOIN and NAMES
                try new_conn.print(server.gpa, ":{s} JOIN {s}\r\n", .{ user.nick, self.name });

                // Next we see if this user needs to have an implicit names sent
                if (new_conn.caps.@"draft/no-implicit-names") return;

                // Send implicit NAMES
                return self.names(server, new_conn);
            }
        }

        // Next we add them
        try self.members.append(server.gpa, .{ .user = user, .privileges = .none });
        // Add the channel to the users list of channels
        try user.channels.append(server.gpa, self);

        // Next we tell everyone about this user joining
        for (self.members.items) |u| {
            for (u.user.connections.items) |conn| {
                try conn.print(server.gpa, ":{s} JOIN {s}\r\n", .{ user.nick, self.name });
                try server.queueWrite(conn.client, conn);
            }
        }

        // This user just joined the channel, so we need to handle implicit names for each
        // connection so all of the users connections receive the same information
        for (user.connections.items) |conn| {
            // See if this connection needs to have an implicit names sent
            if (conn.caps.@"draft/no-implicit-names") continue;

            // Send implicit NAMES
            try self.names(server, conn);
        }

        try server.thread_pool.spawn(db.createChannelMembership, .{ server, self.name, user.nick });
    }

    /// Notifies anyone in the channel with away-notify that the user is away
    pub fn notifyAway(self: *Channel, server: *Server, user: *User) Allocator.Error!void {
        for (self.members.items) |u| {
            for (u.user.connections.items) |c| {
                if (!c.caps.@"away-notify") continue;
                try c.print(
                    server.gpa,
                    ":{s} AWAY :{s} is away\r\n",
                    .{ user.nick, user.nick },
                );
                try server.queueWrite(c.client, c);
            }
        }
    }

    /// Notifies anyone in the channel with away-notify that the user is back
    pub fn notifyBack(self: *Channel, server: *Server, user: *User) Allocator.Error!void {
        for (self.members.items) |m| {
            const u = m.user;
            for (u.connections.items) |c| {
                if (!c.caps.@"away-notify") continue;
                try c.print(
                    server.gpa,
                    ":{s} AWAY\r\n",
                    .{user.nick},
                );
                try server.queueWrite(c.client, c);
            }
        }
    }

    // Removes the user from the channel. Sends a PART to all members
    pub fn removeUser(self: *Channel, server: *Server, user: *User) Allocator.Error!void {
        for (self.members.items, 0..) |m, i| {
            const u = m.user;
            if (u == user) {
                _ = self.members.swapRemove(i);
                break;
            }
        } else {
            for (user.connections.items) |conn| {
                try conn.print(
                    server.gpa,
                    ":{s} 442 {s} {s} :You're not in that channel\r\n",
                    .{ server.hostname, conn.nickname(), self.name },
                );
            }
            return;
        }

        // Spawn a thread to remove the membership from the db
        try server.thread_pool.spawn(db.removeChannelMembership, .{ server, self.name, user.nick });

        // Remove the channel from the user struct
        for (user.channels.items, 0..) |uc, i| {
            if (uc == self) {
                _ = user.channels.swapRemove(i);
            }
        }

        // Send a PART message to all members
        for (self.members.items) |m| {
            const u = m.user;
            for (u.connections.items) |c| {
                try c.print(
                    server.gpa,
                    ":{s} PART {s} :User left\r\n",
                    .{ user.nick, self.name },
                );
                try server.queueWrite(c.client, c);
            }
        }

        // Send a PART to the user who left too
        for (user.connections.items) |c| {
            try c.print(
                server.gpa,
                ":{s} PART {s} :User left\r\n",
                .{ user.nick, self.name },
            );
        }
    }

    pub fn names(self: *Channel, server: *Server, conn: *Connection) Allocator.Error!void {
        for (self.members.items) |us| {
            try conn.print(
                server.gpa,
                ":{s} 353 {s} = {s} :{s}\r\n",
                .{ server.hostname, conn.nickname(), self.name, us.user.nick },
            );
        }
        try conn.print(
            server.gpa,
            ":{s} 366 {s} {s} :End of names list\r\n",
            .{ server.hostname, conn.nickname(), self.name },
        );
        try server.queueWrite(conn.client, conn);
    }

    pub fn who(self: *Channel, server: *Server, conn: *Connection, msg: Message) Allocator.Error!void {
        const client: []const u8 = if (conn.user) |user| user.nick else "*";
        var iter = msg.paramIterator();
        _ = iter.next(); // We already have the first param (the target)

        // Get the WHOX args, if there aren't any we can use an empty string for the same logic
        const args = iter.next() orelse "";
        const token = iter.next();

        if (args.len == 0) {
            for (self.members.items) |member| {
                const user = member.user;
                var flag_buf: [3]u8 = undefined;
                var flag_len: usize = 1;
                flag_buf[0] = if (user.isAway()) 'G' else 'H';
                if (user.modes.operator) {
                    flag_buf[flag_len] = '*';
                    flag_len += 1;
                }
                if (member.privileges.operator) {
                    flag_buf[flag_len] = '@';
                    flag_len += 1;
                }

                const flags = flag_buf[0..flag_len];
                try conn.print(
                    server.gpa,
                    ":{s} 352 {s} {s} {s} {s} {s} {s} {s} :0 {s}\r\n",
                    .{
                        server.hostname,
                        client,
                        self.name,
                        user.username,
                        server.hostname,
                        server.hostname,
                        user.nick,
                        flags,
                        user.real,
                    },
                );
            }
        } else {
            for (self.members.items) |member| {
                const user = member.user;
                try conn.print(
                    server.gpa,
                    ":{s} 354 {s}",
                    .{ server.hostname, client },
                );

                // Find the index of the standard field indicator
                const std_idx = std.mem.indexOfScalar(u8, args, '%') orelse args.len;
                // TODO: any nonstandard fields

                // Handle standard fields, in order. The order is tcuihsnfdlaor
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 't')) |_| {
                    if (token) |t| try conn.print(server.gpa, " {s}", .{t});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'c')) |_| {
                    try conn.print(server.gpa, " {s}", .{self.name});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'u')) |_| {
                    try conn.print(server.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'i')) |_| {
                    try conn.print(server.gpa, " {s}", .{"127.0.0.1"});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'h')) |_| {
                    try conn.print(server.gpa, " {s}", .{server.hostname});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 's')) |_| {
                    try conn.print(server.gpa, " {s}", .{server.hostname});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'n')) |_| {
                    try conn.print(server.gpa, " {s}", .{user.nick});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'f')) |_| {
                    const flag = if (user.isAway()) "G" else "H";
                    try conn.print(server.gpa, " {s}", .{flag});
                    if (user.modes.operator) {
                        try conn.print(server.gpa, "{s}", .{"*"});
                    }
                    if (member.privileges.operator) {
                        try conn.print(server.gpa, "{s}", .{"@"});
                    }
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'd')) |_| {
                    try conn.write(server.gpa, " 0");
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'l')) |_| {
                    try conn.write(server.gpa, " 0");
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'a')) |_| {
                    try conn.print(server.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'o')) |_| {
                    // TODO: chan op level
                    try conn.print(server.gpa, " {s}", .{user.username});
                }
                if (std.mem.indexOfScalarPos(u8, args, std_idx, 'r')) |_| {
                    try conn.print(server.gpa, " :{s}", .{user.real});
                }
                try conn.write(server.gpa, "\r\n");
            }
        }
        try conn.print(
            server.gpa,
            ":{s} 315 {s} {s} :End of WHO list\r\n",
            .{ server.hostname, client, self.name },
        );
        try server.queueWrite(conn.client, conn);
    }

    pub fn getPrivileges(self: *Channel, user: *User) ChannelPrivileges {
        for (self.members.items) |m| {
            if (m.user == user) {
                return m.privileges;
            }
        }
        return .none;
    }

    /// Updates the privileges of user. Saves to the db
    pub fn storePrivileges(self: *Channel, server: *Server, user: *User, privs: ChannelPrivileges) !void {
        for (self.members.items) |*m| {
            if (m.user == user) {
                m.privileges = privs;
                // Save to the db
                try server.thread_pool.spawn(
                    db.updatePrivileges,
                    .{ server, user, privs, self.name },
                );
                return;
            }
        }
    }
};

pub const Timestamp = struct {
    milliseconds: i64,

    pub fn init() Timestamp {
        return .{ .milliseconds = std.time.milliTimestamp() };
    }

    pub fn format(
        self: Timestamp,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = fmt;
        const instant = zeit.instant(
            .{ .source = .{ .unix_nano = self.milliseconds * std.time.ns_per_ms } },
        ) catch unreachable;
        const time = instant.time();
        try writer.print(
            "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z",
            .{
                time.year,
                @intFromEnum(time.month),
                time.day,
                time.hour,
                time.minute,
                time.second,
                time.millisecond,
            },
        );
    }
};
