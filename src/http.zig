const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");
const uuid = @import("uuid");

const log = @import("log.zig");
const irc = @import("irc.zig");
const Sanitize = @import("sanitize.zig");
const Queue = @import("queue.zig").Queue;
const ThreadSafe = @import("ThreadSafe.zig");

const public_html_index = @embedFile("public/html/index.html");
const public_html_channel = @embedFile("public/html/channel.html");
const public_html_channel_list = @embedFile("public/html/channel-list.html");
const public_css_reset = @embedFile("public/css/reset.css");
const public_js_htmx = @embedFile("public/js/htmx-2.0.4.js");
const public_js_htmx_sse = @embedFile("public/js/htmx-ext-sse.js");

pub const Server = struct {
    gpa: std.mem.Allocator,
    channels: *std.StringArrayHashMapUnmanaged(*irc.Channel),
    db_pool: *sqlite.Pool,
    csp_nonce: []const u8 = undefined,
    nonce: []u8 = undefined,

    pub fn hasChannel(self: *const Server, channel: []const u8) bool {
        for (self.channels.keys()) |c| {
            if (std.mem.eql(u8, c[1..], channel)) return true;
        }
        return false;
    }

    /// Generates a 256-bit, base64-encoded nonce and adds a Content-Security-Policy header.
    fn addContentSecurityPolicy(
        self: *Server,
        action: httpz.Action(*Server),
        req: *httpz.Request,
        res: *httpz.Response,
    ) !void {
        _ = action;
        _ = req;

        // TODO: Use static buffers, we know the lenghts of everything here, so we should be
        //       able to skip all the allocations here.

        const nonce_buf = try res.arena.alloc(u8, 32);

        std.crypto.random.bytes(nonce_buf);
        const encoder: std.base64.Base64Encoder = .init(
            std.base64.standard.alphabet_chars,
            std.base64.standard.pad_char,
        );

        const b64_len = encoder.calcSize(nonce_buf.len);
        self.nonce = try res.arena.alloc(u8, b64_len);
        _ = encoder.encode(self.nonce, nonce_buf);

        const header = try std.fmt.allocPrint(
            res.arena,
            "script-src 'nonce-{s}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';",
            .{self.nonce},
        );

        res.header("Content-Security-Policy", header);
    }

    pub fn dispatch(
        self: *Server,
        action: httpz.Action(*Server),
        req: *httpz.Request,
        res: *httpz.Response,
    ) !void {
        try self.addContentSecurityPolicy(action, req, res);
        try action(self, req, res);
    }
};

pub const EventStream = struct {
    irc_channel: *irc.Channel,
    message_queue: *Queue(EventStream.Message, 1024),
    gpa: std.mem.Allocator,

    pub const Message = struct {
        msg: []const u8,
        user: *const irc.User,
        // time?
    };

    fn handle(self: EventStream, stream: std.net.Stream) void {
        var arena_allocator: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_allocator.deinit();
        const arena = arena_allocator.allocator();

        log.info("[HTTP] Opened event stream", .{});

        while (true) {
            const msg = self.message_queue.pop();
            const writer = stream.writer();

            const sanitized_nick = Sanitize.html(arena, msg.user.nick) catch |err| {
                log.err("[HTTP] failed to sanitize nick: {}: {s}", .{ err, msg.user.nick });
                continue;
            };
            const sanitized_msg = Sanitize.html(arena, msg.msg) catch |err| {
                log.err("[HTTP] failed to sanitize message: {}: {s}", .{ err, msg.msg });
                continue;
            };

            writer.print(
                "event: message\ndata: <div><p><b>{s}:</b></p><p>{s}</p>\n\n",
                .{ sanitized_nick, sanitized_msg },
            ) catch break;

            _ = arena_allocator.reset(.free_all);
        }

        for (0..self.irc_channel.web_event_queues.data.items.len) |i| {
            const es = self.irc_channel.web_event_queues.data.items[i];
            if (es == self.message_queue) {
                _ = self.irc_channel.web_event_queues.swapRemove(i);
                log.info("[HTTP] Closed event stream", .{});
                return;
            }
        }
    }
};

pub fn getIndex(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req;

    const html_size = std.mem.replacementSize(u8, public_html_index, "$nonce", ctx.nonce);
    const html_with_nonce = try res.arena.alloc(u8, html_size);
    _ = std.mem.replace(u8, public_html_index, "$nonce", ctx.nonce, html_with_nonce);

    res.status = 200;
    res.body = html_with_nonce;
    res.content_type = .HTML;
}

pub fn getAsset(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    _ = ctx;
    const asset_type = req.param("type").?;
    const name = req.param("name").?;

    if (std.mem.eql(u8, asset_type, "css")) {
        if (std.mem.eql(u8, "reset.css", name)) {
            res.status = 200;
            res.body = public_css_reset;
            res.content_type = .CSS;
            // Cache indefinitely in the browser.
            res.header("Cache-Control", "max-age=31536000, immutable");
            return;
        }
    }

    if (std.mem.eql(u8, asset_type, "js")) {
        if (std.mem.eql(u8, "htmx-2.0.4.js", name)) {
            res.status = 200;
            res.body = public_js_htmx;
            res.content_type = .JS;
            // Cache indefinitely in the browser.
            res.header("Cache-Control", "max-age=31536000, immutable");
            return;
        }
        if (std.mem.eql(u8, "htmx-ext-sse.js", name)) {
            res.status = 200;
            res.body = public_js_htmx_sse;
            res.content_type = .JS;
            // Cache indefinitely in the browser.
            res.header("Cache-Control", "max-age=31536000, immutable");
            return;
        }
    }

    res.status = 404;
    res.body = "Not found";
    res.content_type = .TEXT;
}

pub fn getChannel(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const channel = req.param("channel").?;

    if (!ctx.hasChannel(channel)) {
        res.status = 404;
        res.body = "Channel does not exist";
        res.content_type = .TEXT;
        return;
    }

    const html_size = std.mem.replacementSize(u8, public_html_channel, "$nonce", ctx.nonce);
    const html_with_nonce = try res.arena.alloc(u8, html_size);
    _ = std.mem.replace(u8, public_html_channel, "$nonce", ctx.nonce, html_with_nonce);

    const sanitized_channel_name = Sanitize.html(res.arena, channel) catch |err| {
        log.err("[HTTP] failed to sanitize channel name: {}: {s}", .{ err, channel });
        res.status = 500;
        res.body = "Internal Server Error";
        res.content_type = .TEXT;
        return;
    };

    const header_replace_size = std.mem.replacementSize(
        u8,
        html_with_nonce,
        "$channel_name",
        sanitized_channel_name,
    );
    const body_without_messages = try res.arena.alloc(u8, header_replace_size);
    _ = std.mem.replace(
        u8,
        html_with_nonce,
        "$channel_name",
        sanitized_channel_name,
        body_without_messages,
    );

    const channel_with_hash = try res.arena.alloc(u8, channel.len + 1);
    channel_with_hash[0] = '#';
    @memcpy(channel_with_hash[1..], channel);

    const sql =
        \\SELECT
        \\  uuid,
        \\  timestamp_ms,
        \\  sender_nick,
        \\  message
        \\FROM messages m
        \\WHERE recipient_type = 0
        \\AND recipient_id = (SELECT id FROM channels WHERE name = ?)
        \\ORDER BY timestamp_ms ASC
        \\LIMIT 100;
    ;

    const conn = ctx.db_pool.acquire();
    defer ctx.db_pool.release(conn);
    var rows = conn.rows(sql, .{channel_with_hash}) catch |err| {
        log.err("[HTTP] failed while querying messages: {}: {s}", .{ err, conn.lastError() });
        res.status = 500;
        res.body = "Internal Server Error";
        res.content_type = .TEXT;
        return;
    };
    defer rows.deinit();

    var messages: std.ArrayListUnmanaged(u8) = .empty;
    defer messages.deinit(res.arena);

    while (rows.next()) |row| {
        const timestamp: irc.Timestamp = .{
            .milliseconds = row.int(1),
        };
        const message: irc.Message = .{
            .bytes = row.text(3),
            .timestamp = timestamp,
            .uuid = try uuid.urn.deserialize(row.text(0)),
        };

        var iter = message.paramIterator();
        _ = iter.next();
        const text = iter.next().?;
        const sanitized_text = Sanitize.html(res.arena, text) catch |err| {
            log.err("[HTTP] failed to sanitize nick: {}: {s}", .{ err, text });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };

        const nick = row.text(2);
        const sanitized_nick = Sanitize.html(res.arena, nick) catch |err| {
            log.err("[HTTP] failed to sanitize message: {}: {s}", .{ err, nick });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };

        try messages.appendSlice(res.arena, "<div><p><b>");
        try messages.appendSlice(res.arena, sanitized_nick);
        try messages.appendSlice(res.arena, "</b><p>");
        try messages.appendSlice(res.arena, sanitized_text);
        try messages.appendSlice(res.arena, "</p></div>");
    }

    const body_replace_size = std.mem.replacementSize(
        u8,
        body_without_messages,
        "$messages",
        messages.items,
    );
    const body = try res.arena.alloc(u8, body_replace_size);
    _ = std.mem.replace(u8, body_without_messages, "$messages", messages.items, body);

    res.status = 200;
    res.body = body;
    res.content_type = .HTML;
}

pub fn getChannels(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    _ = req;

    const html_size = std.mem.replacementSize(u8, public_html_channel_list, "$nonce", ctx.nonce);
    const html_with_nonce = try res.arena.alloc(u8, html_size);
    _ = std.mem.replace(u8, public_html_channel_list, "$nonce", ctx.nonce, html_with_nonce);

    var list: std.ArrayListUnmanaged(u8) = .empty;
    defer list.deinit(res.arena);

    for (ctx.channels.keys()) |name| {
        const sanitized_channel_name = Sanitize.html(res.arena, name) catch |err| {
            log.err("[HTTP] failed to sanitize channel name: {}: {s}", .{ err, name });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };
        const html_item = try std.fmt.allocPrint(
            res.arena,
            "<li><a href=\"/channels/{s}\">{s}</a></li>",
            .{ sanitized_channel_name[1..], sanitized_channel_name },
        );
        try list.appendSlice(res.arena, html_item);
    }

    const replace_size = std.mem.replacementSize(u8, html_with_nonce, "$channel_list", list.items);
    const body = try res.arena.alloc(u8, replace_size);
    _ = std.mem.replace(u8, html_with_nonce, "$channel_list", list.items, body);

    res.status = 200;
    res.body = body;
    res.content_type = .HTML;
}

pub fn goToChannel(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const formData = try req.formData();
    const channel = formData.get("channel-name");

    if (channel) |ch| {
        if (ctx.hasChannel(ch)) {
            const url = try std.fmt.allocPrint(res.arena, "/channels/{s}", .{ch});
            res.status = 302;
            res.header("Location", url);
            return;
        }
    }

    res.status = 404;
}

pub fn startChannelEventStream(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const channel = req.param("channel").?;
    const channelWithHash = try std.fmt.allocPrint(res.arena, "#{s}", .{channel});

    if (ctx.channels.get(channelWithHash)) |c| {
        const queue = try ctx.gpa.create(Queue(EventStream.Message, 1024));
        queue.* = .{};
        try c.web_event_queues.append(ctx.gpa, queue);
        try res.startEventStream(EventStream{ .irc_channel = c, .message_queue = queue, .gpa = ctx.gpa }, EventStream.handle);
        return;
    }

    res.status = 404;
    res.body = "No such channel";
    res.content_type = .TEXT;
}
