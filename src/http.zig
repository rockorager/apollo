const std = @import("std");
const sqlite = @import("sqlite");
const httpz = @import("httpz");
const uuid = @import("uuid");
const xev = @import("xev");

const log = @import("log.zig");
const irc = @import("irc.zig");
const IrcServer = @import("Server.zig");
const sanitize = @import("sanitize.zig");
const Url = @import("Url.zig");

const public_html_index = @embedFile("public/html/index.html");
const public_html_channel = @embedFile("public/html/channel.html");
const public_html_channel_list = @embedFile("public/html/channel-list.html");
const public_css_reset = @embedFile("public/css/reset.css");
const public_css_style = @embedFile("public/css/style.css");
const public_js_htmx = @embedFile("public/js/htmx-2.0.4.js");
const public_js_htmx_sse = @embedFile("public/js/htmx-ext-sse.js");
const public_js_stick_to_bottom = @embedFile("public/js/stick-to-bottom.js");

pub const Server = struct {
    gpa: std.mem.Allocator,
    channels: *std.StringArrayHashMapUnmanaged(*irc.Channel),
    db_pool: *sqlite.Pool,
    csp_nonce: []const u8 = undefined,
    nonce: []u8 = undefined,
    irc_server: *IrcServer,

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
    stream: xev.TCP,
    channel: *irc.Channel,
    write_buf: std.ArrayListUnmanaged(u8),

    /// EventStream owns it's own completion. We do this because we can only ever write to the
    /// stream. We have full control over the lifetime of this completion. For other IRC
    /// connections, we could have an inflight write and receive a connection closed on our read
    /// call. This makes managing the lifetime difficult. For EventStream, we will only error out on
    /// the write - and then we can dispose of the connection
    write_c: xev.Completion,

    state: State = .{},

    /// We store some state in the EventStream because it's view is stateful. It's essentially an
    /// IRC client
    const State = struct {
        last_sender: ?*irc.User = null,
        last_timestamp: irc.Timestamp = .{ .milliseconds = 0 },
    };

    pub fn print(
        self: *EventStream,
        gpa: std.mem.Allocator,
        comptime format: []const u8,
        args: anytype,
    ) std.mem.Allocator.Error!void {
        return self.write_buf.writer(gpa).print(format, args);
    }

    pub fn printMessage(
        self: *EventStream,
        gpa: std.mem.Allocator,
        sender: *irc.User,
        msg: irc.Message,
    ) std.mem.Allocator.Error!void {
        const state = &self.state;
        const cmd = msg.command();

        const sender_sanitized: sanitize.Html = .{ .bytes = sender.nick };

        if (std.ascii.eqlIgnoreCase(cmd, "PRIVMSG")) {
            defer {
                // save the state
                self.state.last_sender = sender;
                self.state.last_timestamp = msg.timestamp;
            }

            // Parse the message
            var iter = msg.paramIterator();
            _ = iter.next(); // we can ignore the target
            const content = iter.next() orelse return;
            const san_content: sanitize.Html = .{ .bytes = content };

            // We don't reprint the sender if the last message this message are from the same
            // person. Unless enough time has elapsed (5 minutes)
            if (state.last_sender == sender and
                (state.last_timestamp.milliseconds + 5 * std.time.ms_per_min) >= msg.timestamp.milliseconds)
            {
                const fmt =
                    \\event: message
                    \\data: <div class="message"><p class="body">{s}</p></div>
                    \\
                    \\
                ;
                return self.print(gpa, fmt, .{san_content});
            }
            const fmt =
                \\event: message
                \\data: <div class="message"><p class="nick"><b>{s}</b></p><p class="body">{s}</p></div>
                \\
                \\
            ;
            return self.print(gpa, fmt, .{ sender_sanitized, san_content });
        }

        // TODO: other types of messages
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
        if (std.mem.eql(u8, "style-1.0.0.css", name)) {
            res.status = 200;
            res.body = public_css_style;
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
        if (std.mem.eql(u8, "stick-to-bottom-1.0.1.js", name)) {
            res.status = 200;
            res.body = public_js_stick_to_bottom;
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
    const channel_param = try res.arena.dupe(u8, req.param("channel").?);
    const channel = std.Uri.percentDecodeInPlace(channel_param);

    if (!ctx.channels.contains(channel)) {
        res.status = 404;
        res.body = "Channel does not exist";
        res.content_type = .TEXT;
        return;
    }

    const html_size = std.mem.replacementSize(u8, public_html_channel, "$nonce", ctx.nonce);
    const html_with_nonce = try res.arena.alloc(u8, html_size);
    _ = std.mem.replace(u8, public_html_channel, "$nonce", ctx.nonce, html_with_nonce);

    const sanitized_channel_name = sanitize.html(res.arena, channel) catch |err| {
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
    const body_without_messages_and_sse_endpoint = try res.arena.alloc(u8, header_replace_size);
    _ = std.mem.replace(
        u8,
        html_with_nonce,
        "$channel_name",
        sanitized_channel_name,
        body_without_messages_and_sse_endpoint,
    );

    const url_encoded_channel_name = Url.encode(res.arena, channel) catch |err| {
        log.err("[HTTP] failed to url encode channel name: {}: {s}", .{ err, channel });
        res.status = 500;
        res.body = "Internal Server Error";
        res.content_type = .TEXT;
        return;
    };
    const sanitized_url_encoded_channel_name = sanitize.html(
        res.arena,
        url_encoded_channel_name,
    ) catch |err| {
        log.err("[HTTP] failed to sanitize url encoded channel name: {}: {s}", .{ err, channel });
        res.status = 500;
        res.body = "Internal Server Error";
        res.content_type = .TEXT;
        return;
    };
    const sse_endpoint_replace_size = std.mem.replacementSize(
        u8,
        body_without_messages_and_sse_endpoint,
        "$encoded_channel_name",
        sanitized_url_encoded_channel_name,
    );
    const body_without_messages = try res.arena.alloc(u8, sse_endpoint_replace_size);
    _ = std.mem.replace(
        u8,
        body_without_messages_and_sse_endpoint,
        "$encoded_channel_name",
        sanitized_url_encoded_channel_name,
        body_without_messages,
    );

    // Nested SQL query because we first get the newest 100 messages, then want to order them from
    // oldest to newest. I'm sure there might be a way to optimize this query if it turns out to be
    // slow.
    const sql =
        \\SELECT * FROM (
        \\  SELECT
        \\    uuid,
        \\    timestamp_ms,
        \\    sender_nick,
        \\    message
        \\  FROM messages m
        \\  WHERE recipient_type = 0
        \\  AND recipient_id = (SELECT id FROM channels WHERE name = ?)
        \\  ORDER BY timestamp_ms DESC
        \\  LIMIT 100
        \\) ORDER BY timestamp_ms ASC;
    ;

    const conn = ctx.db_pool.acquire();
    defer ctx.db_pool.release(conn);
    var rows = conn.rows(sql, .{channel}) catch |err| {
        log.err("[HTTP] failed while querying messages: {}: {s}", .{ err, conn.lastError() });
        res.status = 500;
        res.body = "Internal Server Error";
        res.content_type = .TEXT;
        return;
    };
    defer rows.deinit();

    var messages: std.ArrayListUnmanaged(u8) = .empty;
    defer messages.deinit(res.arena);

    // Track some state while printing these messages
    var last_nick_buf: [256]u8 = undefined;
    var last_nick: []const u8 = "";
    var last_time: i64 = 0;

    while (rows.next()) |row| {
        const timestamp: irc.Timestamp = .{
            .milliseconds = row.int(1),
        };
        const message: irc.Message = .{
            .bytes = row.text(3),
            .timestamp = timestamp,
            .uuid = try uuid.urn.deserialize(row.text(0)),
        };
        const nick = row.text(2);

        defer {
            // Store state. We get up to 256 bytes for the nick, which should be good but either way
            // we truncate if needed
            const len = @min(last_nick_buf.len, nick.len);
            @memcpy(last_nick_buf[0..len], nick);
            last_nick = last_nick_buf[0..len];
            last_time = timestamp.milliseconds;
        }

        var iter = message.paramIterator();
        _ = iter.next();
        const content = iter.next() orelse continue;
        const san_content: sanitize.Html = .{ .bytes = content };

        // We don't reprint the sender if the last message this message are from the same
        // person. Unless enough time has elapsed (5 minutes)
        if (std.ascii.eqlIgnoreCase(last_nick, nick) and
            (last_time + 5 * std.time.ms_per_min) >= timestamp.milliseconds)
        {
            const fmt =
                \\<div class="message"><p class="body">{s}</p></div>
            ;
            try messages.writer(res.arena).print(fmt, .{san_content});
            continue;
        }
        const fmt =
            \\<div class="message"><p class="nick"><b>{s}</b></p><p class="body">{s}</p></div>
        ;

        const sender_sanitized: sanitize.Html = .{ .bytes = nick };
        try messages.writer(res.arena).print(fmt, .{ sender_sanitized, san_content });
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
        const sanitized_channel_name = sanitize.html(res.arena, name) catch |err| {
            log.err("[HTTP] failed to sanitize channel name: {}: {s}", .{ err, name });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };
        const url_encoded_channel_name = Url.encode(res.arena, name) catch |err| {
            log.err("[HTTP] failed to url encode channel name: {}: {s}", .{ err, name });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };
        const sanitized_url_encoded_channel_name = sanitize.html(
            res.arena,
            url_encoded_channel_name,
        ) catch |err| {
            log.err("[HTTP] failed to sanitize url encoded channel name: {}: {s}", .{ err, name });
            res.status = 500;
            res.body = "Internal Server Error";
            res.content_type = .TEXT;
            return;
        };

        const html_item = try std.fmt.allocPrint(
            res.arena,
            "<li><a href=\"/channels/{s}\">{s}</a></li>",
            .{ sanitized_url_encoded_channel_name, sanitized_channel_name },
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

/// We steal the fd from httpz.
pub fn startChannelEventStream(ctx: *Server, req: *httpz.Request, res: *httpz.Response) !void {
    const channel_param = try res.arena.dupe(u8, req.param("channel").?);
    const channel = std.Uri.percentDecodeInPlace(channel_param);

    log.err("[HTTP] Starting event stream for {s}", .{channel});

    if (ctx.channels.get(channel)) |c| {
        try prepareResponseForEventStream(res);

        // Create the EventStream
        const es = try ctx.gpa.create(EventStream);
        es.* = .{
            .stream = .{ .fd = res.conn.stream.handle },
            .channel = c,
            .write_buf = .empty,
            .write_c = .{},
        };
        // add the event stream to the server. On wakeup, the server will add the stream to it's
        // list, and the channels list
        ctx.irc_server.wakeup_queue.push(.{ .event_stream = es });
        return;
    }

    res.status = 404;
    res.body = "No such channel";
    res.content_type = .TEXT;
}

/// Vendored from httpz. This was part of self.startEventStream. We copy the part where it writes
/// headers, but stop short of spawning a thread
fn prepareResponseForEventStream(self: *httpz.Response) !void {
    self.content_type = .EVENTS;
    self.headers.add("Cache-Control", "no-cache");
    self.headers.add("Connection", "keep-alive");

    const conn = self.conn;
    const stream = conn.stream;

    const header_buf = try prepareHeader(self);
    try stream.writeAll(header_buf);

    self.disown();
}

/// Vendored from httpz. Not a public function
fn prepareHeader(self: *httpz.Response) ![]const u8 {
    const headers = &self.headers;
    const names = headers.keys[0..headers.len];
    const values = headers.values[0..headers.len];

    // 220 gives us enough space to fit:
    // 1 - The status/first line
    // 2 - The Content-Length header or the Transfer-Encoding header.
    // 3 - Our longest supported built-in content type (for a custom content
    //     type, it would have been set via the res.header(...) call, so would
    //     be included in `len)
    var len: usize = 220;
    for (names, values) |name, value| {
        // +4 for the colon, space and trailer
        len += name.len + value.len + 4;
    }

    var buf = try self.arena.alloc(u8, len);

    var pos: usize = "HTTP/1.1 XXX \r\n".len;
    switch (self.status) {
        inline 100...103, 200...208, 226, 300...308, 400...418, 421...426, 428, 429, 431, 451, 500...511 => |status| @memcpy(buf[0..15], std.fmt.comptimePrint("HTTP/1.1 {d} \r\n", .{status})),
        else => |s| {
            const HTTP1_1 = "HTTP/1.1 ";
            const l = HTTP1_1.len;
            @memcpy(buf[0..l], HTTP1_1);
            pos = l + writeInt(buf[l..], @as(u32, s));
            @memcpy(buf[pos..][0..3], " \r\n");
            pos += 3;
        },
    }

    if (self.content_type) |ct| {
        const content_type: ?[]const u8 = switch (ct) {
            .BINARY => "Content-Type: application/octet-stream\r\n",
            .CSS => "Content-Type: text/css; charset=UTF-8\r\n",
            .CSV => "Content-Type: text/csv; charset=UTF-8\r\n",
            .EOT => "Content-Type: application/vnd.ms-fontobject\r\n",
            .EVENTS => "Content-Type: text/event-stream; charset=UTF-8\r\n",
            .GIF => "Content-Type: image/gif\r\n",
            .GZ => "Content-Type: application/gzip\r\n",
            .HTML => "Content-Type: text/html; charset=UTF-8\r\n",
            .ICO => "Content-Type: image/vnd.microsoft.icon\r\n",
            .JPG => "Content-Type: image/jpeg\r\n",
            .JS => "Content-Type: text/javascript; charset=UTF-8\r\n",
            .JSON => "Content-Type: application/json\r\n",
            .OTF => "Content-Type: font/otf\r\n",
            .PDF => "Content-Type: application/pdf\r\n",
            .PNG => "Content-Type: image/png\r\n",
            .SVG => "Content-Type: image/svg+xml\r\n",
            .TAR => "Content-Type: application/x-tar\r\n",
            .TEXT => "Content-Type: text/plain; charset=UTF-8\r\n",
            .TTF => "Content-Type: font/ttf\r\n",
            .WASM => "Content-Type: application/wasm\r\n",
            .WEBP => "Content-Type: image/webp\r\n",
            .WOFF => "Content-Type: font/woff\r\n",
            .WOFF2 => "Content-Type: font/woff2\r\n",
            .XML => "Content-Type: text/xml; charset=UTF-8\r\n",
            .UNKNOWN => null,
        };
        if (content_type) |value| {
            const end = pos + value.len;
            @memcpy(buf[pos..end], value);
            pos = end;
        }
    }

    if (self.keepalive == false) {
        const CLOSE_HEADER = "Connection: Close\r\n";
        const end = pos + CLOSE_HEADER.len;
        @memcpy(buf[pos..end], CLOSE_HEADER);
        pos = end;
    }

    for (names, values) |name, value| {
        {
            // write the name
            const end = pos + name.len;
            @memcpy(buf[pos..end], name);
            pos = end;
            buf[pos] = ':';
            buf[pos + 1] = ' ';
            pos += 2;
        }

        {
            // write the value + trailer
            const end = pos + value.len;
            @memcpy(buf[pos..end], value);
            pos = end;
            buf[pos] = '\r';
            buf[pos + 1] = '\n';
            pos += 2;
        }
    }

    const buffer_pos = self.buffer.pos;
    const body_len = if (buffer_pos > 0) buffer_pos else self.body.len;
    if (body_len > 0) {
        const CONTENT_LENGTH = "Content-Length: ";
        var end = pos + CONTENT_LENGTH.len;
        @memcpy(buf[pos..end], CONTENT_LENGTH);
        pos = end;

        pos += writeInt(buf[pos..], @intCast(body_len));
        end = pos + 4;
        @memcpy(buf[pos..end], "\r\n\r\n");
        return buf[0..end];
    }

    const fin = blk: {
        // For chunked, we end with a single \r\n because the call to res.chunk()
        // prepends a \r\n. Hence,for the first chunk, we'll have the correct \r\n\r\n
        if (self.chunked) break :blk "Transfer-Encoding: chunked\r\n";
        if (self.content_type == .EVENTS) break :blk "\r\n";
        break :blk "Content-Length: 0\r\n\r\n";
    };

    const end = pos + fin.len;
    @memcpy(buf[pos..end], fin);
    return buf[0..end];
}

/// Vendored from httpz. Not a public function
fn writeInt(into: []u8, value: u32) usize {
    const small_strings = "00010203040506070809" ++
        "10111213141516171819" ++
        "20212223242526272829" ++
        "30313233343536373839" ++
        "40414243444546474849" ++
        "50515253545556575859" ++
        "60616263646566676869" ++
        "70717273747576777879" ++
        "80818283848586878889" ++
        "90919293949596979899";

    var v = value;
    var i: usize = 10;
    var buf: [10]u8 = undefined;
    while (v >= 100) {
        const digits = v % 100 * 2;
        v /= 100;
        i -= 2;
        buf[i + 1] = small_strings[digits + 1];
        buf[i] = small_strings[digits];
    }

    {
        const digits = v * 2;
        i -= 1;
        buf[i] = small_strings[digits + 1];
        if (v >= 10) {
            i -= 1;
            buf[i] = small_strings[digits];
        }
    }

    const l = buf.len - i;
    @memcpy(into[0..l], buf[i..]);
    return l;
}
