const std = @import("std");

/// Html is a type that, when used with zig formatting strings, will write an HTML sanitized version
/// of bytes to the writer
pub const Html = struct {
    bytes: []const u8,

    pub fn format(
        self: Html,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = fmt;
        // User a buffered writer since we'll be doing a lot of single byte writes
        var bw = std.io.bufferedWriter(writer);
        for (self.bytes) |b| {
            switch (b) {
                '<' => try bw.writer().writeAll("&lt;"),
                '>' => try bw.writer().writeAll("&gt;"),
                '&' => try bw.writer().writeAll("&amp;"),
                '"' => try bw.writer().writeAll("&quot;"),
                '\'' => try bw.writer().writeAll("&#x27;"),
                else => try bw.writer().writeByte(b),
            }
        }
        try bw.flush();
    }
};

/// Replaces several charachters with their corresponding html entities to sanitize the HTML passed
/// in. Returns an allocated slice that the caller must free.
pub fn html(allocator: std.mem.Allocator, html_text: []const u8) anyerror![]const u8 {
    const extra_length: usize = length: {
        var extra_length: usize = 0;
        extra_length += 3 * std.mem.count(u8, html_text, "<");
        extra_length += 3 * std.mem.count(u8, html_text, ">");
        extra_length += 4 * std.mem.count(u8, html_text, "&");
        extra_length += 5 * std.mem.count(u8, html_text, "\"");
        extra_length += 5 * std.mem.count(u8, html_text, "'");
        break :length extra_length;
    };

    const sanitized = try allocator.alloc(u8, html_text.len + extra_length);

    var sanitized_index: usize = 0;
    for (0..html_text.len) |i| {
        std.debug.assert(sanitized_index < sanitized.len);
        const c = html_text[i];

        if (c == '<') {
            const end = sanitized_index + 4;
            @memcpy(sanitized[sanitized_index..end], "&lt;");
            sanitized_index = end;
            continue;
        }
        if (c == '>') {
            const end = sanitized_index + 4;
            @memcpy(sanitized[sanitized_index..end], "&gt;");
            sanitized_index = end;
            continue;
        }
        if (c == '&') {
            const end = sanitized_index + 5;
            @memcpy(sanitized[sanitized_index..end], "&amp;");
            sanitized_index = end;
            continue;
        }
        if (c == '\"') {
            const end = sanitized_index + 6;
            @memcpy(sanitized[sanitized_index..end], "&quot;");
            sanitized_index = end;
            continue;
        }
        if (c == '\'') {
            const end = sanitized_index + 6;
            @memcpy(sanitized[sanitized_index..end], "&#x27;");
            sanitized_index = end;
            continue;
        }

        sanitized[sanitized_index] = c;

        sanitized_index += 1;
    }

    return sanitized;
}

test Html {
    const ta = std.testing.allocator;

    const malicious: Html = .{
        .bytes =
        \\<html>
        \\  <body>
        \\    <h1>Test</h1>
        \\    <p style="color: red;">for a test</p>
        \\    <footer>
        \\      <script>
        \\        alert('xss');
        \\      </script>
        \\    </footer>
        \\  </body>
        \\</html>
        ,
    };
    const expected =
        \\&lt;html&gt;
        \\  &lt;body&gt;
        \\    &lt;h1&gt;Test&lt;/h1&gt;
        \\    &lt;p style=&quot;color: red;&quot;&gt;for a test&lt;/p&gt;
        \\    &lt;footer&gt;
        \\      &lt;script&gt;
        \\        alert(&#x27;xss&#x27;);
        \\      &lt;/script&gt;
        \\    &lt;/footer&gt;
        \\  &lt;/body&gt;
        \\&lt;/html&gt;
    ;

    const actual = try std.fmt.allocPrint(ta, "{s}", .{malicious});
    defer ta.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);

    const nested: Html = .{ .bytes = "<p<p<p<p>>>>>" };
    const expected_nested = "&lt;p&lt;p&lt;p&lt;p&gt;&gt;&gt;&gt;&gt;";
    const actual_nested = try std.fmt.allocPrint(ta, "{s}", .{nested});
    defer ta.free(actual_nested);

    try std.testing.expectEqualSlices(u8, expected_nested, actual_nested);
}

test html {
    const ta = std.testing.allocator;

    const malicious =
        \\<html>
        \\  <body>
        \\    <h1>Test</h1>
        \\    <p style="color: red;">for a test</p>
        \\    <footer>
        \\      <script>
        \\        alert('xss');
        \\      </script>
        \\    </footer>
        \\  </body>
        \\</html>
    ;
    const expected =
        \\&lt;html&gt;
        \\  &lt;body&gt;
        \\    &lt;h1&gt;Test&lt;/h1&gt;
        \\    &lt;p style=&quot;color: red;&quot;&gt;for a test&lt;/p&gt;
        \\    &lt;footer&gt;
        \\      &lt;script&gt;
        \\        alert(&#x27;xss&#x27;);
        \\      &lt;/script&gt;
        \\    &lt;/footer&gt;
        \\  &lt;/body&gt;
        \\&lt;/html&gt;
    ;
    const actual = try html(ta, malicious);
    defer ta.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);

    const nested = "<p<p<p<p>>>>>";
    const expected_nested = "&lt;p&lt;p&lt;p&lt;p&gt;&gt;&gt;&gt;&gt;";
    const actual_nested = try html(ta, nested);
    defer ta.free(actual_nested);

    try std.testing.expectEqualSlices(u8, expected_nested, actual_nested);
}

test "refAllDecls" {
    std.testing.refAllDecls(@This());
}
