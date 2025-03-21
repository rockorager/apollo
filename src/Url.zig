const std = @import("std");

/// Returns a url percent-encoded slice that the caller must free.
/// Encoded characters: " < > ` # ? ^ { }
/// Not a complete urlencode implementation; this ignores unicode code points.
/// See https://url.spec.whatwg.org/#percent-encoded-bytes.
pub fn encode(allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
    var new_length = url.len;

    new_length += 2 * std.mem.count(u8, url, "\""); // " -> %22.
    new_length += 2 * std.mem.count(u8, url, "<"); // < -> %3C.
    new_length += 2 * std.mem.count(u8, url, ">"); // > -> %3E.
    new_length += 2 * std.mem.count(u8, url, "`"); // ` -> %60.
    new_length += 2 * std.mem.count(u8, url, "#"); // ` -> %23.
    new_length += 2 * std.mem.count(u8, url, "?"); // ` -> %3F.
    new_length += 2 * std.mem.count(u8, url, "^"); // ` -> %5E.
    new_length += 2 * std.mem.count(u8, url, "{"); // ` -> %7B.
    new_length += 2 * std.mem.count(u8, url, "}"); // ` -> %7D.

    const encoded = try allocator.alloc(u8, new_length);

    var encoded_idx: usize = 0;

    for (0..url.len) |i| {
        const c = url[i];

        if (c == '\"') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%22");
            encoded_idx += 3;
            continue;
        }
        if (c == '<') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%3C");
            encoded_idx += 3;
            continue;
        }
        if (c == '>') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%3E");
            encoded_idx += 3;
            continue;
        }
        if (c == '`') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%60");
            encoded_idx += 3;
            continue;
        }
        if (c == '#') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%23");
            encoded_idx += 3;
            continue;
        }
        if (c == '?') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%3F");
            encoded_idx += 3;
            continue;
        }
        if (c == '^') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%5E");
            encoded_idx += 3;
            continue;
        }
        if (c == '{') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%7B");
            encoded_idx += 3;
            continue;
        }
        if (c == '}') {
            @memcpy(encoded[encoded_idx .. encoded_idx + 3], "%7D");
            encoded_idx += 3;
            continue;
        }

        encoded[encoded_idx] = c;
        encoded_idx += 1;
    }

    return encoded;
}
