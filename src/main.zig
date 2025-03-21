const std = @import("std");
const builtin = @import("builtin");

const log = @import("log.zig");

const Allocator = std.mem.Allocator;
const Server = @import("Server.zig");

const assert = std.debug.assert;

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main() !void {
    log.init();
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

    var opts: Server.Options = .{};
    var args = std.process.args();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--hostname")) {
            opts.hostname = args.next() orelse return error.InvalidArgs;
            continue;
        }
        if (std.mem.eql(u8, arg, "--irc-port")) {
            const port = args.next() orelse return error.InvalidArgs;
            opts.irc_port = try std.fmt.parseUnsigned(u16, port, 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--http-port")) {
            const port = args.next() orelse return error.InvalidArgs;
            opts.http_port = try std.fmt.parseUnsigned(u16, port, 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--auth")) {
            const auth = args.next() orelse return error.InvalidArgs;
            if (std.mem.eql(u8, auth, "none")) {
                opts.auth = .none;
            } else if (std.mem.eql(u8, auth, "github")) {
                opts.auth = .github;
            } else if (std.mem.eql(u8, auth, "atproto")) {
                opts.auth = .atproto;
            }
            continue;
        }
        if (std.mem.eql(u8, arg, "--db")) {
            opts.db_path = args.next() orelse return error.InvalidArgs;
            continue;
        }
    }
    var server: Server = undefined;
    try server.init(gpa, opts);
    defer server.deinit();

    try server.loop.run(.until_done);
}

test {
    _ = @import("queue.zig");
    _ = @import("sanitize.zig");
}
