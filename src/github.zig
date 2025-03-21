const std = @import("std");
const xev = @import("xev");

const log = @import("log.zig");

const HeapArena = @import("HeapArena.zig");
const Server = @import("Server.zig");
const WorkerQueue = Server.WorkerQueue;

/// Wrapper which authenticates with github
pub fn authenticate(
    arena: HeapArena,
    client: *std.http.Client,
    queue: *WorkerQueue,
    fd: xev.TCP,
    auth_header: []const u8,
) !void {
    errdefer {
        queue.push(.{ .auth_failure = .{
            .arena = arena,
            .fd = fd,
            .msg = "github authentication failed",
        } });
    }

    log.debug("authenticating with github", .{});
    const endpoint = "https://api.github.com/user";

    var storage = std.ArrayList(u8).init(arena.allocator());

    const req: std.http.Client.FetchOptions = .{
        .response_storage = .{ .dynamic = &storage },
        .location = .{ .url = endpoint },
        .method = .GET,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    };
    const result = try fetch(client, req);

    switch (result.status) {
        .ok => {
            const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), storage.items, .{});
            const resp = value.object;
            const login = resp.get("login").?.string;
            const avatar_url = resp.get("avatar_url").?.string;
            const realname = resp.get("name").?.string;
            const id = resp.get("id").?.integer;
            queue.push(.{
                .auth_success = .{
                    .arena = arena,
                    .fd = fd,
                    .nick = login,
                    .user = try std.fmt.allocPrint(arena.allocator(), "{d}", .{id}),
                    .realname = realname,
                    .avatar_url = avatar_url,
                },
            });
        },
        .unauthorized, .forbidden => {
            queue.push(.{
                .auth_failure = .{
                    .arena = arena,
                    .fd = fd,
                    .msg = storage.items,
                },
            });
        },
        else => {
            log.warn("unexpected github response: {s}", .{storage.items});
            return error.UnexpectedResponse;
        },
    }
}

/// Performs a fetch with retries
fn fetch(
    client: *std.http.Client,
    request: std.http.Client.FetchOptions,
) !std.http.Client.FetchResult {
    const max_attempts: u2 = 3;
    var attempts: u2 = 0;
    while (true) {
        const result = client.fetch(request) catch |err| {
            if (attempts == max_attempts) return err;
            defer attempts += 1;
            const delay: u64 = @as(u64, 500 * std.time.ns_per_ms) << (attempts + 1);
            log.warn("request failed, retrying in {d} ms", .{delay / std.time.ns_per_ms});
            std.time.sleep(delay);
            continue;
        };
        return result;
    }
}
