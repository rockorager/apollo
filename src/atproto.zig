const std = @import("std");
const sqlite = @import("sqlite");
const xev = @import("xev");

const db = @import("db.zig");
const irc = @import("irc.zig");
const log = @import("log.zig");

const Connection = Server.Connection;
const HeapArena = @import("HeapArena.zig");
const Server = @import("Server.zig");
const User = irc.User;
const WakeupResult = Server.WakeupResult;
const WorkerQueue = Server.WorkerQueue;

const DidDocument = struct {
    alsoKnownAs: []const []const u8,
    service: []const Service,
};

const Service = struct {
    id: []const u8,
    type: []const u8,
    serviceEndpoint: []const u8,
};

pub fn authenticateConnection(
    arena: HeapArena,
    client: *std.http.Client,
    queue: *WorkerQueue,
    pool: *sqlite.Pool,
    fd: xev.TCP,
    handle: []const u8,
    password: []const u8,
) !void {
    const did = resolveHandle(arena.allocator(), client, handle) catch |err| {
        log.err("resolving handle: {}", .{err});
        queue.push(.{
            .auth_failure = .{
                .arena = arena,
                .fd = fd,
                .msg = "error resolving handle",
            },
        });
        return;
    };

    const did_doc = resolveDid(arena.allocator(), client, did) catch |err| {
        log.err("resolving did: {}", .{err});
        queue.push(.{
            .auth_failure = .{
                .arena = arena,
                .fd = fd,
                .msg = "error resolving DID",
            },
        });
        return;
    };

    const scheme = "at://";
    // Backwards verify the alsoKnownAs field
    for (did_doc.alsoKnownAs) |also_known_as| {
        if (!std.mem.startsWith(u8, also_known_as, scheme)) continue;
        if (std.mem.eql(u8, also_known_as[scheme.len..], handle)) break;
    } else {
        log.err("handle doesn't match DID Document", .{});
        queue.push(.{
            .auth_failure = .{
                .arena = arena,
                .fd = fd,
                .msg = "handle doesn't match DID document",
            },
        });
        return;
    }

    const endpoint: []const u8 = for (did_doc.service) |service| {
        // Spec says id "ending with #atproto_pds"
        if (std.mem.endsWith(u8, service.id, "#atproto_pds") and
            std.ascii.eqlIgnoreCase(service.type, "AtprotoPersonalDataServer"))
            break service.serviceEndpoint;
    } else {
        queue.push(.{
            .auth_failure = .{
                .arena = arena,
                .fd = fd,
                .msg = "DID Document has no #atproto_pds",
            },
        });
        return;
    };

    // Now we have the endpoint and the DID.

    const result = authenticate(arena, client, pool, fd, handle, password, did, endpoint) catch {
        log.warn("couldn't authenticate", .{});
        queue.push(.{
            .auth_failure = .{
                .arena = arena,
                .fd = fd,
                .msg = "failed to authenticate",
            },
        });
        return;
    };

    queue.push(result);
}

/// Resolves a handle to a DID
fn resolveHandle(arena: std.mem.Allocator, client: *std.http.Client, handle: []const u8) ![]const u8 {
    // We don't look in the db for this handle. Handles can change, and we don't know if they
    // can be reused...so we just always resolve the handle to a DID via BlueSky

    if (handle.len >= 253) {
        return error.InvalidHandle;
    }

    var buf: [512]u8 = undefined;
    const query = std.fmt.bufPrint(&buf, "handle={s}", .{handle}) catch unreachable;
    const uri: std.Uri = .{
        .scheme = "https",
        .host = .{ .raw = "bsky.social" },
        .path = .{ .raw = "/xrpc/com.atproto.identity.resolveHandle" },
        .query = .{ .raw = query },
    };

    var storage = std.ArrayList(u8).init(arena);
    const req: std.http.Client.FetchOptions = .{
        .response_storage = .{ .dynamic = &storage },
        .location = .{ .uri = uri },
        .method = .GET,
    };

    const result = try fetch(client, req);

    switch (result.status) {
        .ok => {
            const Response = struct {
                did: []const u8,
            };
            const resp = try std.json.parseFromSliceLeaky(Response, arena, storage.items, .{});
            return resp.did;
        },
        .bad_request, .unauthorized => {
            const Response = struct {
                @"error": []const u8,
                message: []const u8,
            };
            const resp = try std.json.parseFromSliceLeaky(Response, arena, storage.items, .{});
            log.err("resolving handle: {s}: {s}", .{ resp.@"error", resp.message });
            return error.BadRequest;
        },
        else => log.err("resolving handle: {d}", .{result.status}),
    }
    return error.BadRequest;
}

/// Resolves a DID to a DID Document
fn resolveDid(arena: std.mem.Allocator, client: *std.http.Client, did: []const u8) !DidDocument {
    var iter = std.mem.splitScalar(u8, did, ':');
    _ = iter.next() orelse return error.InvalidDID;
    const method = iter.next() orelse return error.InvalidDID;
    const id = iter.next() orelse return error.InvalidDID;

    const uri: std.Uri =
        if (std.mem.eql(u8, "web", method)) blk: {
            break :blk .{
                .scheme = "https",
                .host = .{ .raw = id },
                .path = .{ .raw = "/.well-known/did.json" },
            };
        } else if (std.mem.eql(u8, "plc", method)) blk: {
            // We have to add a leading slash
            const path = std.fmt.allocPrint(arena, "/{s}", .{did}) catch unreachable;
            break :blk .{
                .scheme = "https",
                .host = .{ .raw = "plc.directory" },
                .path = .{ .raw = path },
            };
        } else return error.InvalidDID;

    var storage = std.ArrayList(u8).init(arena);
    const req: std.http.Client.FetchOptions = .{
        .response_storage = .{ .dynamic = &storage },
        .location = .{ .uri = uri },
        .method = .GET,
    };

    const result = try fetch(client, req);

    switch (result.status) {
        .ok => {
            const resp = try std.json.parseFromSliceLeaky(
                DidDocument,
                arena,
                storage.items,
                .{ .ignore_unknown_fields = true },
            );
            return resp;
        },
        .not_found => return error.DidNotFound,
        else => log.err("resolving did: {s}: {d}", .{ did, result.status }),
    }
    return error.BadRequest;
}

fn authenticate(
    arena: HeapArena,
    client: *std.http.Client,
    pool: *sqlite.Pool,
    fd: xev.TCP,
    handle: []const u8,
    password: []const u8,
    did: []const u8,
    endpoint: []const u8,
) !WakeupResult {
    const db_conn = pool.acquire();
    defer pool.release(db_conn);
    {
        // We delete all expired tokens
        const sql =
            \\DELETE FROM user_tokens
            \\WHERE refresh_expiry < ?;
        ;
        try db_conn.exec(sql, .{std.time.timestamp()});
    }

    // First we see if we have this user in the user_tokens table.
    const sql =
        \\SELECT id, password_hash, refresh_token
        \\FROM user_tokens
        \\WHERE user_id = (SELECT id FROM users WHERE did = ?);
    ;

    // There could be multiple entries. We'll check them all
    var rows = try db_conn.rows(sql, .{did});
    defer rows.deinit();

    const id: i64, const refresh_token: []const u8 = while (rows.next()) |row| {
        const hash = row.text(1);
        std.crypto.pwhash.bcrypt.strVerify(
            hash,
            password,
            .{ .silently_truncate_password = false },
        ) catch |err| {
            log.warn("bcrypt verification fail: {}", .{err});
            continue;
        };
        break .{ row.int(0), row.text(2) };
    } else {
        // None of them matched. Maybe this is a new app password. We try to authenticate
        // that way
        return createSession(arena, client, pool, fd, handle, password, did, endpoint);
    };

    return refreshSession(arena, client, pool, fd, handle, did, endpoint, refresh_token, id);
}

fn refreshSession(
    arena: HeapArena,
    client: *std.http.Client,
    pool: *sqlite.Pool,
    fd: xev.TCP,
    handle: []const u8,
    did: []const u8,
    endpoint: []const u8,
    token: []const u8,
    row_id: i64, // the row id we need to update with the new refresh token
) !WakeupResult {
    log.debug("refreshing session", .{});
    const route = "/xrpc/com.atproto.server.refreshSession";
    // Do the api call
    var uri = try std.Uri.parse(endpoint);
    if (uri.path.isEmpty()) {
        uri.path = .{ .raw = route };
    } else {
        const original = try uri.path.toRawMaybeAlloc(arena.allocator());
        const trim = std.mem.trimRight(u8, original, "/");
        const new = try std.mem.concat(arena.allocator(), u8, &.{ trim, route });
        uri.path = .{ .raw = new };
    }

    const auth_header = try std.fmt.allocPrint(arena.allocator(), "Bearer {s}", .{token});

    var storage = std.ArrayList(u8).init(arena.allocator());
    const req: std.http.Client.FetchOptions = .{
        .response_storage = .{ .dynamic = &storage },
        .location = .{ .uri = uri },
        .method = .POST,
        .headers = .{
            .authorization = .{ .override = auth_header },
        },
    };

    const result = try fetch(client, req);

    const new_token: []const u8 = switch (result.status) {
        .ok => blk: {
            const Response = struct {
                refreshJwt: []const u8,
            };
            const resp = try std.json.parseFromSliceLeaky(
                Response,
                arena.allocator(),
                storage.items,
                .{ .ignore_unknown_fields = true },
            );
            break :blk resp.refreshJwt;
        },
        else => {
            log.err("refreshing session: {s}: {d}: {s}", .{ handle, result.status, storage.items });
            // Delete the row to force creation of a new session
            const db_conn = pool.acquire();
            defer pool.release(db_conn);
            db_conn.exec("DELETE FROM user_tokens WHERE id = ?", .{row_id}) catch {};
            return error.BadRequest;
        },
    };

    const expiry = std.time.timestamp() + std.time.s_per_day * 28;

    const sql =
        \\UPDATE user_tokens
        \\SET refresh_token = ?, refresh_expiry = ?
        \\WHERE id = ?;
    ;

    const db_conn = pool.acquire();
    defer pool.release(db_conn);

    db_conn.exec(sql, .{ new_token, expiry, row_id }) catch |err| {
        log.err("saving refresh token to db: {}: {s}", .{ err, db_conn.lastError() });
        // Try to delete the row
        db_conn.exec("DELETE FROM user_tokens WHERE id = ?", .{row_id}) catch {};
    };

    log.debug("session saved", .{});
    return .{
        .auth_success = .{
            .arena = arena,
            .fd = fd,
            .nick = handle,
            .user = did,
            .avatar_url = "",
            .realname = "",
        },
    };
}

fn createSession(
    arena: HeapArena,
    client: *std.http.Client,
    pool: *sqlite.Pool,
    fd: xev.TCP,
    handle: []const u8,
    password: []const u8,
    did: []const u8,
    endpoint: []const u8,
) !WakeupResult {
    log.debug("creating new session: handle={s}", .{handle});
    const route = "/xrpc/com.atproto.server.createSession";
    // Do the api call
    var uri = try std.Uri.parse(endpoint);
    if (uri.path.isEmpty()) {
        uri.path = .{ .raw = route };
    } else {
        const original = try uri.path.toRawMaybeAlloc(arena.allocator());
        const trim = std.mem.trimRight(u8, original, "/");
        const new = try std.mem.concat(arena.allocator(), u8, &.{ trim, route });
        uri.path = .{ .raw = new };
    }

    const payload = try std.fmt.allocPrint(
        arena.allocator(),
        "{{\"identifier\":\"{s}\",\"password\":\"{s}\"}}",
        .{ handle, password },
    );

    var storage = std.ArrayList(u8).init(arena.allocator());
    const req: std.http.Client.FetchOptions = .{
        .response_storage = .{ .dynamic = &storage },
        .location = .{ .uri = uri },
        .method = .POST,
        .payload = payload,
        .headers = .{ .content_type = .{ .override = "application/json" } },
    };

    const result = try fetch(client, req);

    const refresh_jwt: []const u8 = switch (result.status) {
        .ok => blk: {
            const Response = struct {
                refreshJwt: []const u8,
            };
            const resp = try std.json.parseFromSliceLeaky(
                Response,
                arena.allocator(),
                storage.items,
                .{ .ignore_unknown_fields = true },
            );
            break :blk resp.refreshJwt;
        },
        else => {
            log.err("creating session: {s}: {d}: {s}", .{ handle, result.status, storage.items });
            return error.BadRequest;
        },
    };

    var buf: [256]u8 = undefined;
    const opts: std.crypto.pwhash.bcrypt.HashOptions = .{
        .params = .owasp,
        .encoding = .crypt,
    };

    const password_hash = try std.crypto.pwhash.bcrypt.strHash(
        password,
        opts,
        &buf,
    );

    const expiry = std.time.timestamp() + std.time.s_per_day * 28;

    {
        // HACK: We create a dummy user and do a store. This ensures the user exists in our
        // query below.

        var user: User = .init();
        user.nick = handle;
        user.username = did;
        try db.storeUser(pool, &user);
    }

    const sql =
        \\INSERT INTO user_tokens (user_id, refresh_token, refresh_expiry, password_hash)
        \\VALUES (
        \\  (SELECT id FROM users WHERE did = ?),
        \\  ?, -- token
        \\  ?, -- expiry
        \\  ?  -- password hash
        \\);
    ;

    const db_conn = pool.acquire();
    defer pool.release(db_conn);

    db_conn.exec(sql, .{ did, refresh_jwt, expiry, password_hash }) catch |err| {
        log.err("saving refresh token to db: {}: {s}", .{ err, db_conn.lastError() });
    };

    return .{
        .auth_success = .{
            .arena = arena,
            .fd = fd,
            .nick = handle,
            .user = did,
            .avatar_url = "",
            .realname = "",
        },
    };
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
