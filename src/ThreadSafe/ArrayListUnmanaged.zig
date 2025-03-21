const std = @import("std");

pub fn ArrayListUnmanaged(comptime T: type) type {
    return struct {
        const Self = @This();

        data: std.ArrayListUnmanaged(T),
        mutex: std.Thread.Mutex,

        pub const empty: Self = .{
            .data = .empty,
            .mutex = .{},
        };

        pub fn append(self: *Self, allocator: std.mem.Allocator, item: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            try self.data.append(allocator, item);
        }

        pub fn swapRemove(self: *Self, idx: usize) T {
            self.mutex.lock();
            defer self.mutex.unlock();

            return self.data.swapRemove(idx);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.data.deinit(allocator);
        }
    };
}
