//! HeapArena contains a heap allocator arena
const HeapArena = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;

arena: *std.heap.ArenaAllocator,

pub fn init(gpa: Allocator) Allocator.Error!HeapArena {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    return .{
        .arena = arena,
    };
}

pub fn deinit(self: HeapArena) void {
    const gpa = self.arena.child_allocator;
    self.arena.deinit();
    gpa.destroy(self.arena);
}

pub fn allocator(self: HeapArena) Allocator {
    return self.arena.allocator();
}
