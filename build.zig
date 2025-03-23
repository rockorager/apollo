const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_llvm = switch (optimize) {
        .Debug => false,
        else => true,
    };

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const xev_mod = libxev.module("xev");
    exe_mod.addImport("xev", xev_mod);

    const zeit = b.dependency("zeit", .{
        .target = target,
        .optimize = optimize,
    });
    const zeit_mod = zeit.module("zeit");
    exe_mod.addImport("zeit", zeit_mod);

    // We use zqlite for the actual interface with sqlite
    const zqlite = b.dependency("zqlite", .{
        .target = target,
        .optimize = optimize,
    });
    const zqlite_mod = zqlite.module("zqlite");
    exe_mod.addImport("sqlite", zqlite_mod);
    exe_mod.link_libc = true;
    exe_mod.linkSystemLibrary("sqlite3", .{});

    const uuid = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });
    const uuid_mod = uuid.module("uuid");
    exe_mod.addImport("uuid", uuid_mod);

    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("httpz", httpz.module("httpz"));

    const exe = b.addExecutable(.{
        .name = "apollo",
        .root_module = exe_mod,
        .use_llvm = use_llvm,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
        .use_llvm = use_llvm,
    });
    exe_unit_tests.root_module.addImport("zeit", zeit_mod);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    {
        // Add a check step for zls
        const check_exe = b.addExecutable(.{
            .name = "apollo",
            .root_module = exe_mod,
        });

        const check_step = b.step("check", "Check if apollo compiles");
        check_step.dependOn(&check_exe.step);
    }
}
