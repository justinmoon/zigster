const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Get dependencies
    const secp256k1 = b.dependency("secp256k1", .{
        .target = target,
        .optimize = optimize,
    });

    const websocket = b.dependency("websocket", .{
        .target = target,
        .optimize = optimize,
    });

    // Create modules
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add dependencies to lib_mod
    lib_mod.linkLibrary(secp256k1.artifact("libsecp"));
    lib_mod.addImport("secp256k1", secp256k1.module("secp256k1"));
    lib_mod.addImport("websocket", websocket.module("websocket"));

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add dependencies to exe_mod
    exe_mod.addImport("zigster_lib", lib_mod);
    exe_mod.addImport("secp256k1", secp256k1.module("secp256k1"));
    exe_mod.linkLibrary(secp256k1.artifact("libsecp"));
    exe_mod.addImport("websocket", websocket.module("websocket"));

    // Create library
    const lib = b.addStaticLibrary(.{
        .name = "zigster",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Create executable
    const exe = b.addExecutable(.{
        .name = "zigster",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    // Set up the run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Using our test wrapper that imports all needed modules
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add module dependencies to the test
    // Need to link libsecp for the tests
    lib_unit_tests.linkLibrary(secp256k1.artifact("libsecp"));

    // Instead of addModule which isn't available, set up include paths for the modules
    lib_unit_tests.addIncludePath(secp256k1.path("src"));
    lib_unit_tests.addIncludePath(websocket.path("src"));
    lib_unit_tests.addIncludePath(b.path("src"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
