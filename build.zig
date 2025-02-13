const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .Debug });

    // Parse command-line argument for builder type
    const builder_type = b.option([]const u8, "builder", "Specify the builder type (module or debug)") orelse "module";

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (std.mem.eql(u8, builder_type, "debug")) {
        const debug_mod = b.createModule(.{
            .root_source_file = b.path("src/debugger.zig"),
            .target = target,
            .optimize = optimize,
        });
        const debug_exe = b.addExecutable(.{
            .name = "vmdebug",
            .root_module = debug_mod,
        });
        const exe_options = b.addOptions();
        exe_options.addOption(bool, "debug", true);
        debug_exe.root_module.addOptions("build_options", exe_options);
        b.installArtifact(debug_exe);
    } else if (std.mem.eql(u8, builder_type, "module")) {
        const exe = b.addExecutable(.{
            .name = "vm2026verify",
            .root_module = exe_mod,
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
        });
        const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_exe_unit_tests.step);
    } else {
        std.debug.print("Invalid builder type: {s}\n", .{builder_type});
    }
}
