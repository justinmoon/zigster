const std = @import("std");
const relay_mod = @import("relay.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.debug.print("Memory leak detected!\n", .{});
    }
    var relay = relay_mod.Relay.init(allocator);
    try relay.run();
}
