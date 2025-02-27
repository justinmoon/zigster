const std = @import("std");
const relay_mod = @import("relay.zig");

pub fn main() !void {
    var relay = relay_mod.Relay.init();
    relay.run();
}
