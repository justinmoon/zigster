const std = @import("std");

/// A simple Nostr relay implementation
pub const Relay = struct {
    /// Runs the relay
    pub fn run(_: *Relay) void {
        std.debug.print("Hello, nostr!\n", .{});
    }

    /// Creates a new Relay instance
    pub fn init() Relay {
        return Relay{};
    }
};
