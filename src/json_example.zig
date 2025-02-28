const std = @import("std");

/// A simple struct with a boolean field that gets serialized as 1/0 instead of true/false
pub const NumericBoolean = struct {
    value: bool,

    /// Custom JSON stringification to convert boolean to 1/0
    pub fn jsonStringify(self: NumericBoolean, out: anytype) !void {
        // Simpler approach: use out.write to output 1 or 0
        const json: u8 = if (self.value) 1 else 0;
        return out.write(json);
    }

    /// Custom JSON parsing to convert 1/0 to boolean
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !NumericBoolean {
        // We need the allocator for parseFromTokenSource
        _ = options;

        // Parse JSON value using Zig's parser
        const parsed = try std.json.parseFromTokenSource(std.json.Value, allocator, source, .{});
        defer parsed.deinit();

        // Get the actual value from the parsed result
        const json_value = parsed.value;

        // Only accept integer 1 or 0, reject everything else
        return switch (json_value) {
            .integer => |i| switch (i) {
                1 => NumericBoolean{ .value = true },
                0 => NumericBoolean{ .value = false },
                else => error.InvalidNumber,
            },
            else => error.UnexpectedToken,
        };
    }
};

test "NumericBoolean serialization and parsing" {
    const allocator = std.testing.allocator;

    // Create a new instance
    const original = NumericBoolean{ .value = true };

    // Serialize it
    var serialized = std.ArrayList(u8).init(allocator);
    defer serialized.deinit();
    try std.json.stringify(original, .{}, serialized.writer());

    // Parse it back
    const round_trip = try std.json.parseFromSlice(
        NumericBoolean,
        allocator,
        serialized.items,
        .{},
    );
    defer round_trip.deinit();

    // Verify it matches the original
    try std.testing.expect(round_trip.value.value == original.value);
}

// Helper function to test invalid JSON inputs
fn testInvalidInput(allocator: std.mem.Allocator, json_string: []const u8, expected_error: anyerror) !void {
    const result = std.json.parseFromSlice(
        NumericBoolean,
        allocator,
        json_string,
        .{},
    );

    try std.testing.expectError(expected_error, result);
}

test "NumericBoolean rejects invalid inputs" {
    const allocator = std.testing.allocator;

    // Test integers other than 0 or 1
    try testInvalidInput(allocator, "2", error.InvalidNumber);
    try testInvalidInput(allocator, "-1", error.InvalidNumber);

    // Test non-integer types
    try testInvalidInput(allocator, "\"true\"", error.UnexpectedToken); // String
    try testInvalidInput(allocator, "true", error.UnexpectedToken); // Boolean
    try testInvalidInput(allocator, "1.0", error.UnexpectedToken); // Float
    try testInvalidInput(allocator, "null", error.UnexpectedToken); // Null
    try testInvalidInput(allocator, "{}", error.UnexpectedToken); // Object
    try testInvalidInput(allocator, "[]", error.UnexpectedToken); // Array
}
