// Test wrapper for Zigster that imports all necessary modules
const std = @import("std");
const secp256k1 = @import("secp256k1");
const websocket = @import("websocket");

// Import the main library code for testing
const root = @import("zigster_lib");
const Note = root.Note;
const Signer = root.Signer;
const Relay = root.Relay;

// Re-export all tests from imported modules
test {
    // This will include all the tests from the current file
    std.testing.refAllDecls(@This());
}

// Tests moved from root.zig
test "Note - create unsigned event" {
    const testing = std.testing;
    std.debug.print("\n>> Running test: Note - create unsigned event\n", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Create a dummy pubkey
    const secp = secp256k1.Secp256k1.genNew();
    defer secp.deinit();
    const sk, const pk = secp.generateKeypair(std.crypto.random);
    _ = sk;

    const content = "Hello, Nostr!";
    const tags = &[_][]const u8{};

    const note = try Note.createUnsigned(
        allocator,
        pk,
        content,
        tags,
    );

    try testing.expectEqual(@as(i32, 1), note.kind);
    try testing.expect(note.sig == null);
    try testing.expectEqualStrings(content, note.content);
    try testing.expectEqual(pk, note.pubkey);
}

test "Create, sign and broadcast note" {
    const testing = std.testing;
    std.debug.print("\n>> Running test: Create, sign and broadcast note\n", .{});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Create a test private key (all zeros)
    var secp = secp256k1.Secp256k1.genNew();
    defer secp.deinit();
    const sk, const pubkey = secp.generateKeypair(std.crypto.random);

    var signer = try Signer.init(sk);
    defer signer.deinit();

    const content = "Hello, Nostr!";
    const tag_str = "test-tag";
    var tags = try allocator.alloc([]const u8, 1);
    tags[0] = try allocator.dupe(u8, tag_str);

    var note = try Note.createUnsigned(allocator, pubkey, content, tags);
    try signer.signNote(allocator, &note);

    // Verify the note has been signed
    try testing.expect(note.sig != null);
    try testing.expect(!std.mem.eql(u8, &note.id, &[_]u8{0} ** 32));
    try pubkey.verify(&secp, &note.id, note.sig.?);
}

// Add a new simple test that directly uses secp256k1
test "Basic secp256k1 functionality" {
    std.debug.print("\n>> Running test: Basic secp256k1 functionality\n", .{});

    // Create a new secp256k1 context
    var secp = secp256k1.Secp256k1.genNew();
    defer secp.deinit();

    // Generate a keypair
    const secret_key, const public_key = secp.generateKeypair(std.crypto.random);

    // Test that we can create a message and sign it
    var message: [32]u8 = undefined;
    std.crypto.random.bytes(&message);

    // Sign the message
    const signature = try secret_key.sign(&message);

    // Verify the signature
    try public_key.verify(&secp, &message, signature);
}

test "Note serialization round-trip" {
    const testing = std.testing;
    std.debug.print("\n>> Running test: Note serialization round-trip\n", .{});

    const allocator = std.heap.page_allocator;

    // Create a simplified note with required fields for testing serialization
    var secp = secp256k1.Secp256k1.genNew();
    defer secp.deinit();
    const secret_key, const pk = secp.generateKeypair(std.crypto.random);
    _ = secret_key; // Unused, just for keypair generation

    // Create a simple note with known content
    const tag_str = "test-tag";
    var tags = try allocator.alloc([]const u8, 1);
    tags[0] = try allocator.dupe(u8, tag_str);

    var note = Note{
        .id = [_]u8{0} ** 32,
        .pubkey = pk,
        .created_at = std.time.timestamp(),
        .kind = 1,
        .tags = tags,
        .content = "Hello, world!",
        .sig = null,
    };

    // Get proper ID
    note.id = try note.calculateId(allocator);

    // Serialize to JSON
    var serialized_json = std.ArrayList(u8).init(allocator);
    defer serialized_json.deinit();

    try std.json.stringify(note, .{}, serialized_json.writer());

    std.debug.print("Serialized JSON: {s}\n", .{serialized_json.items});

    // Parse back into a Note
    var roundtrip_note = try Note.jsonParse(allocator, serialized_json.items);
    std.debug.print("Successfully roundtrip parsed Note object\n", .{});

    // Verify key fields match
    try testing.expectEqualSlices(u8, &note.id, &roundtrip_note.id);
    try testing.expectEqual(note.created_at, roundtrip_note.created_at);
    try testing.expectEqual(note.kind, roundtrip_note.kind);
    try testing.expectEqualStrings(note.content, roundtrip_note.content);

    std.debug.print("Round-trip serialization test passed successfully!\n", .{});
}
