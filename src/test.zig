// Test wrapper for Zigster that imports all necessary modules
const std = @import("std");
const secp256k1 = @import("secp256k1");
const websocket = @import("websocket");

// Import the main library code for testing
const root = @import("zigster_lib");
const Note = root.Note;
const Signer = root.Signer;

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

test "Full Nostr workflow - create, sign, broadcast, and verify" {
    const testing = std.testing;
    std.debug.print("\n>> Running test: Full Nostr workflow\n", .{});

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1. Create a keypair
    var secp = secp256k1.Secp256k1.genNew();
    defer secp.deinit();
    const secret_key, const pubkey = secp.generateKeypair(std.crypto.random);

    // 2. Create a signer with the secret key
    var signer = try Signer.init(secret_key);
    defer signer.deinit();

    // 3. Create a note with content "Hello, nostr"
    const content = "Hello, nostr";
    const tags = try allocator.alloc([]const u8, 0); // Empty tags for simplicity
    var note = try Note.createUnsigned(allocator, pubkey, content, tags);

    // 4. Sign the note
    try signer.signNote(allocator, &note);
    std.debug.print("Created and signed note with ID: {s}\n", .{std.fmt.fmtSliceHexLower(&note.id)});

    // 5. Connect to a local relay
    var client = try root.NostrClient.connect(allocator, "localhost", 8080);
    defer client.deinit();
    std.debug.print("Connected to relay at localhost:8080\n", .{});

    // 6. Create an EVENT message to broadcast the note
    const event_msg = root.ClientMessage{ .Event = note };

    // 7. Serialize and send the message
    var serialized_msg = std.ArrayList(u8).init(allocator);
    defer serialized_msg.deinit();
    try std.json.stringify(event_msg, .{}, serialized_msg.writer());

    // Debug print to see what we're sending
    std.debug.print("EVENT message JSON: {s}\n", .{serialized_msg.items});

    try client.client.writeFrame(.text, serialized_msg.items);
    std.debug.print("Sent EVENT message to relay\n", .{});

    // 8. Wait a moment for the relay to process the event
    std.time.sleep(std.time.ns_per_s * 1); // Sleep for 1 second

    // 9. Create a REQ message to verify the note was accepted
    const subscription_id = "test-sub-1";
    var filter = root.Filter.init(allocator);

    // Create a hex string for the ID
    var id_hex_buf: [64]u8 = undefined; // 32 bytes = 64 hex chars
    _ = try std.fmt.bufPrint(&id_hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&note.id)});

    // Create the ids array with the value already in it
    var ids = try allocator.alloc([]const u8, 1);
    ids[0] = try allocator.dupe(u8, id_hex_buf[0..]);
    filter.ids = ids;

    var filters = try allocator.alloc(root.Filter, 1);
    filters[0] = filter;

    const req_msg = root.ClientMessage{ .Req = .{
        .subscription_id = subscription_id,
        .filters = filters,
    } };

    // 10. Serialize and send the REQ message
    serialized_msg.clearRetainingCapacity();
    try std.json.stringify(req_msg, .{}, serialized_msg.writer());

    // Debug print to see what we're sending
    std.debug.print("REQ message JSON: {s}\n", .{serialized_msg.items});

    try client.client.writeFrame(.text, serialized_msg.items);
    std.debug.print("Sent REQ message to relay\n", .{});

    // 11. Read the response from the relay
    var found_event = false;
    var received_eose = false;

    // Create a handler to process messages
    const Handler = struct {
        found_event: *bool,
        received_eose: *bool,
        subscription_id: []const u8,
        note_id: *const [32]u8,
        allocator: std.mem.Allocator,

        pub fn handle(self: @This(), message: websocket.Message) !void {
            if (message.data.len == 0) return;

            std.debug.print("Received message: {s}\n", .{message.data});

            // Parse the response
            const relay_msg = try root.RelayMessage.jsonParse(self.allocator, message.data);

            switch (relay_msg) {
                .Event => |event| {
                    if (std.mem.eql(u8, event.subscription_id, self.subscription_id)) {
                        // Check if this is our event
                        if (std.mem.eql(u8, &event.event.id, self.note_id)) {
                            self.found_event.* = true;
                            // Use a different name for this buffer to avoid shadowing
                            var event_id_hex_buf: [64]u8 = undefined;
                            _ = std.fmt.bufPrint(&event_id_hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(self.note_id)}) catch unreachable;
                            std.debug.print("Found our event in the relay response: {s}!\n", .{event_id_hex_buf[0..]});
                        }
                    }
                },
                .Eose => |eose_sub_id| {
                    if (std.mem.eql(u8, eose_sub_id, self.subscription_id)) {
                        self.received_eose.* = true;
                        std.debug.print("Received EOSE for our subscription\n", .{});
                    }
                },
                else => {},
            }
        }

        pub fn close(_: @This()) void {}
    };

    // Create the handler and start the read loop in a new thread
    const handler = Handler{
        .found_event = &found_event,
        .received_eose = &received_eose,
        .subscription_id = subscription_id,
        .note_id = &note.id,
        .allocator = allocator,
    };

    _ = try client.client.readLoopInNewThread(handler);

    // Wait for the EOSE message or timeout
    const start_time = std.time.milliTimestamp();
    const timeout_ms = 5000; // 5 second timeout

    while (!received_eose and std.time.milliTimestamp() - start_time < timeout_ms) {
        std.time.sleep(10 * std.time.ns_per_ms); // Sleep briefly to avoid tight loop
    }

    // 12. Verify we found our event
    try testing.expect(found_event);
    std.debug.print("Test completed successfully!\n", .{});
}
