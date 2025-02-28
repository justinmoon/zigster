const std = @import("std");
pub const secp256k1 = @import("secp256k1");
pub const ws = @import("websocket");
const rand = std.crypto.random;

pub const Note = struct {
    // FIXME: should be a method?
    id: [32]u8,
    pubkey: secp256k1.PublicKey,
    created_at: i64,
    kind: i32,
    tags: [][]const u8,
    content: []const u8,
    // sig: ?[64]u8,
    sig: ?secp256k1.schnorr.Signature,

    pub fn createUnsigned(
        _: std.mem.Allocator,
        pubkey: secp256k1.PublicKey,
        content: []const u8,
        tags: [][]const u8,
    ) !Note {
        return Note{
            .id = undefined, // We'll calculate this later
            .pubkey = pubkey,
            .created_at = std.time.timestamp(),
            .kind = 1, // Text note
            .tags = tags,
            .content = content,
            .sig = null,
        };
    }

    /// Calculates the event ID which is the SHA256 hash of the serialized event data
    pub fn calculateId(self: Note, allocator: std.mem.Allocator) ![32]u8 {
        var id: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Format: [0, pubkey, created_at, kind, tags, content]
        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();

        try list.writer().print("[0,\"{s}\",{d},{d},{s},\"{s}\"]", .{
            std.fmt.fmtSliceHexLower(&self.pubkey.xOnlyPublicKey()[0].serialize()),
            self.created_at,
            self.kind,
            try std.json.stringifyAlloc(allocator, self.tags, .{}),
            self.content,
        });

        hasher.update(list.items);
        hasher.final(&id);
        return id;
    }

    /// Convert the note to a JSON string
    pub fn jsonStringify(self: Note, writer: anytype) !void {
        // Use the std.json writer to correctly serialize the object
        try writer.beginObject();

        // ID field
        try writer.objectField("id");
        try writer.write(std.fmt.fmtSliceHexLower(&self.id));

        // Pubkey field
        try writer.objectField("pubkey");
        try writer.write(std.fmt.fmtSliceHexLower(&self.pubkey.xOnlyPublicKey()[0].serialize()));

        // Created_at field
        try writer.objectField("created_at");
        try writer.write(self.created_at);

        // Kind field
        try writer.objectField("kind");
        try writer.write(self.kind);

        // Tags field
        try writer.objectField("tags");
        try writer.write(self.tags);

        // Content field
        try writer.objectField("content");
        try writer.write(self.content);

        // Signature field (if present)
        if (self.sig) |signature| {
            try writer.objectField("sig");
            try writer.write(std.fmt.fmtSliceHexLower(&signature.toStr()));
        }

        try writer.endObject();
    }

    /// Parse a JSON string into a Note
    pub fn jsonParse(allocator: std.mem.Allocator, json_str: []const u8) !Note {
        const json = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer json.deinit();

        const root = json.value.object;

        // Parse id
        var id: [32]u8 = undefined;
        const id_value = root.get("id").?;
        if (id_value == .object and id_value.object.contains("data")) {
            // Handle data array format
            const id_data = id_value.object.get("data").?.array;
            for (id_data.items, 0..) |byte, i| {
                id[i] = @intCast(byte.integer);
            }
        } else if (id_value == .string) {
            // Handle string format (for backward compatibility)
            const id_str = id_value.string;
            _ = try std.fmt.hexToBytes(&id, id_str);
        } else {
            return error.InvalidIdFormat;
        }

        // Parse pubkey
        var pubkey_bytes: [33]u8 = undefined;
        pubkey_bytes[0] = 0x02; // Add prefix byte (will be corrected when PublicKey is created)

        const pubkey_value = root.get("pubkey").?;
        if (pubkey_value == .object and pubkey_value.object.contains("data")) {
            // Handle data array format
            const pubkey_data = pubkey_value.object.get("data").?.array;
            for (pubkey_data.items, 0..) |byte, i| {
                if (i < 32) { // Ensure we don't go out of bounds
                    pubkey_bytes[i + 1] = @intCast(byte.integer);
                }
            }
        } else if (pubkey_value == .string) {
            // Handle string format (for backward compatibility)
            const pubkey_str = pubkey_value.string;
            _ = try std.fmt.hexToBytes(pubkey_bytes[1..], pubkey_str);
        } else {
            return error.InvalidPubkeyFormat;
        }

        const pubkey = try secp256k1.PublicKey.fromSlice(&pubkey_bytes);

        // Parse created_at
        const created_at = @as(i64, @intCast(root.get("created_at").?.integer));

        // Parse kind
        const kind = @as(i32, @intCast(root.get("kind").?.integer));

        // Parse content
        const content = root.get("content").?.string;

        // Parse tags - this is more complex as it's a nested structure
        const tags_json = root.get("tags").?.array;
        var tags = try allocator.alloc([]const u8, tags_json.items.len);
        for (tags_json.items, 0..) |tag_item, i| {
            if (tag_item == .string) {
                tags[i] = try allocator.dupe(u8, tag_item.string);
            } else if (tag_item == .array) {
                // Handle nested array case (original structure)
                const tag_items = tag_item.array.items;
                tags[i] = try allocator.dupe(u8, tag_items[0].string);
            } else {
                // Unexpected type, use a default
                tags[i] = try allocator.dupe(u8, "unknown");
            }
        }

        // Create note with parsed values
        var note = Note{
            .id = id,
            .pubkey = pubkey,
            .created_at = created_at,
            .kind = kind,
            .tags = tags,
            .content = try allocator.dupe(u8, content),
            .sig = null,
        };

        // Parse signature if present
        if (root.get("sig")) |sig_value| {
            const sig_str = sig_value.string;
            // The signature might be too long, let's extract the correct number of bytes
            var sig_bytes: [64]u8 = undefined;
            _ = try std.fmt.hexToBytes(&sig_bytes, sig_str);
            var sig_str_normalized: [128]u8 = undefined; // 64 bytes * 2 for hex
            _ = try std.fmt.bufPrint(&sig_str_normalized, "{s}", .{std.fmt.fmtSliceHexLower(&sig_bytes)});
            note.sig = try secp256k1.schnorr.Signature.fromStr(sig_str_normalized[0..128]);
        }

        return note;
    }
};

// Maybe not necessary???
pub const Signer = struct {
    secret_key: secp256k1.SecretKey,
    // FIXME: maybe not necessary???
    secp256k1: secp256k1.Secp256k1,

    pub fn init(secret_key: secp256k1.SecretKey) !Signer {
        return Signer{
            .secret_key = secret_key,
            .secp256k1 = secp256k1.Secp256k1.genNew(),
        };
    }

    pub fn deinit(self: *Signer) void {
        self.secp256k1.deinit();
    }

    /// Get the public key associated with this signer
    pub fn getPublicKey(self: *Signer) secp256k1.PublicKey {
        return self.secret_key.publicKey(self.secp256k1);
    }

    /// Sign a note, updating its id and sig fields
    pub fn signNote(self: *Signer, allocator: std.mem.Allocator, note: *Note) !void {
        note.id = try note.calculateId(allocator);
        const signature = self.secret_key.sign(&note.id);
        note.sig = try signature;
    }
};

pub const RelayError = error{
    ConnectionFailed,
    SendFailed,
    NoteNotSigned,
    InvalidResponse,
};

pub const Relay = struct {
    client: ws.Client,
    allocator: std.mem.Allocator,

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16) !Relay {
        var client = try ws.Client.init(allocator, .{
            .port = port,
            .host = host,
        });
        errdefer client.deinit();

        // Send the initial handshake request
        try client.handshake("/", .{
            .timeout_ms = 5000,
            .headers = try std.fmt.allocPrint(allocator, "Host: {s}:{d}\r\n", .{ host, port }),
        });

        return Relay{
            .client = client,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Relay) void {
        self.client.deinit();
    }
};

// Illustrating Grok's recommended approach
// pub fn jsonStringify(self: @This(), out: anytype) !void {
//     try out.beginArray();
//     try out.write("EVENT");
//     try out.beginObject();
//     try out.objectField("id"); try out.write(self.id);
//     try out.objectField("pubkey"); try out.write(self.pubkey);
//     try out.objectField("created_at"); try out.write(self.created_at);
//     try out.objectField("kind"); try out.write(self.kind);
//     try out.objectField("tags"); try out.write(self.tags);
//     try out.objectField("content"); try out.write(self.content);
//     try out.objectField("sig"); try out.write(self.sig);
//     try out.endObject();
//     try out.endArray();
// }
