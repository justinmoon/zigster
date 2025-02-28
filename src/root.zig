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

        var writer = std.json.writeStream(list.writer(), .{});
        try writer.beginArray();
        try writer.write(0);
        try writer.write(std.fmt.fmtSliceHexLower(&self.pubkey.xOnlyPublicKey()[0].serialize()));
        try writer.write(self.created_at);
        try writer.write(self.kind);
        try writer.write(self.tags);
        try writer.write(self.content);
        try writer.endArray();

        hasher.update(list.items);
        hasher.final(&id);
        return id;
    }

    /// Convert the note to a JSON string
    pub fn jsonStringify(self: Note, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("id");
        // Convert binary id to hex string
        const id_hex = try std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{std.fmt.fmtSliceHexLower(&self.id)});
        defer std.heap.page_allocator.free(id_hex);
        try writer.write(id_hex);

        try writer.objectField("pubkey");
        // Convert pubkey to hex string
        const pubkey_bytes = self.pubkey.xOnlyPublicKey()[0].serialize();
        const pubkey_hex = try std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{std.fmt.fmtSliceHexLower(&pubkey_bytes)});
        defer std.heap.page_allocator.free(pubkey_hex);
        try writer.write(pubkey_hex);

        try writer.objectField("created_at");
        try writer.write(self.created_at);
        try writer.objectField("kind");
        try writer.write(self.kind);
        try writer.objectField("tags");
        try writer.write(self.tags);
        try writer.objectField("content");
        try writer.write(self.content);
        if (self.sig) |signature| {
            try writer.objectField("sig");
            // Convert signature to hex string
            const sig_str = signature.toStr();
            const sig_hex = try std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{std.fmt.fmtSliceHexLower(&sig_str)});
            defer std.heap.page_allocator.free(sig_hex);
            try writer.write(sig_hex);
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

/// Filter structure for querying events from relays
/// As defined in NIP-01
pub const Filter = struct {
    ids: ?[][]const u8 = null,
    authors: ?[][]const u8 = null,
    kinds: ?[]const u16 = null,
    since: ?i64 = null,
    until: ?i64 = null,
    limit: ?u32 = null,
    // Tag filters are stored as a map of tag name to list of values
    // e.g. "#e": ["event1", "event2"]
    tag_filters: ?std.StringHashMap([]const []const u8) = null,

    pub fn init(allocator: std.mem.Allocator) Filter {
        return Filter{
            .tag_filters = std.StringHashMap([]const []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Filter) void {
        if (self.tag_filters) |*filters| {
            filters.deinit();
        }
    }

    pub fn addTagFilter(self: *Filter, tag: []const u8, values: []const []const u8) !void {
        if (self.tag_filters == null) {
            return error.TagFiltersNotInitialized;
        }
        try self.tag_filters.?.put(tag, values);
    }

    /// Convert the filter to a JSON object
    pub fn jsonStringify(self: Filter, writer: anytype) !void {
        try writer.beginObject();

        if (self.ids) |ids| {
            try writer.objectField("ids");
            try writer.write(ids);
        }

        if (self.authors) |authors| {
            try writer.objectField("authors");
            try writer.write(authors);
        }

        if (self.kinds) |kinds| {
            try writer.objectField("kinds");
            try writer.write(kinds);
        }

        if (self.since) |since| {
            try writer.objectField("since");
            try writer.write(since);
        }

        if (self.until) |until| {
            try writer.objectField("until");
            try writer.write(until);
        }

        if (self.limit) |limit| {
            try writer.objectField("limit");
            try writer.write(limit);
        }

        // Add tag filters if any exist
        if (self.tag_filters) |filters| {
            var iter = filters.iterator();
            while (iter.next()) |entry| {
                try writer.objectField(entry.key_ptr.*);
                try writer.write(entry.value_ptr.*);
            }
        }

        try writer.endObject();
    }

    /// Parse a JSON object into a Filter
    pub fn jsonParse(allocator: std.mem.Allocator, json_obj: std.json.Value) !Filter {
        if (json_obj != .object) {
            return error.InvalidFilterFormat;
        }

        var filter = Filter.init(allocator);
        errdefer filter.deinit();

        const obj = json_obj.object;

        if (obj.get("ids")) |ids_value| {
            if (ids_value != .array) return error.InvalidIdsFormat;
            const ids = try allocator.alloc([]const u8, ids_value.array.items.len);
            for (ids_value.array.items, 0..) |item, i| {
                if (item != .string) return error.InvalidIdFormat;
                ids[i] = try allocator.dupe(u8, item.string);
            }
            filter.ids = ids;
        }

        if (obj.get("authors")) |authors_value| {
            if (authors_value != .array) return error.InvalidAuthorsFormat;
            const authors = try allocator.alloc([]const u8, authors_value.array.items.len);
            for (authors_value.array.items, 0..) |item, i| {
                if (item != .string) return error.InvalidAuthorFormat;
                authors[i] = try allocator.dupe(u8, item.string);
            }
            filter.authors = authors;
        }

        if (obj.get("kinds")) |kinds_value| {
            if (kinds_value != .array) return error.InvalidKindsFormat;
            const kinds = try allocator.alloc(u16, kinds_value.array.items.len);
            for (kinds_value.array.items, 0..) |item, i| {
                if (item != .integer) return error.InvalidKindFormat;
                kinds[i] = @intCast(item.integer);
            }
            filter.kinds = kinds;
        }

        if (obj.get("since")) |since_value| {
            if (since_value != .integer) return error.InvalidSinceFormat;
            filter.since = @intCast(since_value.integer);
        }

        if (obj.get("until")) |until_value| {
            if (until_value != .integer) return error.InvalidUntilFormat;
            filter.until = @intCast(until_value.integer);
        }

        if (obj.get("limit")) |limit_value| {
            if (limit_value != .integer) return error.InvalidLimitFormat;
            filter.limit = @intCast(limit_value.integer);
        }

        // Parse tag filters (keys starting with #)
        var iter = obj.iterator();
        while (iter.next()) |entry| {
            const key = entry.key_ptr.*;
            if (key.len > 0 and key[0] == '#') {
                const tag_value = entry.value_ptr.*;
                if (tag_value != .array) continue;

                const values = try allocator.alloc([]const u8, tag_value.array.items.len);
                for (tag_value.array.items, 0..) |item, i| {
                    if (item != .string) continue;
                    values[i] = try allocator.dupe(u8, item.string);
                }

                try filter.addTagFilter(key, values);
            }
        }

        return filter;
    }
};

/// Message types for Nostr protocol communication
/// As defined in NIP-01
pub const ClientMessage = union(enum) {
    Event: Note,
    Req: struct { subscription_id: []const u8, filters: []Filter },
    Close: []const u8,

    /// Convert a client message to a JSON array
    pub fn jsonStringify(self: ClientMessage, writer: anytype) !void {
        try writer.beginArray();

        switch (self) {
            .Event => |note| {
                try writer.write("EVENT");
                try writer.write(note);
            },
            .Req => |req| {
                try writer.write("REQ");
                try writer.write(req.subscription_id);
                for (req.filters) |filter| {
                    try writer.write(filter);
                }
            },
            .Close => |subscription_id| {
                try writer.write("CLOSE");
                try writer.write(subscription_id);
            },
        }

        try writer.endArray();
    }
};

pub const RelayMessage = union(enum) {
    Event: struct { subscription_id: []const u8, event: Note },
    Ok: struct { event_id: [32]u8, success: bool, message: []const u8 },
    Eose: []const u8,
    Closed: struct { subscription_id: []const u8, message: []const u8 },
    Notice: []const u8,

    /// Convert a relay message to a JSON array
    pub fn jsonStringify(self: RelayMessage, writer: anytype) !void {
        try writer.beginArray();

        switch (self) {
            .Event => |event| {
                try writer.write("EVENT");
                try writer.write(event.subscription_id);
                try writer.write(event.event);
            },
            .Ok => |ok| {
                try writer.write("OK");
                try writer.write(std.fmt.fmtSliceHexLower(&ok.event_id));
                try writer.write(ok.success);
                try writer.write(ok.message);
            },
            .Eose => |subscription_id| {
                try writer.write("EOSE");
                try writer.write(subscription_id);
            },
            .Closed => |closed| {
                try writer.write("CLOSED");
                try writer.write(closed.subscription_id);
                try writer.write(closed.message);
            },
            .Notice => |message| {
                try writer.write("NOTICE");
                try writer.write(message);
            },
        }

        try writer.endArray();
    }

    /// Parse a JSON array into a RelayMessage
    pub fn jsonParse(allocator: std.mem.Allocator, json_str: []const u8) !RelayMessage {
        const json = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer json.deinit();

        if (json.value != .array or json.value.array.items.len < 1) {
            return error.InvalidMessageFormat;
        }

        const array = json.value.array;
        const message_type = array.items[0].string;

        if (std.mem.eql(u8, message_type, "EVENT")) {
            if (array.items.len < 3) return error.InvalidEventFormat;

            const subscription_id = try allocator.dupe(u8, array.items[1].string);
            const event_json = try std.json.stringifyAlloc(allocator, array.items[2], .{});
            const event = try Note.jsonParse(allocator, event_json);

            return RelayMessage{ .Event = .{
                .subscription_id = subscription_id,
                .event = event,
            } };
        } else if (std.mem.eql(u8, message_type, "OK")) {
            if (array.items.len < 4) return error.InvalidOkFormat;

            var event_id: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&event_id, array.items[1].string);
            const success = array.items[2].bool;
            const message = try allocator.dupe(u8, array.items[3].string);

            return RelayMessage{ .Ok = .{
                .event_id = event_id,
                .success = success,
                .message = message,
            } };
        } else if (std.mem.eql(u8, message_type, "EOSE")) {
            if (array.items.len < 2) return error.InvalidEoseFormat;

            const subscription_id = try allocator.dupe(u8, array.items[1].string);

            return RelayMessage{ .Eose = subscription_id };
        } else if (std.mem.eql(u8, message_type, "CLOSED")) {
            if (array.items.len < 3) return error.InvalidClosedFormat;

            const subscription_id = try allocator.dupe(u8, array.items[1].string);
            const message = try allocator.dupe(u8, array.items[2].string);

            return RelayMessage{ .Closed = .{
                .subscription_id = subscription_id,
                .message = message,
            } };
        } else if (std.mem.eql(u8, message_type, "NOTICE")) {
            if (array.items.len < 2) return error.InvalidNoticeFormat;

            const message = try allocator.dupe(u8, array.items[1].string);

            return RelayMessage{ .Notice = message };
        } else {
            return error.UnknownMessageType;
        }
    }
};

pub const NostrClient = struct {
    client: ws.Client,
    allocator: std.mem.Allocator,

    pub fn connect(allocator: std.mem.Allocator, host: []const u8, port: u16) !NostrClient {
        // Use the websocket.connect function directly as shown in the example
        var client = try ws.connect(allocator, host, port, .{
            .buffer_size = 4096, // Add reasonable buffer size
            .max_size = 1 << 20, // ~1MB max message size
        });
        errdefer client.deinit();

        // Send the initial handshake request
        try client.handshake("/", .{
            .timeout_ms = 5000,
            .headers = try std.fmt.allocPrint(allocator, "Host: {s}:{d}\r\n", .{ host, port }),
        });

        return NostrClient{
            .client = client,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NostrClient) void {
        self.client.deinit();
    }
};
