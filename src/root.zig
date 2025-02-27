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

    /// Serialize the note into a JSON string suitable for sending to a relay
    pub fn serialize(self: Note, allocator: std.mem.Allocator) ![]const u8 {
        if (self.sig == null) return error.NoteNotSigned;

        // Format the event object
        var event = std.ArrayList(u8).init(allocator);
        defer event.deinit();

        try event.writer().print("{{\"id\":\"{s}\",\"pubkey\":\"{s}\",\"created_at\":{d},\"kind\":{d},\"tags\":{s},\"content\":\"{s}\",\"sig\":\"{s}\"}}", .{
            std.fmt.fmtSliceHexLower(&self.id),
            std.fmt.fmtSliceHexLower(&self.pubkey.xOnlyPublicKey()[0].serialize()),
            self.created_at,
            self.kind,
            try std.json.stringifyAlloc(allocator, self.tags, .{}),
            self.content,
            std.fmt.fmtSliceHexLower(&self.sig.?.toStr()),
        });

        // Format the complete message
        var msg = std.ArrayList(u8).init(allocator);
        try msg.writer().print("[\"EVENT\",{s}]", .{event.items});
        return msg.toOwnedSlice();
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
        // if (signature) {
        //     note.sig = signature;
        // }
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

    pub fn broadcast(self: *Relay, note: Note) !void {
        // Serialize the note to JSON
        const msg = try note.serialize(self.allocator);
        defer self.allocator.free(msg);

        // Convert to mutable slice as required by websocket.zig
        const mutable_msg = try self.allocator.dupe(u8, msg);
        defer self.allocator.free(mutable_msg);

        try self.client.write(mutable_msg);
    }
};
