const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Handshake = websocket.Handshake;
const Message = websocket.Message;

const Context = struct {};

const Handler = struct {
    conn: *Conn,
    context: *Context,

    pub fn init(h: Handshake, conn: *Conn, context: *Context) !Handler {
        // `h` contains the initial websocket "handshake" request
        // It can be used to apply application-specific logic to verify / allow
        // the connection (e.g. valid url, query string parameters, or headers)

        _ = h; // we're not using this in our simple case

        return Handler{
            .conn = conn,
            .context = context,
        };
    }

    // optional hook that, if present, will be called after initialization is complete
    pub fn afterInit(_: *Handler) !void {}

    pub fn handle(self: *Handler, message: Message) !void {
        const data = message.data;
        try self.conn.write(data); // echo the message back
    }

    // called whenever the connection is closed, can do some cleanup in here
    pub fn close(_: *Handler) void {}
};

/// A simple Nostr relay implementation
pub const Relay = struct {
    allocator: std.mem.Allocator,

    /// Runs the relay
    pub fn run(self: *Relay) !void {
        std.debug.print("Starting nostr relay websocket server...\n", .{});

        var context = Context{};
        // Start the websocket server
        try websocket.listen(
            Handler,
            self.allocator,
            &context,
            .{
                .port = 9000,
                .address = "0.0.0.0",
                .max_headers = 32,
            },
        );
    }

    /// Creates a new Relay instance
    pub fn init(allocator: std.mem.Allocator) Relay {
        return Relay{
            .allocator = allocator,
        };
    }
};
