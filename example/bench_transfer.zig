//! TLS throughput and handshake rate over loopback, client and server in one
//! process. Build with -Dcrypto=std or -Dcrypto=aws_lc to compare backends.
//!
//!   zig build -Doptimize=ReleaseFast [-Dcrypto=aws_lc]
//!   zig-out/bin/bench_transfer <cert dir with cert.pem and key.pem>

const std = @import("std");
const tls = @import("tls");

const port = 9445;
const transfer_bytes = 2 * 1024 * 1024 * 1024; // per cipher suite
const handshakes = 500;
const chunk_len = 64 * 1024;

const Mode = enum { transfer, handshakes };

const Server = struct {
    io: std.Io,
    auth: *tls.config.CertKeyPair,
    listener: *std.Io.net.Server,
    suite: tls.config.CipherSuite,
    mode: Mode,

    fn run(s: Server) void {
        s.serve() catch |err| std.debug.print("server: {}\n", .{err});
    }

    fn serve(s: Server) !void {
        const rng_impl: std.Random.IoSource = .{ .io = s.io };
        const count: usize = if (s.mode == .handshakes) handshakes else 1;
        var chunk: [chunk_len]u8 = undefined;
        @memset(&chunk, 'x');
        for (0..count) |_| {
            const stream = try s.listener.accept(s.io);
            defer stream.close(s.io);
            var conn = try tls.serverFromStream(s.io, stream, .{
                .auth = s.auth,
                .now = std.Io.Clock.real.now(s.io),
                .rng = rng_impl.interface(),
                .cipher_suites = &.{s.suite},
            });
            if (s.mode == .transfer) {
                var sent: usize = 0;
                while (sent < transfer_bytes) : (sent += chunk.len) try conn.writeAll(&chunk);
            }
            try conn.close();
        }
    }
};

fn nowNs(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

fn bench(io: std.Io, auth: *tls.config.CertKeyPair, listener: *std.Io.net.Server, suite: tls.config.CipherSuite, mode: Mode) !void {
    const server: Server = .{ .io = io, .auth = auth, .listener = listener, .suite = suite, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Server.run, .{server});
    defer thread.join();

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const count: usize = if (mode == .handshakes) handshakes else 1;
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const start = nowNs(io);
    var received: usize = 0;
    for (0..count) |_| {
        const stream = try address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var conn = try tls.clientFromStream(io, stream, .{
            .host = "localhost",
            .root_ca = .empty,
            .insecure_skip_verify = true,
            .cipher_suites = &.{suite},
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        });
        while (try conn.next()) |data| received += data.len;
    }
    const elapsed: f64 = @floatFromInt(nowNs(io) - start);
    switch (mode) {
        .transfer => {
            if (received != transfer_bytes) return error.ShortTransfer;
            std.debug.print("{s:<44} {d:>6.2} GB/s\n", .{ @tagName(suite), @as(f64, @floatFromInt(received)) / elapsed });
        },
        .handshakes => std.debug.print("{s:<44} {d:>6.0} handshakes/s\n", .{ @tagName(suite), @as(f64, @floatFromInt(count)) * std.time.ns_per_s / elapsed }),
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: {s} <cert dir with cert.pem and key.pem>\n", .{args[0]});
        return error.MissingArgument;
    }
    const dir = try std.Io.Dir.cwd().openDir(io, args[1], .{});
    var auth = try tls.config.CertKeyPair.fromFilePath(gpa, io, dir, "cert.pem", "key.pem");
    defer auth.deinit(gpa);

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var listener = try address.listen(io, .{ .mode = .stream, .reuse_address = true });
    defer listener.deinit(io);

    const suites = [_]tls.config.CipherSuite{ .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256 };
    for (suites) |suite| try bench(io, &auth, &listener, suite, .transfer);
    try bench(io, &auth, &listener, .AES_128_GCM_SHA256, .handshakes);
}
