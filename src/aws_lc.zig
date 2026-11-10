//! AEADs from AWS-LC's libcrypto, behind the same interface as
//! `std.crypto.aead`, so `cipher.zig` can use either.
//!
//! Only the handful of declarations used here, written by hand: `@cImport`
//! is gone in Zig 0.17 and translate-c through the build system would make
//! every user of this package depend on it.

const std = @import("std");
const assert = std.debug.assert;

const EVP_AEAD = opaque {};

/// `struct evp_aead_ctx_st` from openssl/aead.h.
const EVP_AEAD_CTX = extern struct {
    aead: ?*const EVP_AEAD,
    state: extern union {
        @"opaque": [564]u8,
        alignment: u64,
        ptr: ?*anyopaque,
    },
    state_offset: u8,
    tag_len: u8,
};

extern fn EVP_aead_aes_128_gcm() *const EVP_AEAD;
extern fn EVP_aead_aes_256_gcm() *const EVP_AEAD;
extern fn EVP_aead_chacha20_poly1305() *const EVP_AEAD;
extern fn EVP_AEAD_CTX_init(
    ctx: *EVP_AEAD_CTX,
    aead: *const EVP_AEAD,
    key: [*]const u8,
    key_len: usize,
    tag_len: usize,
    impl: ?*anyopaque,
) c_int;
extern fn EVP_AEAD_CTX_cleanup(ctx: *EVP_AEAD_CTX) void;
extern fn EVP_AEAD_CTX_seal_scatter(
    ctx: *const EVP_AEAD_CTX,
    out: [*]u8,
    out_tag: [*]u8,
    out_tag_len: *usize,
    max_out_tag_len: usize,
    nonce: [*]const u8,
    nonce_len: usize,
    in: [*]const u8,
    in_len: usize,
    extra_in: ?[*]const u8,
    extra_in_len: usize,
    ad: [*]const u8,
    ad_len: usize,
) c_int;
extern fn EVP_AEAD_CTX_open_gather(
    ctx: *const EVP_AEAD_CTX,
    out: [*]u8,
    nonce: [*]const u8,
    nonce_len: usize,
    in: [*]const u8,
    in_len: usize,
    in_tag: [*]const u8,
    in_tag_len: usize,
    ad: [*]const u8,
    ad_len: usize,
) c_int;

pub const Algorithm = enum { aes_128_gcm, aes_256_gcm, chacha20_poly1305 };

/// An AEAD with `std.crypto.aead`'s interface.
pub fn Aead(comptime algorithm: Algorithm) type {
    return struct {
        pub const key_length = switch (algorithm) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
        pub const tag_length = 16;
        pub const nonce_length = 12;

        fn evp() *const EVP_AEAD {
            // The plain GCM AEADs, not the _tls12/_tls13 ones: those enforce
            // the nonce sequence themselves, which needs a context that lives
            // as long as the key, and this interface takes the key per call.
            return switch (algorithm) {
                .aes_128_gcm => EVP_aead_aes_128_gcm(),
                .aes_256_gcm => EVP_aead_aes_256_gcm(),
                .chacha20_poly1305 => EVP_aead_chacha20_poly1305(),
            };
        }

        fn initCtx(ctx: *EVP_AEAD_CTX, key: *const [key_length]u8) void {
            // Only fails on a wrong key or tag length, or out of memory for
            // AEADs that allocate, which these do not.
            const rc = EVP_AEAD_CTX_init(ctx, evp(), key, key_length, tag_length, null);
            assert(rc == 1);
        }

        /// c: ciphertext, same length as m. AWS-LC allows c and m to be the
        /// same buffer or not overlap at all, so a shifted overlap is moved
        /// into place first.
        pub fn encrypt(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) void {
            assert(c.len == m.len);
            var in = m;
            if (m.ptr != c.ptr and overlaps(c, m)) {
                @memmove(c, m);
                in = c;
            }
            var ctx: EVP_AEAD_CTX align(16) = undefined;
            initCtx(&ctx, &key);
            defer EVP_AEAD_CTX_cleanup(&ctx);
            var tag_len: usize = 0;
            const rc = EVP_AEAD_CTX_seal_scatter(&ctx, c.ptr, tag, &tag_len, tag_length, &npub, nonce_length, in.ptr, in.len, null, 0, ad.ptr, ad.len);
            assert(rc == 1 and tag_len == tag_length);
        }

        /// m: cleartext, same length as c. A shifted overlap, which
        /// tls.zig uses to decrypt over the record header, is decrypted in
        /// place and then moved.
        pub fn decrypt(
            m: []u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) std.crypto.errors.AuthenticationError!void {
            assert(c.len == m.len);
            var ctx: EVP_AEAD_CTX align(16) = undefined;
            initCtx(&ctx, &key);
            defer EVP_AEAD_CTX_cleanup(&ctx);
            if (m.ptr != c.ptr and overlaps(m, c)) {
                const in_place: []u8 = @constCast(c);
                if (EVP_AEAD_CTX_open_gather(&ctx, in_place.ptr, &npub, nonce_length, c.ptr, c.len, &tag, tag_length, ad.ptr, ad.len) != 1)
                    return error.AuthenticationFailed;
                @memmove(m, in_place);
                return;
            }
            if (EVP_AEAD_CTX_open_gather(&ctx, m.ptr, &npub, nonce_length, c.ptr, c.len, &tag, tag_length, ad.ptr, ad.len) != 1)
                return error.AuthenticationFailed;
        }
    };
}

fn overlaps(a: []const u8, b: []const u8) bool {
    const a0 = @intFromPtr(a.ptr);
    const b0 = @intFromPtr(b.ptr);
    return a0 < b0 + b.len and b0 < a0 + a.len;
}

pub const Aes128Gcm = Aead(.aes_128_gcm);
pub const Aes256Gcm = Aead(.aes_256_gcm);
pub const ChaCha20Poly1305 = Aead(.chacha20_poly1305);

const testing = std.testing;

test "matches std.crypto" {
    inline for (.{
        .{ Aes128Gcm, std.crypto.aead.aes_gcm.Aes128Gcm },
        .{ Aes256Gcm, std.crypto.aead.aes_gcm.Aes256Gcm },
        .{ ChaCha20Poly1305, std.crypto.aead.chacha_poly.ChaCha20Poly1305 },
    }) |pair| {
        const Lc, const Std = pair;
        var key: [Lc.key_length]u8 = undefined;
        var nonce: [12]u8 = undefined;
        var msg: [1000]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @truncate(i *% 7);
        for (&nonce, 0..) |*b, i| b.* = @truncate(i *% 13);
        for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31);
        const ad = "header";

        var c1: [msg.len]u8 = undefined;
        var c2: [msg.len]u8 = undefined;
        var t1: [16]u8 = undefined;
        var t2: [16]u8 = undefined;
        Lc.encrypt(&c1, &t1, &msg, ad, nonce, key);
        Std.encrypt(&c2, &t2, &msg, ad, nonce, key);
        try testing.expectEqualSlices(u8, &c2, &c1);
        try testing.expectEqualSlices(u8, &t2, &t1);

        var m: [msg.len]u8 = undefined;
        try Lc.decrypt(&m, &c1, t1, ad, nonce, key);
        try testing.expectEqualSlices(u8, &msg, &m);

        // Decrypt over the bytes in front of the ciphertext, as tls.zig
        // does over the record header.
        var buf: [5 + msg.len]u8 = undefined;
        @memcpy(buf[5..], &c1);
        try Lc.decrypt(buf[0..msg.len], buf[5..], t1, ad, nonce, key);
        try testing.expectEqualSlices(u8, &msg, buf[0..msg.len]);

        // In place.
        var inplace = msg;
        var t3: [16]u8 = undefined;
        Lc.encrypt(&inplace, &t3, &inplace, ad, nonce, key);
        try testing.expectEqualSlices(u8, &c1, &inplace);

        t1[0] ^= 1;
        try testing.expectError(error.AuthenticationFailed, Lc.decrypt(&m, &c1, t1, ad, nonce, key));
    }
}
