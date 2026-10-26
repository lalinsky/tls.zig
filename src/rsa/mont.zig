//! Modular exponentiation with a secret exponent, for the primes of an RSA
//! key. A fixed number of 64-bit limbs per size, known at compile time, lets
//! the multiplications below compile to straight-line carry chains, which
//! `std.crypto.ff` (generic limb count, 63-bit limbs, sized for the largest
//! modulus) does not get.
//!
//! Everything that depends on the modulus, the base or the exponent runs in
//! constant time: no branch and no memory index is derived from them.
const std = @import("std");

const Limb = u64;
const DLimb = u128;

pub fn Modulus(comptime n: usize) type {
    return struct {
        const Self = @This();

        pub const limbs = n;
        pub const bytes = n * 8;
        pub const Int = [n]Limb;

        /// Bits of exponent taken per multiplication.
        const window = 5;

        /// Whether `mul` and `sqr` are unrolled completely. That is the
        /// fastest by about a fifth, but costs code quadratic in `n`, so
        /// it is kept to 2048-bit keys and below; larger ones loop over rows.
        const unroll = n <= 16;

        /// Little-endian limbs of the modulus.
        m: Int,
        /// `-m^-1 mod 2^64`.
        m0inv: Limb,
        /// `R mod m`, with `R = 2^(64n)`: one, in Montgomery form.
        one: Int,
        /// `R^2 mod m`, which takes a value into Montgomery form.
        rr: Int,

        /// An odd modulus of at most `bytes` bytes, given big-endian.
        pub fn fromBytes(be: []const u8) error{InvalidModulus}!Self {
            const m = intFromBytes(be) catch return error.InvalidModulus;
            if (m[0] & 1 == 0) return error.InvalidModulus;
            if (isZero(m[1..].*) and m[0] < 3) return error.InvalidModulus;

            // Newton's iteration doubles the correct low bits each step; an
            // odd number is its own inverse modulo 8, which is 3 bits.
            var inv: Limb = m[0];
            for (0..5) |_| inv *%= 2 -% m[0] *% inv;

            var self: Self = .{ .m = m, .m0inv = 0 -% inv, .one = undefined, .rr = undefined };

            // 2^k mod m by doubling, from k = 0 up to 128n.
            var x: Int = @splat(0);
            x[0] = 1;
            for (0..2 * 64 * n) |k| {
                if (k == 64 * n) self.one = x;
                doubleMod(&x, &m);
            }
            self.rr = x;
            return self;
        }

        /// `x^e mod m`, for `x < m`, with `e` big-endian. The time taken
        /// depends on the length of `e`, but not on its value.
        pub fn pow(self: *const Self, x: Int, e: []const u8) Int {
            return self.fromMont(self.powMont(self.toMont(x), e));
        }

        /// `pow` with the base and the result in Montgomery form.
        pub fn powMont(self: *const Self, x: Int, e: []const u8) Int {
            var table: [1 << window]Int = undefined;
            table[0] = self.one;
            table[1] = x;
            for (2..table.len) |i| {
                table[i] = if (i % 2 == 0) self.sqr(table[i / 2]) else self.mul(table[i - 1], table[1]);
            }

            const total_bits = e.len * 8;
            // The first window takes the bits that do not divide evenly, so
            // every later one is whole.
            var pos = total_bits;
            const first = if (total_bits % window == 0) window else total_bits % window;
            pos -= first;
            var acc = select(&table, bitsAt(e, pos, first));
            while (pos > 0) {
                pos -= window;
                inline for (0..window) |_| acc = self.sqr(acc);
                acc = self.mul(acc, select(&table, bitsAt(e, pos, window)));
            }
            return acc;
        }

        /// `x` in Montgomery form, reduced: any `x` below `R` will do,
        /// since `mul` takes one operand up to `R` when the other is below
        /// `m`.
        pub fn toMont(self: *const Self, x: Int) Int {
            return self.mul(x, self.rr);
        }

        pub fn fromMont(self: *const Self, x: Int) Int {
            var plain_one: Int = @splat(0);
            plain_one[0] = 1;
            return self.mul(x, plain_one);
        }

        /// `x mod m` in Montgomery form, for a double-width `x`.
        pub fn reduceWide(self: *const Self, x: [2 * n]Limb) Int {
            const lo = self.toMont(x[0..n].*);
            // The high half stands for `hi * R`, one more factor of `R`.
            const hi = self.mul(self.toMont(x[n..].*), self.rr);
            return self.add(lo, hi);
        }

        /// `a + b mod m`, for `a, b < m`.
        pub fn add(self: *const Self, a: Int, b: Int) Int {
            var r: Int = undefined;
            var carry: Limb = 0;
            inline for (0..n) |i| {
                const s1 = @addWithOverflow(a[i], b[i]);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            self.reduceOnce(&r, carry);
            return r;
        }

        /// `a - b mod m`, for `a, b < m`.
        pub fn sub(self: *const Self, a: Int, b: Int) Int {
            var r: Int = undefined;
            var borrow: Limb = 0;
            inline for (0..n) |i| {
                const s1 = @subWithOverflow(a[i], b[i]);
                const s2 = @subWithOverflow(s1[0], borrow);
                r[i] = s2[0];
                borrow = s1[1] | s2[1];
            }
            // Add m back when it went below zero.
            const mask = 0 -% borrow;
            var carry: Limb = 0;
            inline for (0..n) |i| {
                const s1 = @addWithOverflow(r[i], self.m[i] & mask);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            return r;
        }

        /// Montgomery multiplication, `a * b / R mod m`, for `a, b < m`
        /// (coarsely integrated operand scanning).
        pub noinline fn mul(self: *const Self, a: Int, b: Int) Int {
            @setEvalBranchQuota(16 * n * n);
            var t: [n + 2]Limb = @splat(0);
            if (unroll) {
                inline for (0..n) |i| self.mulRow(&t, a, b[i]);
            } else {
                for (0..n) |i| self.mulRow(&t, a, b[i]);
            }
            var r: Int = t[0..n].*;
            self.reduceOnce(&r, t[n]);
            return r;
        }

        /// One step of `mul`: `t = (t + a * bi + q * m) / 2^64`.
        inline fn mulRow(self: *const Self, t: *[n + 2]Limb, a: Int, bi: Limb) void {
            var c: Limb = 0;
            inline for (0..n) |j| {
                const p = @as(DLimb, a[j]) * bi + t[j] + c;
                t[j] = @truncate(p);
                c = @truncate(p >> 64);
            }
            const s = @as(DLimb, t[n]) + c;
            t[n] = @truncate(s);
            t[n + 1] = @truncate(s >> 64);

            const q = t[0] *% self.m0inv;
            var p = @as(DLimb, q) * self.m[0] + t[0];
            c = @truncate(p >> 64);
            inline for (1..n) |j| {
                p = @as(DLimb, q) * self.m[j] + t[j] + c;
                t[j - 1] = @truncate(p);
                c = @truncate(p >> 64);
            }
            const s2 = @as(DLimb, t[n]) + c;
            t[n - 1] = @truncate(s2);
            t[n] = t[n + 1] + @as(Limb, @truncate(s2 >> 64));
        }

        /// `a * a / R mod m`: the cross products are computed once and
        /// doubled, then the double-width square is reduced.
        pub noinline fn sqr(self: *const Self, a: Int) Int {
            @setEvalBranchQuota(16 * n * n);
            var t: [2 * n + 1]Limb = @splat(0);

            // Cross products a[i] * a[j] for i < j.
            if (unroll) {
                inline for (0..n - 1) |i| {
                    var c: Limb = 0;
                    inline for (i + 1..n) |j| mulAdd(&t[i + j], a[i], a[j], &c);
                    t[i + n] = c;
                }
            } else {
                for (0..n - 1) |i| {
                    var c: Limb = 0;
                    for (i + 1..n) |j| mulAdd(&t[i + j], a[i], a[j], &c);
                    t[i + n] = c;
                }
            }

            // Doubled, plus the squares on the diagonal.
            var top: Limb = 0;
            inline for (0..2 * n) |k| {
                const v = t[k];
                t[k] = (v << 1) | top;
                top = v >> 63;
            }
            var c: Limb = 0;
            inline for (0..n) |i| {
                const p = @as(DLimb, a[i]) * a[i];
                var s = @as(DLimb, t[2 * i]) + @as(Limb, @truncate(p)) + c;
                t[2 * i] = @truncate(s);
                s = @as(DLimb, t[2 * i + 1]) + @as(Limb, @truncate(p >> 64)) + @as(Limb, @truncate(s >> 64));
                t[2 * i + 1] = @truncate(s);
                c = @truncate(s >> 64);
            }

            // Montgomery reduction of the 2n-limb square, one limb at a time.
            var hi: Limb = 0;
            if (unroll) {
                inline for (0..n) |i| self.reduceRow(t[i..][0 .. n + 1], &hi);
            } else {
                for (0..n) |i| self.reduceRow(t[i..][0 .. n + 1], &hi);
            }
            var r: Int = t[n .. 2 * n].*;
            self.reduceOnce(&r, hi);
            return r;
        }

        /// One step of the reduction in `sqr`: adds `q * m`, which clears
        /// `row[0]`, and carries out through `hi`.
        inline fn reduceRow(self: *const Self, row: *[n + 1]Limb, hi: *Limb) void {
            const q = row[0] *% self.m0inv;
            var c: Limb = 0;
            inline for (0..n) |j| mulAdd(&row[j], q, self.m[j], &c);
            const s = @as(DLimb, row[n]) + c + hi.*;
            row[n] = @truncate(s);
            hi.* = @truncate(s >> 64);
        }

        /// `x - m` in place when the value `carry * 2^(64n) + x` is at least
        /// `m`, which must be below `2m`.
        inline fn reduceOnce(self: *const Self, x: *Int, carry: Limb) void {
            var d: Int = undefined;
            var borrow: Limb = 0;
            inline for (0..n) |i| {
                const s = @subWithOverflow(x[i], self.m[i]);
                const s2 = @subWithOverflow(s[0], borrow);
                d[i] = s2[0];
                borrow = s[1] | s2[1];
            }
            // Keep x when the subtraction borrowed past the carry limb.
            const keep = 0 -% (borrow & ~carry & 1);
            inline for (0..n) |i| x[i] = (x[i] & keep) | (d[i] & ~keep);
        }

        pub fn intFromBytes(be: []const u8) error{Overflow}!Int {
            return limbsFromBytes(n, be);
        }

        pub fn intToBytes(x: Int, out: []u8) void {
            limbsToBytes(n, x, out);
        }

        /// `x = 2x mod m`, for `x < m`. Setup only, so the loops are left
        /// rolled; still constant time.
        fn doubleMod(x: *Int, m: *const Int) void {
            var top: Limb = 0;
            for (x) |*v| {
                const w = v.*;
                v.* = (w << 1) | top;
                top = w >> 63;
            }
            var d: Int = undefined;
            var borrow: Limb = 0;
            for (x, m, &d) |xv, mv, *dv| {
                const s1 = @subWithOverflow(xv, mv);
                const s2 = @subWithOverflow(s1[0], borrow);
                dv.* = s2[0];
                borrow = s1[1] | s2[1];
            }
            const keep = 0 -% (borrow & ~top & 1);
            for (x, d) |*xv, dv| xv.* = (xv.* & keep) | (dv & ~keep);
        }

        fn isZero(x: anytype) bool {
            var acc: Limb = 0;
            for (x) |v| acc |= v;
            return acc == 0;
        }

        /// `table[index]`, reading every entry.
        fn select(table: *const [1 << window]Int, index: usize) Int {
            var r: Int = @splat(0);
            for (table, 0..) |*entry, i| {
                const mask = ctEqMask(i, index);
                inline for (0..n) |k| r[k] |= entry[k] & mask;
            }
            return r;
        }
    };
}

/// The RSA secret-key operation by way of the key's primes (RFC 8017,
/// section 5.1.2, step 2.b), for primes of up to `n` limbs.
pub fn Crt(comptime n: usize) type {
    return struct {
        const Self = @This();
        const M = Modulus(n);

        p: M,
        q: M,
        /// `qInv = q^-1 mod p`, as a plain integer.
        q_inv: M.Int,

        /// From the big-endian integers of the key; `q_inv` must be below `p`.
        pub fn init(p: []const u8, q: []const u8, q_inv: []const u8) error{ InvalidModulus, Overflow }!Self {
            return .{
                .p = try M.fromBytes(p),
                .q = try M.fromBytes(q),
                .q_inv = try M.intFromBytes(q_inv),
            };
        }

        /// `x^d mod pq`, from `dP = d mod (p - 1)` and `dQ = d mod (q - 1)`.
        /// `x` and `out` are big-endian, and may be the same buffer; `out`
        /// must be long enough for `pq`.
        pub noinline fn pow(self: *const Self, x: []const u8, dp: []const u8, dq: []const u8, out: []u8) error{Overflow}!void {
            const xw = try limbsFromBytes(2 * n, x);
            const m1 = self.p.powMont(self.p.reduceWide(xw), dp);
            const m2 = self.q.fromMont(self.q.powMont(self.q.reduceWide(xw), dq));

            // h = qInv * (m1 - m2) (mod p). Multiplying the Montgomery form
            // of the difference by the plain qInv gives h plain.
            const h = self.p.mul(self.p.sub(m1, self.p.toMont(m2)), self.q_inv);

            // m = m2 + q * h, below pq.
            var r = mulWide(n, self.q.m, h);
            var carry: Limb = 0;
            for (0..2 * n) |i| {
                const s1 = @addWithOverflow(r[i], if (i < n) m2[i] else 0);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            limbsToBytes(2 * n, r, out);
        }
    };
}

/// The full product of two `n`-limb integers.
fn mulWide(comptime n: usize, a: [n]Limb, b: [n]Limb) [2 * n]Limb {
    var r: [2 * n]Limb = @splat(0);
    for (0..n) |i| {
        var c: Limb = 0;
        for (0..n) |j| mulAdd(&r[i + j], a[j], b[i], &c);
        r[i + n] = c;
    }
    return r;
}

/// A big-endian integer as `k` little-endian limbs; leading zeros beyond
/// their size are allowed.
fn limbsFromBytes(comptime k: usize, be: []const u8) error{Overflow}![k]Limb {
    const start = std.mem.indexOfNone(u8, be, &.{0}) orelse be.len;
    const len = be.len - start;
    if (len > 8 * k) return error.Overflow;
    var buf: [8 * k]u8 = @splat(0);
    @memcpy(buf[8 * k - len ..], be[start..]);
    var r: [k]Limb = undefined;
    for (0..k) |i| r[i] = std.mem.readInt(Limb, buf[8 * k - 8 * (i + 1) ..][0..8], .big);
    return r;
}

/// `x` big-endian, right-aligned in `out`, which must have room for it.
fn limbsToBytes(comptime k: usize, x: [k]Limb, out: []u8) void {
    var buf: [8 * k]u8 = undefined;
    for (0..k) |i| std.mem.writeInt(Limb, buf[8 * k - 8 * (i + 1) ..][0..8], x[i], .big);
    if (out.len >= buf.len) {
        @memset(out[0 .. out.len - buf.len], 0);
        @memcpy(out[out.len - buf.len ..], &buf);
    } else {
        @memcpy(out, buf[buf.len - out.len ..]);
    }
}

/// `t + x * y + c`, low limb into `t` and high limb into `c`.
inline fn mulAdd(t: *Limb, x: Limb, y: Limb, c: *Limb) void {
    const p = @as(DLimb, x) * y + t.* + c.*;
    t.* = @truncate(p);
    c.* = @truncate(p >> 64);
}

/// All ones when `a == b`, zero otherwise, without a branch.
fn ctEqMask(a: usize, b: usize) Limb {
    const d: Limb = a ^ b;
    // The top bit of `d | -d` is set exactly when `d` is not zero.
    return ((d | (0 -% d)) >> 63) -% 1;
}

/// `count` bits of big-endian `e`, starting `pos` bits from its least
/// significant end. The positions are public; only the value is secret.
fn bitsAt(e: []const u8, pos: usize, count: usize) usize {
    var r: usize = 0;
    var k = count;
    while (k > 0) {
        k -= 1;
        const bit = pos + k;
        const byte = e[e.len - 1 - bit / 8];
        r = (r << 1) | ((byte >> @intCast(bit % 8)) & 1);
    }
    return r;
}

const testing = std.testing;

fn testAgainstFf(comptime n: usize, seed: u64) !void {
    const M = Modulus(n);
    const F = std.crypto.ff.Modulus(n * 64);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    for (0..8) |_| {
        var m_bytes: [M.bytes]u8 = undefined;
        rand.bytes(&m_bytes);
        m_bytes[0] |= 0x80;
        m_bytes[M.bytes - 1] |= 1;
        const m = try M.fromBytes(&m_bytes);
        const fm = try F.fromBytes(&m_bytes, .big);

        var x_bytes: [M.bytes]u8 = undefined;
        rand.bytes(&x_bytes);
        x_bytes[0] &= 0x7f;
        var e_bytes: [M.bytes]u8 = undefined;
        rand.bytes(&e_bytes);

        const got = m.pow(try M.intFromBytes(&x_bytes), &e_bytes);
        const want = try fm.powWithEncodedExponent(try F.Fe.fromBytes(fm, &x_bytes, .big), &e_bytes, .big);

        var got_bytes: [M.bytes]u8 = undefined;
        M.intToBytes(got, &got_bytes);
        var want_bytes: [M.bytes]u8 = undefined;
        try want.toBytes(&want_bytes, .big);
        try testing.expectEqualSlices(u8, &want_bytes, &got_bytes);
    }
}

test "pow matches std.crypto.ff" {
    try testAgainstFf(16, 1);
    try testAgainstFf(24, 2);
    try testAgainstFf(32, 3);
}

test "pow with a modulus shorter than the limbs" {
    const M = Modulus(16);
    // 2^61 - 1, a prime: x^(p-1) = 1 by Fermat.
    var m_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &m_bytes, (1 << 61) - 1, .big);
    const m = try M.fromBytes(&m_bytes);
    var e_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &e_bytes, (1 << 61) - 2, .big);
    var x: M.Int = @splat(0);
    x[0] = 123456789;
    const r = m.pow(x, &e_bytes);
    try testing.expectEqual(@as(u64, 1), r[0]);
    for (r[1..]) |v| try testing.expectEqual(@as(u64, 0), v);
}

test "an even modulus is refused" {
    const M = Modulus(16);
    try testing.expectError(error.InvalidModulus, M.fromBytes(&.{ 0x12, 0x34 }));
}
