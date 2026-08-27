const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const Io = std.Io;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");
const record = @import("record.zig");
const rsa = @import("rsa/rsa.zig");
const proto = @import("protocol.zig");

const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

pub const supported_signature_algorithms = &[_]proto.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
    .rsa_pkcs1_sha1,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
};

pub const CertKeyPair = struct {
    /// A chain of one or more certificates, leaf first.
    ///
    /// Each X.509 certificate contains the public key of a key pair, extra
    /// information (the name of the holder, the name of an issuer of the
    /// certificate, validity time spans) and a signature generated using the
    /// private key of the issuer of the certificate.
    ///
    /// All certificates from the bundle are sent to the other side when creating
    /// Certificate tls message.
    ///
    /// Leaf certificate and private key are used to create signature for
    /// CertifyVerify tls message.
    bundle: Certificate.Bundle,

    /// Private key corresponding to the public key in leaf certificate from the
    /// bundle.
    key: PrivateKey,

    /// Ecdsa key pair derived from key. Computed on init and cached because it
    /// is costly operation. Important for server which is creating many
    /// signatures with the same key to not repeat that operation.
    ecdsa_key_pair: ?EcdsaKeyPair = null,

    pub fn fromFilePath(
        allocator: mem.Allocator,
        io: Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePath(allocator, io, dir, cert_path);
        const key_file = try dir.openFile(io, key_path, .{});
        defer key_file.close(io);

        const key = try PrivateKey.fromFile(allocator, io, key_file);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromFilePathAbsolute(
        allocator: mem.Allocator,
        io: Io,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePathAbsolute(allocator, io, cert_path);
        const key_file = try std.Io.Dir.openFileAbsolute(io, key_path, .{});
        defer key_file.close(io);

        const key = try PrivateKey.fromFile(allocator, io, key_file);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromSlice(
        allocator: mem.Allocator,
        io: Io,
        cert_slice: []const u8,
        key_slice: []const u8,
    ) !CertKeyPair {
        const key = try PrivateKey.parsePem(key_slice);
        const bundle = try cert.fromSlice(allocator, io, cert_slice);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn deinit(c: *CertKeyPair, allocator: mem.Allocator) void {
        c.bundle.deinit(allocator);
    }

    const EcdsaKeyPair = union(enum) {
        ecdsa_secp256r1_sha256: EcdsaP256Sha256.KeyPair,
        ecdsa_secp384r1_sha384: EcdsaP384Sha384.KeyPair,

        fn init(pk: PrivateKey) !?EcdsaKeyPair {
            switch (pk.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    const Ecdsa = SchemeEcdsa(comptime_scheme);
                    const key = pk.key.ecdsa;
                    const key_len = Ecdsa.SecretKey.encoded_length;
                    if (key.len < key_len) return error.InvalidEncoding;
                    const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                    return switch (comptime_scheme) {
                        .ecdsa_secp256r1_sha256 => .{ .ecdsa_secp256r1_sha256 = key_pair },
                        .ecdsa_secp384r1_sha384 => .{ .ecdsa_secp384r1_sha384 = key_pair },
                        else => unreachable,
                    };
                },
                else => return null,
            }
        }
    };
};

pub const cert = struct {
    // A chain of one or more certificates.
    //
    // They are used to verify that certificate chain sent by the other side
    // forms valid trust chain.
    pub const Bundle = crypto.Certificate.Bundle;

    pub fn fromFilePath(allocator: mem.Allocator, io: Io, dir: std.Io.Dir, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePath(allocator, io, Io.Clock.real.now(io), dir, path);
        return bundle;
    }

    pub fn fromFilePathAbsolute(allocator: mem.Allocator, io: Io, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePathAbsolute(allocator, io, Io.Clock.real.now(io), path);
        return bundle;
    }

    pub fn fromSystem(allocator: mem.Allocator, io: Io) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.rescan(allocator, io, Io.Clock.real.now(io));
        return bundle;
    }

    pub fn fromSlice(allocator: mem.Allocator, io: Io, slice: []const u8) !Bundle {
        const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const size = slice.len;
        const ts = Io.Clock.real.now(io);

        var bundle: Bundle = .empty;

        //Contains modified code from std.crypto.Certificate.Bundle.addCertsFromFile
        const decoded_size_upper_bound = size / 4 * 3;
        const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
            return Certificate.Bundle.AddCertsFromFileError.CertificateAuthorityBundleTooBig;
        try bundle.bytes.ensureUnusedCapacity(allocator, needed_capacity);
        const end_reserved: u32 = @intCast(bundle.bytes.items.len + decoded_size_upper_bound);
        const buffer = bundle.bytes.allocatedSlice()[end_reserved..];
        @memcpy(buffer[0..size], slice);
        const encoded_bytes = buffer[0..size];

        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";

        var start_index: usize = 0;
        while (mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
            const cert_start = begin_marker_start + begin_marker.len;
            const cert_end = mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
                return Certificate.Bundle.AddCertsFromFileError.MissingEndCertificateMarker;
            start_index = cert_end + end_marker.len;
            const encoded_cert = mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            const dest_buf = bundle.bytes.allocatedSlice()[decoded_start..];
            bundle.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
            try bundle.parseCert(allocator, decoded_start, ts.toSeconds());
        }
        return bundle;
    }
};

pub const CertificateBuilder = struct {
    cert_key_pair: *CertKeyPair,
    transcript: *Transcript,
    tls_version: proto.Version = .tls_1_3,
    side: proto.Side = .client,
    rng: std.Random,

    pub fn makeCertificate(h: CertificateBuilder, w: *record.Writer) !void {
        const certs = h.cert_key_pair.bundle.bytes.items;
        const certs_count = h.cert_key_pair.bundle.map.size;

        // Differences between tls 1.3 and 1.2
        // TLS 1.3 has request context in header and extensions for each certificate.
        // Here we use empty length for each field.
        // TLS 1.2 don't have these two fields.
        const request_context, const extensions = if (h.tls_version == .tls_1_3)
            .{ &[_]u8{0}, &[_]u8{ 0, 0 } }
        else
            .{ &[_]u8{}, &[_]u8{} };
        const certs_len = certs.len + (3 + extensions.len) * certs_count;

        // Write handshake header
        try w.handshakeRecordHeader(.certificate, certs_len + request_context.len + 3);
        try w.slice(request_context);
        try w.int(u24, certs_len);

        // Write each certificate
        var index: u32 = 0;
        while (index < certs.len) {
            const e = try Certificate.der.Element.parse(certs, index);
            const crt = certs[index..e.slice.end];
            try w.int(u24, crt.len); // certificate length
            try w.slice(crt); // certificate
            try w.slice(extensions); // certificate extensions
            index = e.slice.end;
        }
    }

    pub fn makeCertificateVerify(h: CertificateBuilder, w: *record.Writer) !void {
        // Creates signature for client certificate signature message.
        // Returns signature bytes and signature scheme.
        //
        // Every branch below returns a slice pointing into this buffer, so it
        // has to outlive the switch. 512 bytes is the largest of the three: an
        // RSA-4096 signature. ECDSA DER and Ed25519 are much smaller.
        var buf: [512]u8 = undefined;
        const signature, const signature_scheme = switch (h.cert_key_pair.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| brk: {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                var signer = try key_pair.signer(null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize();
                break :brk .{
                    signature.toDer(buf[0..Ecdsa.Signature.der_encoded_length_max]),
                    comptime_scheme,
                };
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| brk: {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try h.cert_key_pair.key.key.rsa.signerOaep(Hash, null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize(&buf, h.rng);
                break :brk .{ signature.bytes, comptime_scheme };
            },
            .ed25519 => brk: {
                // EdDSA signs the whole message in one shot (no incremental
                // hash state), so unlike the branches above this bypasses
                // setSignatureVerifyBytes and builds the TLS 1.3 CertificateVerify
                // content directly. Ed25519 isn't defined for TLS 1.2's
                // CertificateVerify construction, so tls_1_2 isn't handled here.
                const Eddsa = crypto.sign.Ed25519;
                const message = if (h.side == .server)
                    h.transcript.serverCertificateVerify()
                else
                    h.transcript.clientCertificateVerify();
                const signature = try h.cert_key_pair.key.key.ed25519.sign(message, null);
                buf[0..Eddsa.Signature.encoded_length].* = signature.toBytes();
                break :brk .{ buf[0..Eddsa.Signature.encoded_length], .ed25519 };
            },
            else => return error.TlsUnknownSignatureScheme,
        };

        try w.handshakeRecordHeader(.certificate_verify, signature.len + 4);
        try w.enumValue(signature_scheme);
        try w.int(u16, signature.len);
        try w.slice(signature);
    }

    fn setSignatureVerifyBytes(h: CertificateBuilder, signer: anytype) void {
        if (h.tls_version == .tls_1_2) {
            // tls 1.2 signature uses current transcript hash value.
            // ref: https://datatracker.ietf.org/doc/html/rfc5246.html#section-7.4.8
            const Hash = @TypeOf(signer.h);
            signer.h = h.transcript.hash(Hash);
        } else {
            // tls 1.3 signature is computed over concatenation of 64 spaces,
            // context, separator and content.
            // ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
            if (h.side == .server) {
                signer.update(h.transcript.serverCertificateVerify());
            } else {
                signer.update(h.transcript.clientCertificateVerify());
            }
        }
    }
};

fn SchemeEcdsa(comptime scheme: proto.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
        else => unreachable,
    };
}

pub const CertificateParser = struct {
    pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
    pub_key_buf: [1038]u8 = undefined,
    pub_key: []const u8 = undefined,

    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    signature_buf: [1024]u8 = undefined,
    signature: []const u8 = undefined,

    root_ca: Certificate.Bundle,
    host: []const u8,
    skip_verify: bool = false,
    now_sec: i64,
    purpose: Purpose = .server_auth,

    pub const Purpose = enum {
        server_auth,
        client_auth,
    };

    pub fn parseCertificate(h: *CertificateParser, d: *record.Decoder, tls_version: proto.Version) !void {
        if (tls_version == .tls_1_3) {
            const request_context = try d.decode(u8);
            if (request_context != 0) return error.TlsIllegalParameter;
        }

        var trust_chain_established = false;
        var last_cert: ?Certificate.Parsed = null;
        var non_self_issued_intermediates_below: usize = 0;
        var chain: [64]Certificate = undefined;
        var chain_len: usize = 0;
        const certs_len = try d.decode(u24);
        const start_idx = d.idx;
        while (d.idx - start_idx < certs_len) {
            const crt_len = try d.decode(u24);
            const crt = try d.slice(crt_len);
            if (tls_version == .tls_1_3) {
                // certificate extensions present in tls 1.3
                try d.skip(try d.decode(u16));
            }
            if (trust_chain_established)
                continue;

            const subject = try (Certificate{ .buffer = crt, .index = 0 }).parse();
            if (last_cert) |pc| {
                if (pc.verify(subject, h.now_sec)) {
                    if (!h.skip_verify) {
                        try validateIssuer(
                            subject,
                            h.purpose,
                            non_self_issued_intermediates_below,
                            false,
                            chain[0..chain_len],
                        );
                        if (chain_len == chain.len) return error.CertificateChainTooLong;
                        chain[chain_len] = subject.certificate;
                        chain_len += 1;
                    }
                    last_cert = subject;
                    if (!mem.eql(u8, subject.subject(), subject.issuer())) {
                        non_self_issued_intermediates_below += 1;
                    }
                } else |err| switch (err) {
                    error.CertificateIssuerMismatch => {
                        // skip certificate which is not part of the chain
                        continue;
                    },
                    else => return err,
                }
            } else { // first certificate
                if (!h.skip_verify and h.host.len > 0) {
                    try subject.verifyHostName(h.host);
                }
                if (!h.skip_verify) {
                    try validatePurpose(subject, h.purpose);
                    chain[0] = subject.certificate;
                    chain_len = 1;
                }
                h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
                h.pub_key_algo = subject.pub_key_algo;
                last_cert = subject;
            }
            if (!h.skip_verify) {
                if (try h.verifyRoot(
                    last_cert.?,
                    non_self_issued_intermediates_below,
                    chain[0..chain_len],
                )) {
                    trust_chain_established = true;
                }
            }
        }
        if (!h.skip_verify and !trust_chain_established) {
            return error.CertificateIssuerNotFound;
        }
    }

    fn verifyRoot(
        h: *const CertificateParser,
        subject: Certificate.Parsed,
        non_self_issued_intermediates_below: usize,
        chain_below: []const Certificate,
    ) !bool {
        const bytes_index = h.root_ca.find(subject.issuer()) orelse return false;
        const issuer = (Certificate{
            .buffer = h.root_ca.bytes.items,
            .index = bytes_index,
        }).parse() catch unreachable;
        try subject.verify(issuer, h.now_sec);
        if (h.now_sec < issuer.validity.not_before) return error.CertificateNotYetValid;
        if (h.now_sec > issuer.validity.not_after) return error.CertificateExpired;

        // An exact certificate in the trust store is already a trust anchor;
        // this preserves certificate pinning for a self-signed, non-CA leaf.
        // A distinct certificate used to sign the leaf still has to be a CA.
        if (!try sameCertificate(subject, issuer)) {
            try validateIssuer(
                issuer,
                h.purpose,
                non_self_issued_intermediates_below,
                true,
                chain_below,
            );
        }
        return true;
    }

    pub fn parseCertificateVerify(h: *CertificateParser, d: *record.Decoder) !void {
        h.signature_scheme = try d.decode(proto.SignatureScheme);
        h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
    }

    pub fn verifySignature(h: *CertificateParser, verify_bytes: []const u8) !void {
        switch (h.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                const cert_named_curve = h.pub_key_algo.X9_62_id_ecPublicKey;
                switch (cert_named_curve) {
                    inline .secp384r1, .X9_62_prime256v1 => |comptime_cert_named_curve| {
                        const Ecdsa = SchemeEcdsaCert(comptime_scheme, comptime_cert_named_curve);
                        const key = try Ecdsa.PublicKey.fromSec1(h.pub_key);
                        const sig = try Ecdsa.Signature.fromDer(h.signature);
                        try sig.verify(verify_bytes, key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            },
            .ed25519 => {
                if (h.pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                const Eddsa = crypto.sign.Ed25519;
                if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                if (h.pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(h.pub_key[0..Eddsa.PublicKey.encoded_length].*);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.Pss(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk, null);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.PKCS1v1_5(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk);
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    fn SchemeEcdsaCert(comptime scheme: proto.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
        const Sha256 = crypto.hash.sha2.Sha256;
        const Sha384 = crypto.hash.sha2.Sha384;
        const Ecdsa = crypto.sign.ecdsa.Ecdsa;

        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => Ecdsa(cert_named_curve.Curve(), Sha256),
            .ecdsa_secp384r1_sha384 => Ecdsa(cert_named_curve.Curve(), Sha384),
            else => @compileError("bad scheme"),
        };
    }
};

const CertificateConstraints = struct {
    basic_constraints_present: bool = false,
    is_ca: bool = false,
    max_path_len: ?u32 = null,
    key_usage_present: bool = false,
    key_cert_sign: bool = false,
    extended_key_usage_present: bool = false,
    server_auth: bool = false,
    client_auth: bool = false,
    any_auth: bool = false,
    name_constraints: ?NameConstraints = null,
};

fn validatePurpose(parsed: Certificate.Parsed, purpose: CertificateParser.Purpose) !void {
    const constraints = try parseCertificateConstraints(parsed);
    if (!constraints.extended_key_usage_present or constraints.any_auth) return;
    const permitted = switch (purpose) {
        .server_auth => constraints.server_auth,
        .client_auth => constraints.client_auth,
    };
    if (!permitted) return error.CertificateIncompatibleExtendedKeyUsage;
}

fn validateIssuer(
    parsed: Certificate.Parsed,
    purpose: CertificateParser.Purpose,
    non_self_issued_intermediates_below: usize,
    trust_anchor: bool,
    chain_below: []const Certificate,
) !void {
    const constraints = try parseCertificateConstraints(parsed);
    const basic_constraints_required = !trust_anchor or parsed.version == .v3;
    if ((basic_constraints_required and !constraints.basic_constraints_present) or
        (constraints.basic_constraints_present and !constraints.is_ca))
    {
        return error.CertificateNotAuthorizedToSign;
    }
    if (constraints.key_usage_present and !constraints.key_cert_sign) {
        return error.CertificateNotAuthorizedToSign;
    }
    if (constraints.max_path_len) |max_path_len| {
        if (non_self_issued_intermediates_below > max_path_len) {
            return error.CertificatePathLengthExceeded;
        }
    }
    if (constraints.extended_key_usage_present and !constraints.any_auth) {
        const permitted = switch (purpose) {
            .server_auth => constraints.server_auth,
            .client_auth => constraints.client_auth,
        };
        if (!permitted) return error.CertificateIncompatibleExtendedKeyUsage;
    }
    if (constraints.name_constraints) |name_constraints| {
        try checkNameConstraints(name_constraints, chain_below);
    }
}

const DerElement = struct {
    identifier: u8,
    start: usize,
    end: usize,
};

fn parseDerElement(bytes: []const u8, index: usize, limit: usize) !DerElement {
    if (limit > bytes.len or index >= limit or limit - index < 2) {
        return error.CertificateFieldHasInvalidLength;
    }
    const identifier = bytes[index];
    const size_byte = bytes[index + 1];
    var content_start = index + 2;
    var content_len: usize = 0;
    if (size_byte & 0x80 == 0) {
        content_len = size_byte;
    } else {
        const len_size = size_byte & 0x7f;
        if (len_size == 0 or len_size > @sizeOf(u32) or len_size > limit - content_start) {
            return error.CertificateFieldHasInvalidLength;
        }
        if (bytes[content_start] == 0) return error.CertificateFieldHasInvalidLength;
        for (bytes[content_start..][0..len_size]) |byte| {
            content_len = (content_len << 8) | byte;
        }
        if (content_len < 128) return error.CertificateFieldHasInvalidLength;
        content_start += len_size;
    }
    if (content_len > limit - content_start) return error.CertificateFieldHasInvalidLength;
    return .{
        .identifier = identifier,
        .start = content_start,
        .end = content_start + content_len,
    };
}

fn expectDerElement(bytes: []const u8, index: usize, limit: usize, identifier: u8) !DerElement {
    const elem = try parseDerElement(bytes, index, limit);
    if (elem.identifier != identifier) return error.CertificateFieldHasWrongDataType;
    return elem;
}

fn encodedCertificate(parsed: Certificate.Parsed) ![]const u8 {
    const bytes = parsed.certificate.buffer;
    const certificate = try expectDerElement(bytes, parsed.certificate.index, bytes.len, 0x30);
    return bytes[parsed.certificate.index..certificate.end];
}

fn sameCertificate(a: Certificate.Parsed, b: Certificate.Parsed) !bool {
    return mem.eql(u8, try encodedCertificate(a), try encodedCertificate(b));
}

fn certificateExtensions(parsed: Certificate.Parsed) !?DerElement {
    const bytes = parsed.certificate.buffer;
    const certificate = try expectDerElement(bytes, parsed.certificate.index, bytes.len, 0x30);
    const tbs = try expectDerElement(bytes, certificate.start, certificate.end, 0x30);
    var index = tbs.start;

    var elem = try parseDerElement(bytes, index, tbs.end);
    if (elem.identifier == 0xa0) {
        index = elem.end;
        elem = try parseDerElement(bytes, index, tbs.end);
    }

    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    inline for (0..5) |_| {
        index = elem.end;
        elem = try parseDerElement(bytes, index, tbs.end);
    }
    index = elem.end;

    while (index < tbs.end) {
        elem = try parseDerElement(bytes, index, tbs.end);
        switch (elem.identifier) {
            0x81, 0x82 => {}, // issuerUniqueID and subjectUniqueID
            0xa3 => {
                const extensions = try expectDerElement(bytes, elem.start, elem.end, 0x30);
                if (extensions.end != elem.end) return error.CertificateFieldHasInvalidLength;
                return extensions;
            },
            else => return error.CertificateFieldHasWrongDataType,
        }
        index = elem.end;
    }
    return null;
}

const ParsedExtension = struct {
    oid: []const u8,
    critical: bool,
    value: []const u8,
    end: usize,
};

fn parseExtension(bytes: []const u8, index: usize, limit: usize) !ParsedExtension {
    const extension = try expectDerElement(bytes, index, limit, 0x30);
    const oid = try expectDerElement(bytes, extension.start, extension.end, 0x06);
    var next = oid.end;
    var critical = false;
    var elem = try parseDerElement(bytes, next, extension.end);
    if (elem.identifier == 0x01) {
        if (elem.end - elem.start != 1 or
            (bytes[elem.start] != 0x00 and bytes[elem.start] != 0xff))
        {
            return error.CertificateFieldHasWrongDataType;
        }
        critical = bytes[elem.start] != 0;
        next = elem.end;
        elem = try parseDerElement(bytes, next, extension.end);
    }
    if (elem.identifier != 0x04) return error.CertificateFieldHasWrongDataType;
    if (elem.end != extension.end) return error.CertificateFieldHasInvalidLength;
    return .{
        .oid = bytes[oid.start..oid.end],
        .critical = critical,
        .value = bytes[elem.start..elem.end],
        .end = extension.end,
    };
}

const oid_key_usage = &[_]u8{ 0x55, 0x1d, 0x0f };
const oid_subject_alt_name = &[_]u8{ 0x55, 0x1d, 0x11 };
const oid_basic_constraints = &[_]u8{ 0x55, 0x1d, 0x13 };
const oid_name_constraints = &[_]u8{ 0x55, 0x1d, 0x1e };
const oid_extended_key_usage = &[_]u8{ 0x55, 0x1d, 0x25 };
const oid_any_extended_key_usage = &[_]u8{ 0x55, 0x1d, 0x25, 0x00 };
const oid_server_auth = &[_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
const oid_client_auth = &[_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };

const NameConstraints = struct {
    permitted: ?[]const u8,
    excluded: ?[]const u8,
};

fn parseCertificateConstraints(parsed: Certificate.Parsed) !CertificateConstraints {
    const extensions = try certificateExtensions(parsed) orelse return .{};
    const bytes = parsed.certificate.buffer;
    try validateUniqueExtensions(bytes, extensions);
    var result: CertificateConstraints = .{};
    var index = extensions.start;
    while (index < extensions.end) {
        const extension = try parseExtension(bytes, index, extensions.end);
        if (mem.eql(u8, extension.oid, oid_basic_constraints)) {
            result.basic_constraints_present = true;
            try parseBasicConstraints(extension.value, &result);
        } else if (mem.eql(u8, extension.oid, oid_key_usage)) {
            result.key_usage_present = true;
            result.key_cert_sign = try parseKeyCertSign(extension.value);
        } else if (mem.eql(u8, extension.oid, oid_extended_key_usage)) {
            result.extended_key_usage_present = true;
            try parseExtendedKeyUsage(extension.value, &result);
        } else if (mem.eql(u8, extension.oid, oid_name_constraints)) {
            result.name_constraints = try parseNameConstraints(extension.value, extension.critical);
        } else if (extension.critical and !mem.eql(u8, extension.oid, oid_subject_alt_name)) {
            return error.CertificateUnhandledCriticalExtension;
        }
        index = extension.end;
    }
    return result;
}

fn validateUniqueExtensions(bytes: []const u8, extensions: DerElement) !void {
    var index = extensions.start;
    while (index < extensions.end) {
        const extension = try parseExtension(bytes, index, extensions.end);
        var previous_index = extensions.start;
        while (previous_index < index) {
            const previous = try parseExtension(bytes, previous_index, extensions.end);
            if (mem.eql(u8, previous.oid, extension.oid)) return error.CertificateDuplicateExtension;
            previous_index = previous.end;
        }
        index = extension.end;
    }
}

fn parseBasicConstraints(value: []const u8, result: *CertificateConstraints) !void {
    const sequence = try expectDerElement(value, 0, value.len, 0x30);
    if (sequence.end != value.len) return error.CertificateFieldHasInvalidLength;
    var index = sequence.start;
    if (index < sequence.end) {
        var elem = try parseDerElement(value, index, sequence.end);
        if (elem.identifier == 0x01) {
            if (elem.end - elem.start != 1) return error.CertificateFieldHasInvalidLength;
            if (value[elem.start] != 0x00 and value[elem.start] != 0xff) {
                return error.CertificateFieldHasWrongDataType;
            }
            result.is_ca = value[elem.start] != 0;
            index = elem.end;
        }
        if (index < sequence.end) {
            elem = try expectDerElement(value, index, sequence.end, 0x02);
            if (elem.start == elem.end or elem.end - elem.start > @sizeOf(u32)) {
                return error.CertificateFieldHasInvalidLength;
            }
            if (value[elem.start] & 0x80 != 0) return error.CertificateFieldHasWrongDataType;
            var path_len: u32 = 0;
            for (value[elem.start..elem.end]) |byte| path_len = (path_len << 8) | byte;
            result.max_path_len = path_len;
            index = elem.end;
        }
    }
    if (index != sequence.end) return error.CertificateFieldHasInvalidLength;
    if (result.max_path_len != null and !result.is_ca) return error.CertificateFieldHasWrongDataType;
}

fn parseKeyCertSign(value: []const u8) !bool {
    const bit_string = try expectDerElement(value, 0, value.len, 0x03);
    if (bit_string.end != value.len or bit_string.end == bit_string.start) {
        return error.CertificateFieldHasInvalidLength;
    }
    const unused_bits = value[bit_string.start];
    if (unused_bits > 7) return error.CertificateFieldHasWrongDataType;
    if (bit_string.end - bit_string.start == 1) {
        if (unused_bits != 0) return error.CertificateFieldHasWrongDataType;
        return false;
    }
    const final_byte = value[bit_string.end - 1];
    const unused_mask: u8 = if (unused_bits == 0) 0 else (@as(u8, 1) << @intCast(unused_bits)) - 1;
    if (final_byte & unused_mask != 0) return error.CertificateFieldHasWrongDataType;
    return value[bit_string.start + 1] & 0x04 != 0;
}

fn parseExtendedKeyUsage(value: []const u8, result: *CertificateConstraints) !void {
    const sequence = try expectDerElement(value, 0, value.len, 0x30);
    if (sequence.end != value.len) return error.CertificateFieldHasInvalidLength;
    var index = sequence.start;
    while (index < sequence.end) {
        const oid = try expectDerElement(value, index, sequence.end, 0x06);
        const encoded = value[oid.start..oid.end];
        if (mem.eql(u8, encoded, oid_any_extended_key_usage)) result.any_auth = true;
        if (mem.eql(u8, encoded, oid_server_auth)) result.server_auth = true;
        if (mem.eql(u8, encoded, oid_client_auth)) result.client_auth = true;
        index = oid.end;
    }
}

fn parseNameConstraints(value: []const u8, critical: bool) !NameConstraints {
    const sequence = try expectDerElement(value, 0, value.len, 0x30);
    if (sequence.end != value.len) return error.CertificateFieldHasInvalidLength;

    var permitted: ?[]const u8 = null;
    var excluded: ?[]const u8 = null;
    var index = sequence.start;
    if (index < sequence.end) {
        const elem = try parseDerElement(value, index, sequence.end);
        if (elem.identifier == 0xa0) {
            permitted = value[elem.start..elem.end];
            index = elem.end;
        }
    }
    if (index < sequence.end) {
        const elem = try parseDerElement(value, index, sequence.end);
        if (elem.identifier == 0xa1) {
            excluded = value[elem.start..elem.end];
            index = elem.end;
        }
    }
    const permitted_empty = if (permitted) |subtrees| subtrees.len == 0 else true;
    const excluded_empty = if (excluded) |subtrees| subtrees.len == 0 else true;
    if (index != sequence.end or (permitted == null and excluded == null) or
        (permitted_empty and excluded_empty))
    {
        return error.CertificateFieldHasWrongDataType;
    }

    var unhandled = false;
    if (permitted) |subtrees| try validateConstraintSubtrees(subtrees, &unhandled);
    if (excluded) |subtrees| try validateConstraintSubtrees(subtrees, &unhandled);
    if (critical and unhandled) return error.CertificateUnhandledCriticalExtension;
    return .{ .permitted = permitted, .excluded = excluded };
}

fn validateConstraintSubtrees(subtrees: []const u8, unhandled: *bool) !void {
    var index: usize = 0;
    while (index < subtrees.len) {
        const subtree = try expectDerElement(subtrees, index, subtrees.len, 0x30);
        const base = try parseDerElement(subtrees, subtree.start, subtree.end);
        switch (base.identifier) {
            0x81, 0x82, 0x86 => {
                const constraint = subtrees[base.start..base.end];
                if (!isIa5String(constraint)) return error.CertificateFieldHasWrongDataType;
                if (base.identifier == 0x81 and mem.findScalar(u8, constraint, '@') != null) {
                    _ = parseMailbox(constraint) orelse return error.CertificateFieldHasWrongDataType;
                } else {
                    if (base.identifier == 0x86 and isIpAddress(constraint)) {
                        return error.CertificateFieldHasWrongDataType;
                    }
                    if (!domainNameValid(constraint, true)) return error.CertificateFieldHasWrongDataType;
                }
            },
            0x87 => try validateIpConstraint(subtrees[base.start..base.end]),
            else => unhandled.* = true,
        }
        // Like Go's crypto/x509 parser, ignore the optional minimum and maximum
        // fields after the GeneralSubtree base.
        index = subtree.end;
    }
}

fn isIa5String(value: []const u8) bool {
    for (value) |byte| if (byte >= 0x80) return false;
    return true;
}

fn domainNameValid(name: []const u8, constraint: bool) bool {
    if (name.len == 0) return true;
    if (name[name.len - 1] == '.') return false;
    var start: usize = @intFromBool(constraint and name[0] == '.');
    var label_start = start;
    while (start <= name.len) : (start += 1) {
        if (start < name.len and (name[start] < 33 or name[start] > 126)) return false;
        if (start == name.len or name[start] == '.') {
            if (start == label_start) return false;
            label_start = start + 1;
        }
    }
    return true;
}

fn validateIpConstraint(constraint: []const u8) !void {
    if (constraint.len != 8 and constraint.len != 32) return error.CertificateFieldHasWrongDataType;
    const half = constraint.len / 2;
    var saw_zero = false;
    for (constraint[half..]) |byte| {
        switch (byte) {
            0xff => if (saw_zero) return error.CertificateFieldHasWrongDataType,
            0x00 => saw_zero = true,
            0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe => {
                if (saw_zero) return error.CertificateFieldHasWrongDataType;
                saw_zero = true;
            },
            else => return error.CertificateFieldHasWrongDataType,
        }
    }
}

const Mailbox = struct {
    local: []const u8,
    domain: []const u8,
};

fn parseMailbox(value: []const u8) ?Mailbox {
    const at = mem.findScalar(u8, value, '@') orelse return null;
    if (at == 0 or at + 1 == value.len or mem.findScalar(u8, value[at + 1 ..], '@') != null) return null;
    const domain = value[at + 1 ..];
    if (!domainNameValid(domain, false)) return null;
    return .{ .local = value[0..at], .domain = domain };
}

fn isIpAddress(value: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(value, 0) catch return false;
    return true;
}

fn checkNameConstraints(constraints: NameConstraints, chain_below: []const Certificate) !void {
    for (chain_below) |certificate| {
        // Every certificate added to chain_below was parsed successfully by
        // parseCertificate.
        const parsed = certificate.parse() catch unreachable;
        const san = parsed.subjectAltName();
        if (san.len == 0) continue;
        const names = try expectDerElement(san, 0, san.len, 0x30);
        if (names.end != san.len) return error.CertificateFieldHasInvalidLength;
        var index = names.start;
        while (index < names.end) {
            const name = try parseDerElement(san, index, names.end);
            switch (name.identifier) {
                0x81, 0x82, 0x86, 0x87 => try checkConstrainedName(
                    constraints,
                    name.identifier,
                    san[name.start..name.end],
                ),
                else => {},
            }
            index = name.end;
        }
    }
}

fn checkConstrainedName(constraints: NameConstraints, tag: u8, name: []const u8) !void {
    if (tag != 0x87) {
        if (!isIa5String(name)) return error.CertificateFieldHasWrongDataType;
        switch (tag) {
            0x81 => _ = parseMailbox(name) orelse return error.CertificateFieldHasWrongDataType,
            0x82 => if (!domainNameValid(name, false)) return error.CertificateFieldHasWrongDataType,
            0x86 => {},
            else => unreachable,
        }
    } else if (name.len != 4 and name.len != 16) {
        return error.CertificateFieldHasWrongDataType;
    }

    if (constraints.permitted) |subtrees| {
        const any, const matched = try matchConstraintSubtrees(subtrees, tag, name, false);
        if (any and !matched) return error.CertificateNameConstraintViolation;
    }
    if (constraints.excluded) |subtrees| {
        _, const matched = try matchConstraintSubtrees(subtrees, tag, name, true);
        if (matched) return error.CertificateNameConstraintViolation;
    }
}

fn matchConstraintSubtrees(
    subtrees: []const u8,
    tag: u8,
    name: []const u8,
    excluded: bool,
) !struct { bool, bool } {
    var any = false;
    var matched = false;
    var index: usize = 0;
    while (index < subtrees.len) {
        const subtree = try expectDerElement(subtrees, index, subtrees.len, 0x30);
        const base = try parseDerElement(subtrees, subtree.start, subtree.end);
        if (base.identifier == tag) {
            any = true;
            if (try nameMatchesConstraint(
                tag,
                subtrees[base.start..base.end],
                name,
                excluded,
            )) matched = true;
        }
        index = subtree.end;
    }
    return .{ any, matched };
}

fn nameMatchesConstraint(tag: u8, constraint: []const u8, name: []const u8, excluded: bool) !bool {
    return switch (tag) {
        0x81 => emailMatchesConstraint(constraint, name),
        0x82 => domainMatchesConstraint(constraint, name) or
            (excluded and wildcardCoversConstraint(name, constraint)),
        0x86 => domainMatchesConstraint(constraint, try uriHost(name)),
        0x87 => ipMatchesConstraint(constraint, name),
        else => unreachable,
    };
}

fn domainMatchesConstraint(constraint: []const u8, name: []const u8) bool {
    if (constraint.len == 0) return true;
    if (name.len < constraint.len or
        !std.ascii.eqlIgnoreCase(name[name.len - constraint.len ..], constraint)) return false;
    if (constraint[0] == '.') return name.len > constraint.len;
    return name.len == constraint.len or name[name.len - constraint.len - 1] == '.';
}

fn wildcardCoversConstraint(name: []const u8, constraint: []const u8) bool {
    // Deliberately stricter than Go: a wildcard SAN can cover an excluded
    // concrete subtree even though the labels do not compare literally.
    if (!mem.startsWith(u8, name, "*.")) return false;
    const dot = mem.findScalar(u8, constraint, '.') orelse return false;
    return std.ascii.eqlIgnoreCase(name[1..], constraint[dot..]);
}

fn emailMatchesConstraint(constraint: []const u8, email: []const u8) bool {
    const mailbox = parseMailbox(email) orelse return false;
    if (parseMailbox(constraint)) |exact| {
        return mem.eql(u8, mailbox.local, exact.local) and
            std.ascii.eqlIgnoreCase(mailbox.domain, exact.domain);
    }
    return domainMatchesConstraint(constraint, mailbox.domain);
}

fn uriHost(uri_text: []const u8) ![]const u8 {
    const uri = std.Uri.parse(uri_text) catch return error.CertificateFieldHasWrongDataType;
    const component = uri.host orelse return error.CertificateNameConstraintViolation;
    const host = switch (component) {
        .raw => |host| host,
        .percent_encoded => |host| blk: {
            if (mem.findScalar(u8, host, '%') != null) {
                return error.CertificateFieldHasWrongDataType;
            }
            break :blk host;
        },
    };

    if (host.len == 0) return error.CertificateNameConstraintViolation;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        // std.Uri retains brackets around IPv6 literals, while IpAddress.parse
        // expects the unbracketed address.
        if (isIpAddress(host[1 .. host.len - 1])) {
            return error.CertificateNameConstraintViolation;
        }
        // Deliberately fail closed for malformed bracketed hosts. Go strips
        // the brackets and compares non-IP contents as a domain.
        return error.CertificateFieldHasWrongDataType;
    }
    if (isIpAddress(host)) return error.CertificateNameConstraintViolation;
    if (!domainNameValid(host, false)) return error.CertificateFieldHasWrongDataType;
    return host;
}

fn ipMatchesConstraint(constraint: []const u8, ip: []const u8) bool {
    const half = constraint.len / 2;
    if (ip.len != half) return false;
    for (ip, constraint[0..half], constraint[half..]) |byte, network, mask| {
        if (byte & mask != network & mask) return false;
    }
    return true;
}

test "X.509 booleans accept Go-compatible explicit false" {
    const extension_der = [_]u8{
        0x30, 0x0c,
        0x06, 0x03,
        0x55, 0x1d,
        0x13, 0x01,
        0x01, 0x00,
        0x04, 0x02,
        0x30, 0x00,
    };
    const extension = try parseExtension(&extension_der, 0, extension_der.len);
    try testing.expect(!extension.critical);

    var constraints: CertificateConstraints = .{};
    try parseBasicConstraints(&.{ 0x30, 0x03, 0x01, 0x01, 0x00 }, &constraints);
    try testing.expect(!constraints.is_ca);

    try testing.expect(!try parseKeyCertSign(&.{ 0x03, 0x01, 0x00 }));

    const duplicate_extensions = extension_der ++ extension_der;
    try testing.expectError(
        error.CertificateDuplicateExtension,
        validateUniqueExtensions(&duplicate_extensions, .{
            .identifier = 0x30,
            .start = 0,
            .end = duplicate_extensions.len,
        }),
    );
}

test "name constraints follow Go critical and matching behavior" {
    const io = testing.io;
    var leaf = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/valid_leaf.pem"));
    defer leaf.deinit(testing.allocator);
    const chain = [_]Certificate{.{ .buffer = leaf.bytes.items, .index = 0 }};

    // permittedSubtrees: dNSName valid.test
    const permitted_der = [_]u8{ 0x30, 0x10, 0xa0, 0x0e, 0x30, 0x0c, 0x82, 0x0a } ++ "valid.test".*;
    const permitted = try parseNameConstraints(&permitted_der, true);
    try checkNameConstraints(permitted, &chain);

    // excludedSubtrees: dNSName valid.test
    const excluded_der = [_]u8{ 0x30, 0x10, 0xa1, 0x0e, 0x30, 0x0c, 0x82, 0x0a } ++ "valid.test".*;
    const excluded = try parseNameConstraints(&excluded_der, true);
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        checkNameConstraints(excluded, &chain),
    );

    // directoryName is unsupported: critical rejects, non-critical ignores it.
    const unsupported = [_]u8{ 0x30, 0x06, 0xa0, 0x04, 0x30, 0x02, 0x84, 0x00 };
    try testing.expectError(
        error.CertificateUnhandledCriticalExtension,
        parseNameConstraints(&unsupported, true),
    );
    _ = try parseNameConstraints(&unsupported, false);

    try testing.expect(try nameMatchesConstraint(0x81, "example.com", "user@example.com", false));
    try testing.expect(try nameMatchesConstraint(0x82, "foo.example.com", "*.example.com", true));
    try testing.expect(try nameMatchesConstraint(0x86, ".example.com", "https://www.example.com/path", false));
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        nameMatchesConstraint(0x86, ".example.com", "https://[::1]/path", false),
    );
    try testing.expectError(
        error.CertificateFieldHasWrongDataType,
        nameMatchesConstraint(0x86, ".example.com", "https://..example.com/path", false),
    );
    try testing.expect(try nameMatchesConstraint(
        0x87,
        &.{ 10, 0, 0, 0, 255, 0, 0, 0 },
        &.{ 10, 2, 3, 4 },
        false,
    ));
}

fn testParseCertificateChain(
    root_ca: Certificate.Bundle,
    chain: []const []const u8,
    host: []const u8,
    purpose: CertificateParser.Purpose,
    now_sec: i64,
) !void {
    var message_buf: [4096]u8 = undefined;
    var writer = record.Writer.init(&message_buf);
    var certificates_len: usize = 0;
    for (chain) |certificate| certificates_len += 3 + certificate.len;
    try writer.int(u24, certificates_len);
    for (chain) |certificate| {
        try writer.int(u24, certificate.len);
        try writer.slice(certificate);
    }

    var decoder: record.Decoder = .init(.handshake, writer.buffered());
    var parser: CertificateParser = .{
        .root_ca = root_ca,
        .host = host,
        .purpose = purpose,
        .now_sec = now_sec,
    };
    try parser.parseCertificate(&decoder, .tls_1_2);
}

test "CertificateParser accepts an authorized CA intermediate" {
    const io = testing.io;
    const now_sec = 1_800_000_000;

    var root = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/root.pem"));
    defer root.deinit(testing.allocator);
    var intermediate = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/intermediate.pem"));
    defer intermediate.deinit(testing.allocator);
    var leaf = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/valid_leaf.pem"));
    defer leaf.deinit(testing.allocator);

    try testParseCertificateChain(
        root,
        &.{ leaf.bytes.items, intermediate.bytes.items },
        "valid.test",
        .server_auth,
        now_sec,
    );

    const intermediate_parsed = try (Certificate{ .buffer = intermediate.bytes.items, .index = 0 }).parse();
    try validateIssuer(intermediate_parsed, .server_auth, 0, false, &.{});
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        validateIssuer(intermediate_parsed, .server_auth, 1, false, &.{}),
    );

    const leaf_parsed = try (Certificate{ .buffer = leaf.bytes.items, .index = 0 }).parse();
    try validatePurpose(leaf_parsed, .server_auth);
    try testing.expectError(
        error.CertificateIncompatibleExtendedKeyUsage,
        validatePurpose(leaf_parsed, .client_auth),
    );
}

test "CertificateParser rejects a non-CA certificate used as an issuer" {
    const io = testing.io;
    const now_sec = 1_800_000_000;

    var root = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/root.pem"));
    defer root.deinit(testing.allocator);
    var attacker = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/attacker_leaf.pem"));
    defer attacker.deinit(testing.allocator);
    var forged = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/forged_leaf.pem"));
    defer forged.deinit(testing.allocator);

    // The standard library's low-level primitive accepts both signatures. The
    // TLS path validator must additionally reject attacker as an unauthorized
    // issuer because its Basic Constraints say CA:FALSE.
    const forged_parsed = try (Certificate{ .buffer = forged.bytes.items, .index = 0 }).parse();
    const attacker_parsed = try (Certificate{ .buffer = attacker.bytes.items, .index = 0 }).parse();
    const root_parsed = try (Certificate{ .buffer = root.bytes.items, .index = 0 }).parse();
    try forged_parsed.verify(attacker_parsed, now_sec);
    try attacker_parsed.verify(root_parsed, now_sec);

    try testing.expectError(
        error.CertificateNotAuthorizedToSign,
        testParseCertificateChain(
            root,
            &.{ forged.bytes.items, attacker.bytes.items },
            "victim.test",
            .server_auth,
            now_sec,
        ),
    );
}

test "CertificateParser accepts an exactly pinned self-signed leaf" {
    const io = testing.io;
    const now_sec = 1_800_000_000;
    var pinned = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/pinned_leaf.pem"));
    defer pinned.deinit(testing.allocator);

    try testParseCertificateChain(
        pinned,
        &.{pinned.bytes.items},
        "pinned.test",
        .server_auth,
        now_sec,
    );
}

test "CertificateParser enforces intermediate EKU and path length" {
    const io = testing.io;
    const now_sec = 1_800_000_000;
    var root = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/root.pem"));
    defer root.deinit(testing.allocator);

    var eku_intermediate = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/eku_intermediate.pem"));
    defer eku_intermediate.deinit(testing.allocator);
    var eku_leaf = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/eku_leaf.pem"));
    defer eku_leaf.deinit(testing.allocator);
    try testing.expectError(
        error.CertificateIncompatibleExtendedKeyUsage,
        testParseCertificateChain(
            root,
            &.{ eku_leaf.bytes.items, eku_intermediate.bytes.items },
            "eku.test",
            .server_auth,
            now_sec,
        ),
    );

    var intermediate = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/intermediate.pem"));
    defer intermediate.deinit(testing.allocator);
    var subordinate = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/subordinate_intermediate.pem"));
    defer subordinate.deinit(testing.allocator);
    var path_leaf = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/path_leaf.pem"));
    defer path_leaf.deinit(testing.allocator);
    try testing.expectError(
        error.CertificatePathLengthExceeded,
        testParseCertificateChain(
            root,
            &.{ path_leaf.bytes.items, subordinate.bytes.items, intermediate.bytes.items },
            "path.test",
            .server_auth,
            now_sec,
        ),
    );
}

test "CertificateParser enforces DNS name constraints end to end" {
    const io = testing.io;
    const now_sec = 1_800_000_000;
    var root = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/root.pem"));
    defer root.deinit(testing.allocator);
    var constrained = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/constrained_intermediate.pem"));
    defer constrained.deinit(testing.allocator);
    var allowed = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/allowed_leaf.pem"));
    defer allowed.deinit(testing.allocator);
    var denied = try cert.fromSlice(testing.allocator, io, @embedFile("testdata/x509_path/denied_leaf.pem"));
    defer denied.deinit(testing.allocator);

    try testParseCertificateChain(
        root,
        &.{ allowed.bytes.items, constrained.bytes.items },
        "service.allowed.test",
        .server_auth,
        now_sec,
    );
    try testing.expectError(
        error.CertificateNameConstraintViolation,
        testParseCertificateChain(
            root,
            &.{ denied.bytes.items, constrained.bytes.items },
            "x.blocked.allowed.test",
            .server_auth,
            now_sec,
        ),
    );
}

fn SchemeHash(comptime scheme: proto.SignatureScheme) type {
    const Sha256 = crypto.hash.sha2.Sha256;
    const Sha384 = crypto.hash.sha2.Sha384;
    const Sha512 = crypto.hash.sha2.Sha512;

    return switch (scheme) {
        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
        .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
        .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
        else => @compileError("bad scheme"),
    };
}

pub fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (buf.len < data.len) {
        return error.BufferUndersize;
    }
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

pub fn dupeMin(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

pub const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    ml_kem768: MLKem768.KeyPair = undefined,

    secp256r1_pk_buf: [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //65 bytes
    secp384r1_pk_buf: [EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //97
    ml_kem768_pk_buf: [MLKem768.PublicKey.encoded_length + X25519.public_length]u8 = undefined, // 1216
    shared_key_buf: [64]u8 = undefined,

    pub const seed_len = 32 + 32 + 48 + 64 + 64;

    pub fn init(seed: [seed_len]u8, named_groups: []const proto.NamedGroup) !DhKeyPair {
        var kp: DhKeyPair = .{};
        for (named_groups) |ng|
            switch (ng) {
                .x25519 => kp.x25519_kp = try X25519.KeyPair.generateDeterministic(seed[0..][0..X25519.seed_length].*),
                .secp256r1 => kp.secp256r1_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed[32..][0..EcdsaP256Sha256.KeyPair.seed_length].*),
                .secp384r1 => kp.secp384r1_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic(seed[32 + 32 ..][0..EcdsaP384Sha384.KeyPair.seed_length].*),
                .x25519_ml_kem768 => kp.ml_kem768 = try MLKem768.KeyPair.generateDeterministic(seed[32 + 32 + 48 + 64 ..][0..MLKem768.seed_length].*),
                else => return error.TlsIllegalParameter,
            };
        return kp;
    }

    // x25519: 32,  secp256r1: 32, secp384r1: 48, x25519_ml_kem768: 64
    pub fn sharedKey(self: *DhKeyPair, named_group: proto.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                self.shared_key_buf[0..32].* = try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                );
                return self.shared_key_buf[0..32];
            },
            .secp256r1 => {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..32].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..32];
            },
            .secp384r1 => {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..48].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..48];
            },
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = self.ml_kem768.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(self.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                self.shared_key_buf = (hsk ++ xsk);
                return &self.shared_key_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65, 97 or 1216 bytes ml_kem
    pub fn publicKey(self: *DhKeyPair, named_group: proto.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => {
                self.secp256r1_pk_buf = self.secp256r1_kp.public_key.toUncompressedSec1();
                return &self.secp256r1_pk_buf;
            },
            .secp384r1 => {
                self.secp384r1_pk_buf = self.secp384r1_kp.public_key.toUncompressedSec1();
                return &self.secp384r1_pk_buf;
            },
            .x25519_ml_kem768 => {
                self.ml_kem768_pk_buf = self.ml_kem768.public_key.toBytes() ++ self.x25519_kp.public_key;
                return &self.ml_kem768_pk_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }
};

const testing = std.testing;
const testu = @import("testu.zig");

test "DhKeyPair.x25519" {
    var seed: [DhKeyPair.seed_len]u8 = undefined;
    testu.fill(&seed);
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes(
        \\ F1 67 FB 4A 49 B2 91 77  08 29 45 A1 F7 08 5A 21
        \\ AF FE 9E 78 C2 03 9B 81  92 40 72 73 74 7A 46 1E
    );
    var kp = try DhKeyPair.init(seed, &.{.x25519});
    try testing.expectEqualSlices(u8, expected, try kp.sharedKey(.x25519, server_pub_key));
}

test "CertificateBuilder.makeCertificateVerify ed25519" {
    // Bundle is unused by makeCertificateVerify (it only signs the
    // transcript with cert_key_pair.key), so an empty one is fine here.
    var cert_key_pair = CertKeyPair{
        .bundle = .{ .map = .{}, .bytes = .{ .items = &.{}, .capacity = 0 } },
        .key = try PrivateKey.parsePem(@embedFile("testdata/ed25519_private_key.pem")),
    };
    var transcript = Transcript{};
    var prng = std.Random.DefaultPrng.init(0);
    const cb = CertificateBuilder{
        .cert_key_pair = &cert_key_pair,
        .transcript = &transcript,
        .side = .server,
        .rng = prng.random(),
    };

    var buf: [256]u8 = undefined;
    var w = record.Writer.init(&buf);
    try cb.makeCertificateVerify(&w);

    // Decode the message as a peer would off the wire and check the
    // signature verifies against the key's own public key.
    var d = record.Decoder.init(.handshake, w.buffered()[4..]); // skip 1-byte type + u24 length header
    const signature_scheme = try d.decode(proto.SignatureScheme);
    try testing.expectEqual(.ed25519, signature_scheme);
    const signature = try d.slice(try d.decode(u16));

    const Eddsa = crypto.sign.Ed25519;
    const sig = Eddsa.Signature.fromBytes(signature[0..Eddsa.Signature.encoded_length].*);
    try sig.verify(transcript.serverCertificateVerify(), cert_key_pair.key.key.ed25519.public_key);
}

/// Signs an empty server transcript with `key_pem` and returns the decoded
/// CertificateVerify body, so a test can check the signature the peer sees.
fn testCertificateVerify(
    key_pem: []const u8,
    buf: []u8,
    transcript: *Transcript,
) !struct { proto.SignatureScheme, []const u8 } {
    // Bundle is unused by makeCertificateVerify (it only signs the
    // transcript with cert_key_pair.key), so an empty one is fine here.
    const key = try PrivateKey.parsePem(key_pem);
    var cert_key_pair = CertKeyPair{
        .bundle = .{ .map = .{}, .bytes = .{ .items = &.{}, .capacity = 0 } },
        .key = key,
        // The ecdsa branch signs with this cached pair, not with `key`.
        .ecdsa_key_pair = try CertKeyPair.EcdsaKeyPair.init(key),
    };
    var prng = std.Random.DefaultPrng.init(0);
    const cb = CertificateBuilder{
        .cert_key_pair = &cert_key_pair,
        .transcript = transcript,
        .side = .server,
        .rng = prng.random(),
    };

    var w = record.Writer.init(buf);
    try cb.makeCertificateVerify(&w);

    // Decode as a peer would off the wire; skip 1-byte type + u24 length.
    var d = record.Decoder.init(.handshake, w.buffered()[4..]);
    const scheme = try d.decode(proto.SignatureScheme);
    return .{ scheme, try d.slice(try d.decode(u16)) };
}

test "CertificateBuilder.makeCertificateVerify ecdsa" {
    var transcript = Transcript{};
    var buf: [256]u8 = undefined;
    const scheme, const signature = try testCertificateVerify(
        @embedFile("testdata/ec_prime256v1_private_key.pem"),
        &buf,
        &transcript,
    );
    try testing.expectEqual(.ecdsa_secp256r1_sha256, scheme);

    const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
    const pk = try PrivateKey.parsePem(@embedFile("testdata/ec_prime256v1_private_key.pem"));
    const secret_key = try Ecdsa.SecretKey.fromBytes(
        pk.key.ecdsa[0..Ecdsa.SecretKey.encoded_length].*,
    );
    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
    const sig = try Ecdsa.Signature.fromDer(signature);
    try sig.verify(transcript.serverCertificateVerify(), key_pair.public_key);
}

test "CertificateBuilder.makeCertificateVerify rsa" {
    var transcript = Transcript{};
    var buf: [1024]u8 = undefined;
    const scheme, const signature = try testCertificateVerify(
        @embedFile("testdata/rsa_private_key.pem"),
        &buf,
        &transcript,
    );
    try testing.expectEqual(.rsa_pss_rsae_sha256, scheme);

    const pk = try PrivateKey.parsePem(@embedFile("testdata/rsa_private_key.pem"));
    const Pss = rsa.Pss(crypto.hash.sha2.Sha256);
    const sig = Pss.Signature{ .bytes = signature };
    try sig.verify(transcript.serverCertificateVerify(), pk.key.rsa.public, null);
}
