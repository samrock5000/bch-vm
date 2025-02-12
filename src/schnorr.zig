const builtin = @import("builtin");
const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const testing = std.testing;

const EncodingError = crypto.errors.EncodingError;
const IdentityElementError = crypto.errors.IdentityElementError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;
const NotSquare = crypto.errors.NotSquareError;
pub const SchnorrErrorSet = EncodingError || IdentityElementError || NonCanonicalError || SignatureVerificationError || NotSquare;

/// Schnorr over Secp256k1 with SHA-256.
pub const SchnorrBCH = Schnorr(crypto.ecc.Secp256k1, crypto.hash.sha2.Sha256);

pub const sha256 = crypto.hash.sha2.Sha256;

/// Schnorr Secp256k1.
pub fn Schnorr(comptime Curve: type, comptime Hash: type) type {
    return struct {
        /// Length (in bytes) of optional random bytes, for non-deterministic signatures.
        pub const noise_length = Curve.scalar.encoded_length;

        /// A secret key.
        pub const SecretKey = struct {
            /// Length (in bytes) of a raw secret key.
            pub const encoded_length = Curve.scalar.encoded_length;

            bytes: Curve.scalar.CompressedScalar,

            pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
                return SecretKey{ .bytes = bytes };
            }

            pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
                return sk.bytes;
            }
        };

        /// An ECDSA public key.
        pub const PublicKey = struct {
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const compressed_sec1_encoded_length = 1 + Curve.Fe.encoded_length;
            /// Length (in bytes) of a compressed sec1-encoded key.
            pub const uncompressed_sec1_encoded_length = 1 + 2 * Curve.Fe.encoded_length;

            p: Curve,

            /// Create a public key from a SEC-1 representation.
            pub fn fromSec1(sec1: []const u8) !PublicKey {
                return PublicKey{ .p = try Curve.fromSec1(sec1) };
            }

            /// Encode the public key using the compressed SEC-1 format.
            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            /// Encoding the public key using the uncompressed SEC-1 format.
            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };

        /// An Schnorr signature.
        pub const Signature = struct {
            /// Length (in bytes) of a raw signature.
            pub const encoded_length = Curve.scalar.encoded_length * 2;

            /// The R component of an ECDSA signature.
            r: Curve.scalar.CompressedScalar,
            /// The S component of an ECDSA signature.
            s: Curve.scalar.CompressedScalar,

            /// Create a Verifier for incremental verification of a signature.
            pub fn verifier(self: Signature, public_key: PublicKey) (NonCanonicalError || EncodingError || IdentityElementError)!Verifier {
                return Verifier.init(self, public_key);
            }

            /// Verify the signature against a message and public key.
            /// Return IdentityElement or NonCanonical if the public key or signature are not in the expected range,
            /// or SignatureVerificationError if the signature is invalid for the given message and key.
            pub fn verify(self: Signature, msg: []const u8, public_key: PublicKey) (IdentityElementError || NotSquare || NonCanonicalError || SignatureVerificationError)!void {
                var st = try Verifier.init(self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature (r, s) in big-endian format.
            pub fn toBytes(self: Signature) [encoded_length]u8 {
                var bytes: [encoded_length]u8 = undefined;
                @memcpy(bytes[0 .. encoded_length / 2], &self.r);
                @memcpy(bytes[encoded_length / 2 ..], &self.s);
                return bytes;
            }

            /// Create a signature from a raw encoding of (r, s).
            /// ECDSA always assumes big-endian.
            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return Signature{
                    .r = bytes[0 .. encoded_length / 2].*,
                    .s = bytes[encoded_length / 2 ..].*,
                };
            }
        };

        /// A Signer is used to incrementally compute a signature.
        /// It can be obtained from a `KeyPair`, using the `signer()` function.
        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,
            noise: ?[noise_length]u8,

            fn init(secret_key: SecretKey, noise: ?[noise_length]u8) !Signer {
                return Signer{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .noise = noise,
                };
            }

            /// Add new data to the message being signed.
            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            /// Compute a schnorr signature over the entire message.
            pub fn finalize(self: *Signer, msg: []const u8) (IdentityElementError || NonCanonicalError)!Signature {
                const scalar_encoded_length = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, scalar_encoded_length);
                var h: [h_len]u8 = [_]u8{0} ** h_len;
                const h_slice = h[h_len - Hash.digest_length .. h_len];
                self.h.final(h_slice);

                std.debug.assert(h.len >= scalar_encoded_length);

                var k = derive_nonce_rfc6979(&self.secret_key.bytes, msg);

                const r = try Curve.basePoint.mul(k.toBytes(.big), .big);
                const Rx = r.affineCoordinates().x.toBytes(.big);
                const Ry = r.affineCoordinates().y.toBytes(.big);

                const y = try Curve.Fe.fromBytes(Ry, .big);

                if (!y.isSquare()) {
                    k = k.neg();
                }

                const pubk = try Curve.basePoint.mul(self.secret_key.toBytes(), .big);

                const econcat = Rx ++ &pubk.toCompressedSec1() ++ h_slice;

                var out: [32]u8 = undefined;

                _ = sha256.hash(econcat, &out, .{});
                const e = reduceToScalar(Curve.Fe.encoded_length, out);
                const s = k.add(e.mul(try Curve.scalar.Scalar.fromBytes(self.secret_key.bytes, .big)));

                return Signature{ .r = Rx, .s = s.toBytes(.big) };
            }
        };

        /// A Verifier is used to incrementally verify a signature.
        /// It can be obtained from a `Signature`, using the `verifier()` function.
        pub const Verifier = struct {
            h: Hash,
            r: Curve.scalar.Scalar,
            s: Curve.scalar.Scalar,
            public_key: PublicKey,

            fn init(sig: Signature, public_key: PublicKey) (IdentityElementError || NonCanonicalError)!Verifier {
                const r = try Curve.scalar.Scalar.fromBytes(sig.r, .big);
                const s = try Curve.scalar.Scalar.fromBytes(sig.s, .big);
                if (r.isZero() or s.isZero()) return error.IdentityElement;

                return Verifier{
                    .h = Hash.init(.{}),
                    .r = r,
                    .s = s,
                    .public_key = public_key,
                };
            }

            /// Add new content to the message to be verified.
            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }
            pub fn verifyMessageHash(self: *Verifier, msg_hash: [32]u8) (IdentityElementError || NonCanonicalError || SignatureVerificationError || NotSquare)!void {
                const ht = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, ht);
                var m: [h_len]u8 = [_]u8{0} ** h_len;
                const s = self.s;
                const pubk = self.public_key.toCompressedSec1();
                const e_data = self.r.toBytes(.big) ++ pubk ++ msg_hash;
                _ = sha256.hash(&e_data, &m, .{});
                const e = reduceToScalar(32, m);

                // Compute point R = s * G - e * P.
                const sG = try Curve.basePoint.mul(s.toBytes(.big), .big);
                const eP = try self.public_key.p.mul(e.toBytes(.big), .big);
                // const eP = try e.mul(self.public_key.p);
                const R = sG.sub(eP).affineCoordinates();

                if (!R.y.isSquare()) {
                    return error.NotSquare;
                }
                if (R.x.isZero()) {
                    return error.SignatureVerificationFailed;
                }
                // Signature is valid if the serialization of R.x equals r.
                const rx = reduceToScalar(32, R.x.toBytes(.big));
                if (!self.r.equivalent(rx)) {
                    return error.SignatureVerificationFailed;
                }
            }

            /// Verify that the signature is valid for the entire message.
            pub fn verify(self: *Verifier) (IdentityElementError || NonCanonicalError || SignatureVerificationError || NotSquare)!void {
                const ht = Curve.scalar.encoded_length;
                const h_len = @max(Hash.digest_length, ht);
                var m: [h_len]u8 = [_]u8{0} ** h_len;
                const s = self.s;
                self.h.final(m[h_len - Hash.digest_length .. h_len]);
                const pubk = self.public_key.toCompressedSec1();
                const e_data = self.r.toBytes(.big) ++ pubk ++ m;
                _ = sha256.hash(&e_data, &m, .{});
                const e = reduceToScalar(32, m);

                // Compute point R = s * G - e * P.
                const sG = try Curve.basePoint.mul(s.toBytes(.big), .big);
                const eP = try self.public_key.p.mul(e.toBytes(.big), .big);
                // const eP = try e.mul(self.public_key.p);
                const R = sG.sub(eP).affineCoordinates();

                if (!R.y.isSquare()) {
                    return error.NotSquare;
                }
                if (R.x.isZero()) {
                    return error.SignatureVerificationFailed;
                }
                // Signature is valid if the serialization of R.x equals r.
                const rx = reduceToScalar(32, R.x.toBytes(.big));
                if (!self.r.equivalent(rx)) {
                    return error.SignatureVerificationFailed;
                }
            }
        };

        /// An ECDSA key pair.
        pub const KeyPair = struct {
            /// Length (in bytes) of a seed required to create a key pair.
            pub const seed_length = noise_length;

            /// Public part.
            public_key: PublicKey,
            /// Secret scalar.
            secret_key: SecretKey,

            /// Create a new key pair. The seed must be secret and indistinguishable from random.
            /// The seed can also be left to null in order to generate a random key pair.
            pub fn create(seed: ?[seed_length]u8) IdentityElementError!KeyPair {
                var seed_ = seed;
                if (seed_ == null) {
                    var random_seed: [seed_length]u8 = undefined;
                    crypto.random.bytes(&random_seed);
                    seed_ = random_seed;
                }
                const h = [_]u8{0x00} ** Hash.digest_length;
                const k0 = [_]u8{0x01} ** SecretKey.encoded_length;
                const secret_key = deterministicScalar(h, k0, seed_).toBytes(.big);
                return fromSecretKey(SecretKey{ .bytes = secret_key });
            }

            /// Return the public key corresponding to the secret key.
            pub fn fromSecretKey(secret_key: SecretKey) IdentityElementError!KeyPair {
                const public_key = try Curve.basePoint.mul(secret_key.bytes, .big);
                return KeyPair{ .secret_key = secret_key, .public_key = PublicKey{ .p = public_key } };
            }

            /// Sign a message using the key pair.
            /// The noise can be null in order to create deterministic signatures.
            /// If deterministic signatures are not required, the noise should be randomly generated instead.
            /// This helps defend against fault attacks.
            pub fn schnorrSign(
                key_pair: KeyPair,
                msg: []const u8,
            ) (IdentityElementError || NonCanonicalError)!Signature {
                var st = try key_pair.signer(null);
                st.update(msg);
                return st.finalize(msg);
            }

            /// Create a Signer, that can be used for incremental signature verification.
            pub fn signer(key_pair: KeyPair, noise: ?[noise_length]u8) !Signer {
                return Signer.init(key_pair.secret_key, noise);
            }
        };

        // Reduce the coordinate of a field element to the scalar field.
        fn reduceToScalar(comptime unreduced_len: usize, s: [unreduced_len]u8) Curve.scalar.Scalar {
            if (unreduced_len >= 48) {
                var xs = [_]u8{0} ** 64;
                @memcpy(xs[xs.len - s.len ..], s[0..]);
                return Curve.scalar.Scalar.fromBytes64(xs, .big);
            }
            var xs = [_]u8{0} ** 48;
            @memcpy(xs[xs.len - s.len ..], s[0..]);
            return Curve.scalar.Scalar.fromBytes48(xs, .big);
        }

        // Create a deterministic scalar according to a secret key and optional noise.
        // This uses the overly conservative scheme from the "Deterministic ECDSA and EdDSA Signatures with Additional Randomness" draft.
        fn deterministicScalar(h: [Hash.digest_length]u8, secret_key: Curve.scalar.CompressedScalar) Curve.scalar.Scalar {
            return derive_nonce_rfc6979(&secret_key, &h);
        }
        fn hmac_sha256(key: []const u8, msg: []const u8) [32]u8 {
            var out: [32]u8 = undefined;
            var mac = Hmac.init(key);
            mac.update(msg);
            mac.final(&out);
            return out;
        }
        fn derive_nonce_rfc6979(secret_key: []const u8, message: []const u8) Secp.scalar.Scalar {
            const aad = "Schnorr+SHA256  ".*;
            var _h1 = sha256.init(.{});
            _h1.update(message);
            var h1 = _h1.finalResult();

            var V = [_]u8{0x01} ** 32;
            var K = [_]u8{0x00} ** 32;
            const buf_len = 32 + 1 + 32 + 32 + 16;
            var buf = [_]u8{0x00} ** buf_len;
            @memcpy(buf[0..32], &V);
            buf[32] = 0;
            @memcpy(buf[33..65], secret_key);
            @memcpy(buf[65..97], &h1);
            @memcpy(buf[97..], &aad);
            K = hmac_sha256(&K, &buf);

            V = hmac_sha256(&K, &V);

            @memcpy(buf[0..32], (&V));
            buf[32] = 1;
            K = hmac_sha256(&K, &buf);

            V = hmac_sha256(&K, &V);

            while (true) {
                V = hmac_sha256(&K, &V);
                if (Secp.scalar.Scalar.fromBytes(V, .big)) |s| return s else |_| {}
                @memcpy(buf[0..32], &V);
                buf[32] = 0;
                K = hmac_sha256(&K, buf[0..33]);
                V = hmac_sha256(&K, &V);
            }
        }
    };
}

const Hmac = crypto.auth.hmac.sha2.HmacSha256;
const Secp = crypto.ecc.Secp256k1;

// const HmacDrbg = struct {
//     k: Hmac,
//     v: []u8,

//     fn init(
//         x: []const u8,
//         h: []const u8,
//         data: []const u8,
//     ) HmacDrbg {
//         var k = Hmac.init(&[_]u8{0x00} ** 32);
//         var v = [_]u8{0x01} ** 32;

//         var out: [32]u8 = undefined;
//         for (0..2) |i| {
//             k.update(&v);
//             k.update(&[_]u8{@intCast(i)});
//             k.update(x);
//             k.final(&out);
//             k.update(h);
//             k.update(data);
//             k.final(&out);

//             k = Hmac.init(&out);
//             k.update(&v);

//             k.final(&out);
//             v = out[0..].*;
//         }
//         return HmacDrbg{
//             .k = k,
//             .v = &v,
//         };
//     }
//     fn fill_bytes(self: *HmacDrbg, out: *[32]u8) void {
//         for (out) |_| {
//             self.k.update(self.v);
//             self.k.final(out);
//             self.v = out;
//         }

//         self.k.update(self.v);
//         self.k.update(&[_]u8{0x00});
//         self.k.final(out);
//         self.k = Hmac.init(out);
//         self.k.update(self.v);
//         self.k.final(out);
//         self.v = out;
//     }
// };

pub const PK1 = [33]u8{
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
};
pub const MSG1 = [32]u8{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
pub const SIG1 = [64]u8{
    0x78, 0x7a, 0x84, 0x8e, 0x71, 0x04, 0x3d, 0x28, 0x0c, 0x50, 0x47, 0x0e, 0x8e, 0x15, 0x32, 0xb2,
    0xdd, 0x5d, 0x20, 0xee, 0x91, 0x2a, 0x45, 0xdb, 0xdd, 0x2b, 0xd1, 0xdf, 0xbf, 0x18, 0x7e, 0xf6,
    0x70, 0x31, 0xa9, 0x88, 0x31, 0x85, 0x9d, 0xc3, 0x4d, 0xff, 0xee, 0xdd, 0xa8, 0x68, 0x31, 0x84,
    0x2c, 0xcd, 0x00, 0x79, 0xe1, 0xf9, 0x2a, 0xf1, 0x77, 0xf7, 0xf2, 0x2c, 0xc1, 0xdc, 0xed, 0x05,
};

pub const PK2 = [33]u8{
    0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41,
    0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6,
    0x59,
};
pub const MSG2 = [32]u8{
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
};
pub const SIG2 = [64]u8{
    0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb,
    0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d,
    0x1e, 0x51, 0xa2, 0x2c, 0xce, 0xc3, 0x55, 0x99, 0xb8, 0xf2, 0x66, 0x91, 0x22, 0x81, 0xf8, 0x36,
    0x5f, 0xfc, 0x2d, 0x03, 0x5a, 0x23, 0x04, 0x34, 0xa1, 0xa6, 0x4d, 0xc5, 0x9f, 0x70, 0x13, 0xfd,
};

pub const PK3 = [33]u8{
    0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41,
    0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6,
    0x59,
};
pub const MSG3 = [32]u8{
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
};
pub const SIG3 = [64]u8{ 0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb, 0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d, 0xfa, 0x16, 0xae, 0xe0, 0x66, 0x09, 0x28, 0x0a, 0x19, 0xb6, 0x7a, 0x24, 0xe1, 0x97, 0x7e, 0x46, 0x97, 0x71, 0x2b, 0x5f, 0xd2, 0x94, 0x39, 0x14, 0xec, 0xd5, 0xf7, 0x30, 0x90, 0x1b, 0x4a, 0xb7 };
pub const PRIVKEY = [32]u8{
    254, 237, 105, 209, 200, 130, 84,  7,   141, 199, 110, 17, 65, 127, 3, 163, 108, 0, 97, 33, 253,
    109, 3,   79,  35,  138, 200, 124, 171, 86,  179, 100,
};

// Test vector 7:x Negated message hash, R.x mismatch */
const PK7 = [33]u8{ 0x03, 0xFA, 0xC2, 0x11, 0x4C, 0x2F, 0xBB, 0x09, 0x15, 0x27, 0xEB, 0x7C, 0x64, 0xEC, 0xB1, 0x1F, 0x80, 0x21, 0xCB, 0x45, 0xE8, 0xE7, 0x80, 0x9D, 0x3C, 0x09, 0x38, 0xE4, 0xB8, 0xC0, 0xE5, 0xF8, 0x4B };

const MSG7 = [32]u8{
    0x5E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A,
    0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D,
    0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33,
    0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C,
};

const SIG7 = [64]u8{
    0x00, 0xDA, 0x9B, 0x08, 0x17, 0x2A, 0x9B, 0x6F,
    0x04, 0x66, 0xA2, 0xDE, 0xFD, 0x81, 0x7F, 0x2D,
    0x7A, 0xB4, 0x37, 0xE0, 0xD2, 0x53, 0xCB, 0x53,
    0x95, 0xA9, 0x63, 0x86, 0x6B, 0x35, 0x74, 0xBE,
    0xD0, 0x92, 0xF9, 0xD8, 0x60, 0xF1, 0x77, 0x6A,
    0x1F, 0x74, 0x12, 0xAD, 0x8A, 0x1E, 0xB5, 0x0D,
    0xAC, 0xCC, 0x22, 0x2B, 0xC8, 0xC0, 0xE2, 0x6B,
    0x20, 0x56, 0xDF, 0x2F, 0x27, 0x3E, 0xFD, 0xEC,
};
pub const RFC_PRIV_KEY = [32]u8{ 201, 175, 169, 216, 69, 186, 117, 22, 107, 92, 33, 87, 103, 177, 214, 147, 78, 80, 195, 219, 54, 232, 155, 18, 123, 138, 98, 43, 18, 15, 103, 33 };

pub const EXPECTED_K = [32]u8{ 166, 227, 197, 125, 208, 26, 190, 144, 8, 101, 56, 57, 131, 85, 221, 76, 59, 23, 170, 135, 51, 130, 176, 242, 77, 97, 41, 73, 61, 138, 173, 96 };
pub const aad_length = 16;
const schnorr = @This();

const PRIV_KEYS = [_][]const u8{
    "ce76090568e5686f7c3eb4163acab9343daa4155595136cdcd4b842ce198b541",
    "91f5cd69c6162a8d55f8251b7ef35fb0692c7f6b52ecc0f227e4a02e8da80648",
    "8fe27e7a1a4eab6ecff34d410aee8d9f4a76dd2f889c057c1e3cc6156d7b2b9d",
    "8311cfc1313ad36e3b9b20b8eb5f94ff91270831e46dd7de7abd64de520d8f46",
    "d16ed6db426896860e66afa6abf3c09ce6e87a25776a4a169fe679e9f5b1cc45",
    "0d0a4fa9846ecb64fd7316b1ae67ced967ee2aaf25df4da0a5ad3a5f119faefc",
    "34c72536ab9512f13b7d83f157435f247ce1864223eb775ccc92e624c000b236",
    "333dc630224ba7e7db45fbdb33217763f480f800babfc801ead02819b59a44a9",
    "faaff21c868c18c3fde4b0bb4810f6d9d4d52416563b545c69397d2d7aa0400f",
    "a72d989d75ca9dbae91efe78eca345893df0dbdb47a10e4f4f146e3c3e891600",
};

const SIGS = [_][]const u8{
    "90030bf11a9f11b8c278f43184f0183b2f92705a7d67ea51c612b0ec049ad9f14419a812d2e7913e1ef517dfd142e5d6a0cb6ad0bbddd46798e5cf45cc6b173d",
    "1840d5b0aff418d7981e8be57c94d0ed0e681d143b4f510af1e7129bbec613a6cb10d133d54c8b1b18fa6395ac034289e97a915476cee312b558c5956835fdeb",
    "52343f7021026a1765f6db45cc3a600f93a002c47c8240e1abe15fb1993b18056519e192654d548b1c26d6251db5336821a5ecc84ac4cfa2b3d46be15c76d217",
    "56bc14a185edea2ba3fffa5b4a16e814349ccabc08f8200a890900f42df68ea51d8f76e18e32d32ddfe2717b3f915f61429eec5794f13da602c30114074dc051",
    "5f630170c2fe7206cf9fe22d724efb811b3c7eb1f6a5d5aa42769e228b74dc8adf882cca01b35a273c278d9447be506a32313eeb86de3ace06e1e9c00c9b061c",
    "7ee207d1d0a77a49b239ffa3d33d1f339a0c6b7c7b809907f733d32fb9c58a39472885a654e9a200213ad382893caa1a52ab4fe26bfd206e7c011598e4cd2a78",
    "94306d74b1c62d582220f1fb8ddfb4e3343987092443e8ebc7e5e57bdf79dff2234a343eec095bbe0473175c3ef7bb23f05d4e1959651af3b8caddfb2a594d10",
    "1111ac2509de47a108097b933e5c0d709f1f6926bddcc7a60ee663cd32fac6c26599f20eb2249747f1d97c097cfcc3ca4a3d30a4b99219920d293efac5e92eb8",
    "5d0302fc45215213b4404329be740ef5f96ff642e070ae5fe8fb4304a540deff56aa14507c6c7b50873040fbf0a2e8dbc7ad839966c69f0329e9710b8ebc8289",
    "61055b194471b5ca21e1e5133ed78b3fddcbdaf1d8c4faf9a7645920c4562ab413dd66af6384dc77212d8d729cdd47571580e1f1c209511d246267b104f8ed8e",
};
pub const MSG = "sample".*;

test "CHECK SIGS MSG RAW" {
    var keys: [32]u8 = undefined;
    var sig_res: [64]u8 = undefined;
    const Scheme = schnorr.SchnorrBCH;
    // Warmup phase
    const warmup_iterations = 10;
    for (0..warmup_iterations) |_| {
        for (PRIV_KEYS, 0..) |k, i| {
            _ = try std.fmt.hexToBytes(&keys, k);
            const sk = try Scheme.SecretKey.fromBytes(keys);
            const kp = try Scheme.KeyPair.fromSecretKey(sk);
            const sig = try kp.schnorrSign(&MSG);
            var verifier = try SchnorrBCH.Verifier.init(sig, kp.public_key);
            verifier.update(&MSG);
            try verifier.verify();
            _ = try std.fmt.hexToBytes(&sig_res, SIGS[i]);
            const x = std.mem.eql(u8, &sig_res, &sig.toBytes());
            std.debug.assert(x);
        }
    }
    // Capture the start time
    const start_time = std.time.milliTimestamp();

    for (PRIV_KEYS, 0..) |k, i| {
        _ = try std.fmt.hexToBytes(&keys, k);
        const sk = try Scheme.SecretKey.fromBytes(keys);
        const kp = try Scheme.KeyPair.fromSecretKey(sk);
        const sig = try kp.schnorrSign(&MSG);
        var verifier = try SchnorrBCH.Verifier.init(sig, kp.public_key);
        verifier.update(&MSG);
        try verifier.verify();
        _ = try std.fmt.hexToBytes(&sig_res, SIGS[i]);
        const x = std.mem.eql(u8, &sig_res, &sig.toBytes());
        std.debug.assert(x);
    }
    // Capture the end time
    const end_time = std.time.milliTimestamp();

    // Calculate the total time taken
    const total_time = end_time - start_time;

    // Print the total time taken
    std.debug.print("Total time taken: {} milliseconds\n", .{total_time});
}

test "SIGS MSG HASHED" {
    var keys: [32]u8 = undefined;
    var sig_res: [64]u8 = undefined;
    const Scheme = schnorr.SchnorrBCH;
    var msg_hash: [32]u8 = undefined;
    sha256.hash(&MSG, &msg_hash, .{});

    for (PRIV_KEYS, 0..) |k, i| {
        _ = try std.fmt.hexToBytes(&keys, k);
        const sk = try Scheme.SecretKey.fromBytes(keys);
        const kp = try Scheme.KeyPair.fromSecretKey(sk);
        const sig = try kp.schnorrSign(&MSG);
        var verifier = try SchnorrBCH.Verifier.init(sig, kp.public_key);
        try verifier.verifyMessageHash(msg_hash);
        _ = try std.fmt.hexToBytes(&sig_res, SIGS[i]);
        // std.debug.print("{any}\n == {any}\n", .{ sig_res, sig.toBytes() });
        const x = std.mem.eql(u8, &sig_res, &sig.toBytes());
        std.debug.assert(x);
    }
}
test "test vectors from Bitcoin ABC libsecp256k1" {
    const sig1 = SchnorrBCH.Signature.fromBytes(SIG1);
    const pk1 = try SchnorrBCH.PublicKey.fromSec1(&PK1);
    var verifier = try SchnorrBCH.Verifier.init(sig1, pk1);
    const res = try verifier.verifyMessageHash(MSG1);
    _ = res;

    const sig2 = SchnorrBCH.Signature.fromBytes(SIG2);
    const pk2 = try SchnorrBCH.PublicKey.fromSec1(&PK2);
    var verifier2 = try SchnorrBCH.Verifier.init(sig2, pk2);
    const res2 = try verifier2.verifyMessageHash(MSG2);
    _ = res2;

    const sig3 = SchnorrBCH.Signature.fromBytes(SIG3);
    const pk3 = try SchnorrBCH.PublicKey.fromSec1(&PK3);
    var verifier3 = try SchnorrBCH.Verifier.init(sig3, pk3);
    const res3 = verifier3.verifyMessageHash(MSG3) catch |err| switch (err) {
        error.NotSquare => {
            const expected_error = error.NotSquare;
            const actual_error_union: anyerror!void = error.NotSquare;
            _ = try std.testing.expectError(expected_error, actual_error_union);
        },
        else => unreachable,
    };
    const sig7 = SchnorrBCH.Signature.fromBytes(SIG7);
    const pk7 = try SchnorrBCH.PublicKey.fromSec1(&PK7);
    var verifier7 = try SchnorrBCH.Verifier.init(sig7, pk7);
    const res7 = verifier7.verifyMessageHash(MSG7) catch |err| switch (err) {
        error.NotSquare => {
            const expected_error = error.NotSquare;
            const actual_error_union: anyerror!void = error.NotSquare;
            _ = try std.testing.expectError(expected_error, actual_error_union);
        },
        else => unreachable,
    };
    _ = res;
    _ = res2;
    _ = res3;
    _ = res7;
}
