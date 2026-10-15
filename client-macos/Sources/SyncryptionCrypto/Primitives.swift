import Clibsodium
import CryptoKit
import Foundation

/// The primitives of docs/crypto.md 2: SHA-2, HMAC and HKDF from CryptoKit; Ed25519,
/// X25519 and the ChaCha20-Poly1305 AEADs from libsodium.
public enum Primitives {
    private static let ready: Bool = sodium_init() >= 0

    static func ensureReady() {
        precondition(ready, "libsodium failed to initialise")
    }

    public static func random(_ n: Int) -> Bytes {
        ensureReady()
        var out = Bytes(repeating: 0, count: n)
        randombytes_buf(&out, n)
        return out
    }

    public static func sha256(_ m: Bytes) -> Bytes { Bytes(SHA256.hash(data: m)) }
    public static func sha512(_ m: Bytes) -> Bytes { Bytes(SHA512.hash(data: m)) }

    public static func hmacSHA256(key: Bytes, _ m: Bytes) -> Bytes {
        Bytes(HMAC<SHA256>.authenticationCode(for: m, using: SymmetricKey(data: key)))
    }

    /// HKDF-SHA256. An empty salt means HashLen zero bytes (RFC 5869), which HMAC treats the
    /// same as an empty key.
    public static func hkdf(ikm: Bytes, salt: Bytes, info: Bytes, length: Int = 32) -> Bytes {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info,
                                         outputByteCount: length)
        return key.withUnsafeBytes { Bytes($0) }
    }

    // MARK: Ed25519

    public static func ed25519PublicKey(seed: Bytes) -> Bytes {
        ensureReady()
        precondition(seed.count == 32)
        var pk = Bytes(repeating: 0, count: 32)
        var sk = Bytes(repeating: 0, count: 64)
        _ = crypto_sign_seed_keypair(&pk, &sk, seed)
        wipe(&sk)
        return pk
    }

    /// Deterministic Ed25519 signature (RFC 8032).
    public static func ed25519Sign(seed: Bytes, _ m: Bytes) -> Bytes {
        ensureReady()
        var pk = Bytes(repeating: 0, count: 32)
        var sk = Bytes(repeating: 0, count: 64)
        _ = crypto_sign_seed_keypair(&pk, &sk, seed)
        var sig = Bytes(repeating: 0, count: 64)
        _ = crypto_sign_detached(&sig, nil, m, UInt64(m.count), sk)
        wipe(&sk)
        return sig
    }

    /// Strict verification: rejects non-canonical encodings and small-order keys.
    public static func ed25519Verify(publicKey: Bytes, signature: Bytes, _ m: Bytes) -> Bool {
        ensureReady()
        guard publicKey.count == 32, signature.count == 64 else { return false }
        return crypto_sign_verify_detached(signature, m, UInt64(m.count), publicKey) == 0
    }

    /// Ed25519 public key to X25519 (`u = (1 + y) / (1 - y)`). Nil if not a valid point.
    public static func ed25519PublicToX25519(_ pk: Bytes) -> Bytes? {
        ensureReady()
        guard pk.count == 32 else { return nil }
        var x = Bytes(repeating: 0, count: 32)
        return crypto_sign_ed25519_pk_to_curve25519(&x, pk) == 0 ? x : nil
    }

    /// Ed25519 seed to X25519 secret: SHA-512(seed)[0:32]. X25519 clamps it.
    public static func ed25519SeedToX25519(_ seed: Bytes) -> Bytes { Array(sha512(seed).prefix(32)) }

    // MARK: X25519

    public static func x25519Base(_ scalar: Bytes) -> Bytes {
        ensureReady()
        var q = Bytes(repeating: 0, count: 32)
        _ = crypto_scalarmult_curve25519_base(&q, scalar)
        return q
    }

    /// X25519. Nil if the result is all zero (a low-order point).
    public static func x25519(_ scalar: Bytes, _ point: Bytes) -> Bytes? {
        ensureReady()
        guard scalar.count == 32, point.count == 32 else { return nil }
        var q = Bytes(repeating: 0, count: 32)
        return crypto_scalarmult_curve25519(&q, scalar, point) == 0 ? q : nil
    }

    // MARK: AEADs

    /// ChaCha20-Poly1305 (RFC 8439, 12-byte nonce). Returns ciphertext || tag.
    public static func chachaSeal(key: Bytes, nonce: Bytes, _ m: Bytes, ad: Bytes = []) -> Bytes {
        ensureReady()
        precondition(key.count == 32 && nonce.count == 12)
        var c = Bytes(repeating: 0, count: m.count + 16)
        var clen: UInt64 = 0
        _ = crypto_aead_chacha20poly1305_ietf_encrypt(&c, &clen, m, UInt64(m.count), ad, UInt64(ad.count), nil, nonce, key)
        return c
    }

    public static func chachaOpen(key: Bytes, nonce: Bytes, _ c: Bytes, ad: Bytes = []) -> Bytes? {
        ensureReady()
        guard key.count == 32, nonce.count == 12, c.count >= 16 else { return nil }
        var m = Bytes(repeating: 0, count: c.count - 16)
        var mlen: UInt64 = 0
        let r = crypto_aead_chacha20poly1305_ietf_decrypt(&m, &mlen, nil, c, UInt64(c.count), ad, UInt64(ad.count), nonce, key)
        return r == 0 ? m : nil
    }

    /// XChaCha20-Poly1305 (24-byte nonce). Returns ciphertext || tag.
    public static func xchachaSeal(key: Bytes, nonce: Bytes, _ m: Bytes, ad: Bytes) -> Bytes {
        ensureReady()
        precondition(key.count == 32 && nonce.count == 24)
        var c = Bytes(repeating: 0, count: m.count + 16)
        var clen: UInt64 = 0
        _ = crypto_aead_xchacha20poly1305_ietf_encrypt(&c, &clen, m, UInt64(m.count), ad, UInt64(ad.count), nil, nonce, key)
        return c
    }

    public static func xchachaOpen(key: Bytes, nonce: Bytes, _ c: Bytes, ad: Bytes) -> Bytes? {
        ensureReady()
        guard key.count == 32, nonce.count == 24, c.count >= 16 else { return nil }
        var m = Bytes(repeating: 0, count: c.count - 16)
        var mlen: UInt64 = 0
        let r = crypto_aead_xchacha20poly1305_ietf_decrypt(&m, &mlen, nil, c, UInt64(c.count), ad, UInt64(ad.count), nonce, key)
        return r == 0 ? m : nil
    }
}
