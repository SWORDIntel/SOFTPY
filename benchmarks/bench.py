"""Performance benchmarks for crypto_standalone.

Run with: pytest benchmarks/ -v --benchmark-only
Or quick: python benchmarks/bench.py
"""

import time


def _bench(label, fn, iterations=1):
    t0 = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - t0
    rate = iterations / elapsed if elapsed > 0 else float("inf")
    print(f"  {label:40s} {iterations} iters in {elapsed:.3f}s  ({rate:.1f}/s)")
    return elapsed


def main():
    print("=" * 70)
    print("crypto_standalone Performance Benchmarks")
    print("=" * 70)

    # --- Hashing ---
    print("\n[Hashing]")
    from crypto_standalone import sha256, sha512, sha3_256

    data_1k = b"x" * 1024
    data_64k = b"x" * 65536

    _bench("SHA-256 (1 KB)", lambda: sha256(data_1k), 50)
    _bench("SHA-256 (64 KB)", lambda: sha256(data_64k), 5)
    _bench("SHA-512 (1 KB)", lambda: sha512(data_1k), 50)
    _bench("SHA3-256 (1 KB)", lambda: sha3_256(data_1k), 50)

    # --- HMAC ---
    print("\n[HMAC]")
    from crypto_standalone import hmac_sha256

    key = b"k" * 32
    _bench("HMAC-SHA256 (1 KB)", lambda: hmac_sha256(key, data_1k), 50)

    # --- AEAD ---
    print("\n[AEAD Encrypt]")
    from crypto_standalone import ChaCha20Poly1305, AESGCM

    key = b"\x00" * 32
    chacha = ChaCha20Poly1305(key=key)
    gcm = AESGCM(key=key)
    msg = b"m" * 1024

    _bench("ChaCha20-Poly1305 encrypt (1 KB)", lambda: chacha.encrypt_blob(msg), 20)
    _bench("AES-256-GCM encrypt (1 KB)", lambda: gcm.encrypt_blob(msg), 5)

    # --- Ed25519 ---
    print("\n[Ed25519]")
    from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify

    sk, pk = ed25519_keygen()
    _bench("Ed25519 keygen", lambda: ed25519_keygen(), 3)
    _bench("Ed25519 sign", lambda: ed25519_sign(b"benchmark message", sk), 10)
    sig = ed25519_sign(b"benchmark message", sk)
    _bench("Ed25519 verify", lambda: ed25519_verify(b"benchmark message", sig, pk), 10)

    # --- X25519 ---
    print("\n[X25519]")
    from crypto_standalone import x25519_keygen, x25519

    sk1, pk1 = x25519_keygen()
    sk2, pk2 = x25519_keygen()
    _bench("X25519 keygen", lambda: x25519_keygen(), 10)
    _bench("X25519 DH", lambda: x25519(sk1, pk2), 10)

    # --- P-256 ---
    print("\n[P-256]")
    from crypto_standalone import p256_keygen

    _bench("P-256 keygen", lambda: p256_keygen(), 5)

    # --- RSA ---
    print("\n[RSA]")
    from crypto_standalone import generate_rsa_keypair

    _bench("RSA-2048 keygen", lambda: generate_rsa_keypair(2048), 1)

    # --- KDF ---
    print("\n[KDF]")
    from crypto_standalone import hkdf_sha256, pbkdf2_sha256

    _bench("HKDF-SHA256 (32 B)", lambda: hkdf_sha256(b"salt", b"ikm", b"info", 32), 50)
    _bench("PBKDF2-SHA256 (100 iter)", lambda: pbkdf2_sha256(b"pw", b"salt", 100, 32), 20)

    # --- RNG ---
    print("\n[RNG]")
    from crypto_standalone import HMAC_DRBG_SHA256

    seed = b"\x00" * 32
    drbg = HMAC_DRBG_SHA256(entropy_input=seed)
    _bench("HMAC_DRBG generate (32 B)", lambda: drbg.random_bytes(32), 50)
    _bench("HMAC_DRBG generate (1 KB)", lambda: drbg.random_bytes(1024), 20)

    print("\n" + "=" * 70)
    print("Benchmarks complete.")


if __name__ == "__main__":
    main()
