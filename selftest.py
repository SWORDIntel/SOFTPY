"""Comprehensive self-test suite for military-grade crypto toolkit."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def test_hashes():
    from crypto_standalone import sha256_hex, sha384_hex, sha512_hex, hmac_sha256, tagged_hash
    
    tests = [
        ("SHA-256", sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("SHA-384", sha384_hex(b"abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        ("SHA-512", sha512_hex(b"abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ]
    
    for name, got, exp in tests:
        if got != exp:
            print(f"  {name}: FAIL")
            return False
    
    mac = hmac_sha256(b"key", b"message")
    if len(mac) != 32:
        print("  HMAC-SHA256: FAIL")
        return False
    
    tagged = tagged_hash("test", b"data")
    if len(tagged) != 32:
        print("  Tagged hash: FAIL")
        return False
    
    print("  Hashes: PASS")
    return True


def test_sha3():
    from crypto_standalone import sha3_256_hex, sha3_512_hex, shake_128
    
    if sha3_256_hex(b"abc") != "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532":
        print("  SHA3-256: FAIL")
        return False
    
    if len(shake_128(b"test", 32)) != 32:
        print("  SHAKE-128: FAIL")
        return False
    
    print("  SHA-3: PASS")
    return True


def test_aead():
    from crypto_standalone import AESGCM
    from crypto_standalone import ChaCha20Poly1305
    
    key = b"\x00" * 32
    msg = b"secret message"
    aad = b"metadata"
    
    gcm = AESGCM(key)
    blob_gcm = gcm.encrypt_blob(msg, aad=aad)
    if gcm.decrypt_blob(blob_gcm, aad=aad) != msg:
        print("  AES-GCM: FAIL")
        return False
    
    try:
        gcm.decrypt_blob(blob_gcm, aad=b"wrong")
        print("  AES-GCM tamper detection: FAIL")
        return False
    except ValueError:
        pass
    
    cp = ChaCha20Poly1305(key)
    blob_cp = cp.encrypt_blob(msg, aad=aad)
    if cp.decrypt_blob(blob_cp, aad=aad) != msg:
        print("  ChaCha20-Poly1305: FAIL")
        return False
    
    try:
        cp.decrypt_blob(blob_cp, aad=b"wrong")
        print("  ChaCha20-Poly1305 tamper detection: FAIL")
        return False
    except ValueError:
        pass
    
    print("  AEAD: PASS")
    return True


def test_kdf():
    from crypto_standalone import hkdf_sha256, pbkdf2_sha256
    
    okm = hkdf_sha256(b"salt", b"ikm", b"info", 32)
    if len(okm) != 32:
        print("  HKDF: FAIL")
        return False
    
    dk = pbkdf2_sha256(b"password", b"salt", 1000, 32)
    if len(dk) != 32:
        print("  PBKDF2: FAIL")
        return False
    
    print("  KDF: PASS")
    return True


def test_rsa():
    from crypto_standalone import generate_rsa_keypair
    
    kp = generate_rsa_keypair(2048)
    msg = b"test"
    
    ct = kp.public.encrypt(msg)
    if kp.private.decrypt(ct) != msg:
        print("  RSA PKCS#1 v1.5: FAIL")
        return False
    
    ct_oaep = kp.public.encrypt_oaep(msg)
    if kp.private.decrypt_oaep(ct_oaep) != msg:
        print("  RSA-OAEP: FAIL")
        return False
    
    sig = kp.private.sign(msg)
    if not kp.public.verify(msg, sig):
        print("  RSA sign/verify: FAIL")
        return False
    
    sig_pss = kp.private.sign_pss(msg)
    if not kp.public.verify_pss(msg, sig_pss):
        print("  RSA-PSS: FAIL")
        return False
    
    print("  RSA: PASS")
    return True


def test_ed25519():
    from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify
    
    sk, pk = ed25519_keygen()
    msg = b"test message"
    sig = ed25519_sign(msg, sk)
    
    if not ed25519_verify(msg, sig, pk):
        print("  Ed25519 verify: FAIL")
        return False
    
    if ed25519_verify(b"wrong", sig, pk):
        print("  Ed25519 tamper detection: FAIL")
        return False
    
    print("  Ed25519: PASS")
    return True


def test_x25519():
    from crypto_standalone import x25519_keygen, x25519
    
    sk1, pk1 = x25519_keygen()
    sk2, pk2 = x25519_keygen()
    
    s1 = x25519(sk1, pk2)
    s2 = x25519(sk2, pk1)
    
    if s1 != s2:
        print("  X25519 agreement: FAIL")
        return False
    
    if len(s1) != 32:
        print("  X25519 length: FAIL")
        return False
    
    print("  X25519: PASS")
    return True


def test_p_curves():
    from crypto_standalone import p256_keygen, p384_keygen
    
    sk256 = p256_keygen()
    msg = b"test"
    sig256 = sk256.sign(msg)
    
    if not sk256.public_key.verify(msg, sig256):
        print("  P-256 ECDSA: FAIL")
        return False
    
    sk256_2 = p256_keygen()
    shared = sk256.ecdh(sk256_2.public_key)
    if len(shared) != 32:
        print("  P-256 ECDH: FAIL")
        return False
    
    sk384 = p384_keygen()
    sig384 = sk384.sign(msg)
    if not sk384.public_key.verify(msg, sig384):
        print("  P-384 ECDSA: FAIL")
        return False
    
    print("  P-curves: PASS")
    return True


def test_utilities():
    from crypto_standalone import random_bytes, random_below
    from crypto_standalone import secure_zero, SecureBytes
    
    if len(random_bytes(32)) != 32:
        print("  random_bytes: FAIL")
        return False
    
    r = random_below(100)
    if not (0 <= r < 100):
        print("  random_below: FAIL")
        return False
    
    data = bytearray(b"secret")
    secure_zero(data)
    if data != bytearray(6):
        print("  secure_zero: FAIL")
        return False
    
    with SecureBytes(32) as sb:
        if len(sb) != 32:
            print("  SecureBytes: FAIL")
            return False
    
    print("  Utilities: PASS")
    return True


def main():
    print("=" * 60)
    print("Military-Grade Crypto Toolkit Self-Test v2.0")
    print("=" * 60)
    print()
    
    tests = [
        ("Extended Hashes", test_hashes),
        ("SHA-3 Family", test_sha3),
        ("AEAD (GCM + ChaCha20-Poly1305)", test_aead),
        ("Key Derivation (HKDF + PBKDF2)", test_kdf),
        ("RSA (OAEP + PSS)", test_rsa),
        ("Ed25519", test_ed25519),
        ("X25519", test_x25519),
        ("NIST P-curves", test_p_curves),
        ("Utilities", test_utilities),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_fn in tests:
        print(f"[{name}]")
        try:
            if test_fn():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ {failed} FAILED")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
