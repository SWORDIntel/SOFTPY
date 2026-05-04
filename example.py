"""Military-grade crypto toolkit demonstration (v2.0)."""

print("=" * 70)
print("Pure-Python Military-Grade Crypto Toolkit v2.0")
print("=" * 70)
print()

# 1. Authenticated Encryption (AEAD)
print("[1] Authenticated Encryption")
from crypto_standalone import ChaCha20Poly1305, AESGCM

msg = b"Top secret message"
aad = b"metadata: classification=SECRET"

# ChaCha20-Poly1305 (fastest in pure Python)
cp = ChaCha20Poly1305(b"\x00" * 32)
blob_cp = cp.encrypt_blob(msg, aad=aad)
decrypted_cp = cp.decrypt_blob(blob_cp, aad=aad)
print(f"  ChaCha20-Poly1305: {decrypted_cp == msg}")

# AES-256-GCM (NIST standard)
gcm = AESGCM(b"\x00" * 32)
blob_gcm = gcm.encrypt_blob(msg, aad=aad)
decrypted_gcm = gcm.decrypt_blob(blob_gcm, aad=aad)
print(f"  AES-256-GCM: {decrypted_gcm == msg}")
print()

# 2. Modern Signatures (Ed25519)
print("[2] Ed25519 Digital Signatures")
from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify

sk_ed, pk_ed = ed25519_keygen()
sig_ed = ed25519_sign(b"document to sign", sk_ed)
valid_ed = ed25519_verify(b"document to sign", sig_ed, pk_ed)
print(f"  Sign/Verify: {valid_ed}")
print(f"  Key size: {len(sk_ed)} bytes, Signature size: {len(sig_ed)} bytes")
print()

# 3. Key Agreement (X25519)
print("[3] X25519 Key Agreement (ECDH)")
from crypto_standalone import x25519_keygen, x25519

alice_sk, alice_pk = x25519_keygen()
bob_sk, bob_pk = x25519_keygen()
alice_shared = x25519(alice_sk, bob_pk)
bob_shared = x25519(bob_sk, alice_pk)
print(f"  Agreement: {alice_shared == bob_shared}")
print(f"  Shared secret: {len(alice_shared)} bytes")
print()

# 4. NIST P-curves (P-256, P-384)
print("[4] NIST P-256 ECDSA + ECDH")
from crypto_standalone import p256_keygen, p384_keygen

sk_p256 = p256_keygen()
sig_p256 = sk_p256.sign(b"contract")
valid_p256 = sk_p256.public_key.verify(b"contract", sig_p256)
print(f"  P-256 ECDSA: {valid_p256}")

sk_p256_2 = p256_keygen()
shared_p256 = sk_p256.ecdh(sk_p256_2.public_key)
print(f"  P-256 ECDH: {len(shared_p256)} bytes")

sk_p384 = p384_keygen()
sig_p384 = sk_p384.sign(b"treaty")
valid_p384 = sk_p384.public_key.verify(b"treaty", sig_p384)
print(f"  P-384 ECDSA: {valid_p384}")
print()

# 5. Extended Hash Family
print("[5] Extended Hash Family")
from crypto_standalone import sha256_hex, sha384_hex, sha512_hex, sha3_256_hex, shake_128

print(f"  SHA-256('abc'): {sha256_hex(b'abc')[:16]}...")
print(f"  SHA-384('abc'): {sha384_hex(b'abc')[:16]}...")
print(f"  SHA-512('abc'): {sha512_hex(b'abc')[:16]}...")
print(f"  SHA3-256('abc'): {sha3_256_hex(b'abc')[:16]}...")
print(f"  SHAKE-128('abc', 32): {shake_128(b'abc', 32).hex()[:16]}...")
print()

# 6. Key Derivation Functions
print("[6] Key Derivation Functions")
from crypto_standalone import hkdf_sha256, pbkdf2_sha256

# HKDF for deriving multiple keys from master secret
master_secret = b"shared-secret-from-ecdh"
encryption_key = hkdf_sha256(b"salt", master_secret, b"encryption", 32)
mac_key = hkdf_sha256(b"salt", master_secret, b"authentication", 32)
print(f"  HKDF encryption key: {encryption_key.hex()[:16]}...")
print(f"  HKDF MAC key: {mac_key.hex()[:16]}...")

# PBKDF2 for password-based keys
password_key = pbkdf2_sha256(b"user-password", b"random-salt", 10000, 32)
print(f"  PBKDF2 (10k iter): {password_key.hex()[:16]}...")
print()

# 7. RSA with Modern Padding
print("[7] RSA with OAEP and PSS")
from crypto_standalone import generate_rsa_keypair

kp = generate_rsa_keypair(2048)

# OAEP encryption (modern)
ct_oaep = kp.public.encrypt_oaep(b"classified")
pt_oaep = kp.private.decrypt_oaep(ct_oaep)
print(f"  RSA-OAEP: {pt_oaep == b'classified'}")

# PSS signatures (modern)
sig_pss = kp.private.sign_pss(b"document")
valid_pss = kp.public.verify_pss(b"document", sig_pss)
print(f"  RSA-PSS: {valid_pss}")
print()

# 8. Pure-Python RNG (DigitalURandom + HMAC_DRBG_SHA256)
print("[8] Pure-Python Random Number Generation")
from crypto_standalone import HMAC_DRBG_SHA256, DigitalURandom

# HMAC_DRBG_SHA256 — NIST SP 800-90A deterministic PRNG
drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32, personalization=b"demo")
drbg_out = drbg.random_bytes(32)
print(f"  HMAC_DRBG output: {drbg_out.hex()[:16]}...")

# Reseed with fresh entropy
drbg.reseed(entropy_input=b"\xff" * 32)
drbg_out2 = drbg.random_bytes(32)
print(f"  After reseed: {drbg_out2.hex()[:16]}...")

# DigitalURandom — full entropy pipeline (no os.urandom)
rng = DigitalURandom(strict_hardware=False)
rng_out = rng.urandom(32)
print(f"  DigitalURandom: {rng_out.hex()[:16]}...")
print(f"  Entropy sources: {len(rng.report['events'])} collected")
print()

# 9. Secure Random & Memory
print("[9] Utilities")
from crypto_standalone import random_bytes, random_below, SecureBytes, secure_zero

rand = random_bytes(16)
print(f"  Random bytes: {rand.hex()[:16]}...")
print(f"  Random int [0, 100): {random_below(100)}")

with SecureBytes(32) as key_material:
    key_material[:] = random_bytes(32)
    print(f"  Secure context: {len(key_material)} bytes (auto-zeroed on exit)")

data = bytearray(b"sensitive-key-material")
secure_zero(data)
print(f"  Zeroed: {data == bytearray(len(data))}")
print()

# 10. Domain-Separated Hashing
print("[10] Tagged Hashing (Domain Separation)")
from crypto_standalone import tagged_hash

tag1 = tagged_hash("crypto_standalone:v2:signatures", b"data")
tag2 = tagged_hash("crypto_standalone:v2:encryption", b"data")
print(f"  Signature context: {tag1.hex()[:16]}...")
print(f"  Encryption context: {tag2.hex()[:16]}...")
print(f"  Different contexts: {tag1 != tag2}")
print()

print("=" * 70)
print("All examples completed successfully!")
print("=" * 70)
