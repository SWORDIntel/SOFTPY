# Pure-Python Crypto Toolkit v2.0 🔐

**Military-grade cryptography** with zero external dependencies. NSA Suite B / CNSA 2.0 compliant algorithms implemented entirely in Python stdlib.

## Features

### Authenticated Encryption (AEAD)
- **AES-256-GCM** (NIST SP 800-38D)
- **ChaCha20-Poly1305** (RFC 8439, IETF recommended)
- **AES-256-CBC/CTR** (legacy modes)

### Hashing
- **SHA-256, SHA-384, SHA-512** (FIPS 180-4)
- **SHA-3 family** (SHA3-256, SHA3-512, SHAKE-128/256, FIPS 202)
- **SHA-1** (deprecated, for compatibility)
- **HMAC** (SHA-1/256/384/512, RFC 2104)
- **Tagged hashing** (domain separation)

### Key Derivation
- **HKDF** (RFC 5869, extract-and-expand)
- **PBKDF2** (RFC 2898, password-based, 600k+ iterations)

### Public Key Cryptography
- **RSA** (2048+ bit, PKCS#1 v1.5, OAEP, PSS, Baillie-PSW primality)
- **Ed25519** (RFC 8032, modern signatures, 32-byte keys)
- **X25519** (RFC 7748, modern ECDH, 32-byte keys)
- **NIST P-256 / P-384** (ECDSA + ECDH, FIPS 186-4)

### Random Number Generation
- **CSPRNG wrapper** (health-checked `os.urandom`)
- **HMAC_DRBG_SHA256** (NIST SP 800-90A deterministic random bit generator)
- **DigitalURandom** (entropy collector: TPM 2.0, /dev/hwrng, timing jitter, thread scheduler, GC/allocator jitter, Linux proc/sysfs)

### AWS Integration
- **AWS Signature Version 4** (request signing + sending)

### Utilities
- **Secure memory** (best-effort zeroing)
- **Constant-time comparison**

## Installation

```bash
pip install -e .
```

Or just copy the `src/crypto_standalone` directory.

## Quick Start

### Authenticated Encryption (Recommended)

```python
from crypto_standalone import ChaCha20Poly1305, AESGCM

# ChaCha20-Poly1305 (fastest in pure Python)
cipher = ChaCha20Poly1305(key=b"\x00" * 32)
blob = cipher.encrypt_blob(b"secret message", aad=b"metadata")
plaintext = cipher.decrypt_blob(blob, aad=b"metadata")

# AES-256-GCM (NIST standard)
gcm = AESGCM(key=b"\x00" * 32)
blob = gcm.encrypt_blob(b"secret message", aad=b"metadata")
plaintext = gcm.decrypt_blob(blob, aad=b"metadata")
```

### Modern Signatures

```python
from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify

private_key, public_key = ed25519_keygen()
signature = ed25519_sign(b"message", private_key)
valid = ed25519_verify(b"message", signature, public_key)
```

### Key Agreement

```python
from crypto_standalone import x25519_keygen, x25519

alice_sk, alice_pk = x25519_keygen()
bob_sk, bob_pk = x25519_keygen()

alice_shared = x25519(alice_sk, bob_pk)
bob_shared = x25519(bob_sk, alice_pk)
assert alice_shared == bob_shared  # 32-byte shared secret
```

### Key Derivation

```python
from crypto_standalone import hkdf_sha256, pbkdf2_sha256

# HKDF for key derivation
key_material = hkdf_sha256(
    salt=b"optional-salt", ikm=b"input-key-material",
    info=b"context-info", length=32
)

# PBKDF2 for passwords (600k+ iterations recommended)
derived_key = pbkdf2_sha256(
    password=b"user-password", salt=b"random-salt-16-bytes",
    iterations=600_000, dklen=32
)
```

### RSA

```python
from crypto_standalone import generate_rsa_keypair

keypair = generate_rsa_keypair(2048)

# OAEP (modern encryption)
ciphertext = keypair.public.encrypt_oaep(b"hello")
plaintext = keypair.private.decrypt_oaep(ciphertext)

# PSS (modern signatures)
signature = keypair.private.sign_pss(b"message")
valid = keypair.public.verify_pss(b"message", signature)
```

### HMAC_DRBG (NIST SP 800-90A)

```python
from crypto_standalone import HMAC_DRBG_SHA256
import os

drbg = HMAC_DRBG_SHA256(entropy_input=os.urandom(32))
random_bytes = drbg.generate(32)
```

### Hashing

```python
from crypto_standalone import sha256, sha256_hex, hmac_sha256

digest = sha256(b"data")
hex_digest = sha256_hex(b"data")
mac = hmac_sha256(key=b"secret", message=b"data")
```

## Testing

### Self-Test

```bash
python selftest_v2.py   # 9/9 checks
```

### Pytest Suite (252 tests)

```bash
pip install -e ".[dev]"   # installs pytest + hypothesis
pytest tests/ -v          # unit + adversarial
```

### Test Categories

| Category | Count | Coverage |
|----------|-------|----------|
| Unit tests | 66 | AES, hashes, RSA, ECC, KDF/utils |
| Wycheproof adversarial | 186 | Tag tampering, AAD manipulation, nonce reuse, signature malleability, invalid scalars, low-order points, attack simulations, property-based fuzzing |

### CI/CD

```bash
# GitHub Actions: .github/workflows/test.yml
# Tests Python 3.8–3.12, unit + adversarial + self-test
```

## Algorithm Recommendations

| Purpose | Recommended | Avoid |
|---------|-------------|-------|
| Encryption | ChaCha20-Poly1305 or AES-GCM | AES-CBC without HMAC |
| Hashing | SHA-256 or SHA-384 | SHA-1 |
| Signatures | Ed25519 or P-384 ECDSA | RSA PKCS#1 v1.5 |
| Key agreement | X25519 or P-384 ECDH | — |
| Key derivation | HKDF-SHA256 | — |
| Passwords | PBKDF2-SHA256 (600k+ iter) | — |
| RNG | HMAC_DRBG_SHA256 or os.urandom | `random` module |

## Security Caveats

⚠️ **Pure-Python implementation — not for adversarial timing environments.**

- **Timing side-channels**: Python integer arithmetic is variable-time
- **Performance**: SHA-256 is ~200× slower than C-backed `hashlib`
- **No hardware acceleration**: No AES-NI, no assembly

**Suitable for:**
- Embedded systems without C compilers
- Educational purposes
- Environments where external dependencies are forbidden
- Bootstrapping secure channels before installing native crypto

**For production, prefer:** `cryptography` (Rust/C), `pycryptodome` (C), or HSMs.

## Threat Model

| Threat | Status |
|--------|--------|
| Passive eavesdropping | ✅ AEAD provides confidentiality |
| Ciphertext tampering | ✅ Authentication tags detect modifications |
| Message forgery | ✅ HMAC + digital signatures |
| Man-in-the-middle | ✅ ECDH + signatures |
| Brute force | ✅ 256-bit keys (2^256 operations) |
| Birthday attacks | ✅ SHA-256+ (128+ bit collision resistance) |
| Nonce reuse (ECDSA) | ✅ RFC 6979 deterministic k |
| Weak RNG | ✅ HMAC_DRBG + os.urandom |
| Timing attacks | ❌ Python is not constant-time |
| Power analysis | ❌ No hardware countermeasures |
| Side-channel cache attacks | ❌ No constant-time memory access |

## Package Structure

```
src/crypto_standalone/
├── __init__.py              # Top-level exports
├── symmetric/
│   ├── aes.py               # AES-256 (CBC, CTR)
│   ├── aes_gcm.py           # AES-256-GCM
│   └── chacha20.py          # ChaCha20-Poly1305
├── hashing/
│   ├── sha2.py              # SHA-1/256/384/512, HMAC
│   └── sha3.py              # SHA-3, SHAKE
├── asymmetric/
│   ├── rsa.py               # RSA (OAEP, PSS)
│   ├── ed25519.py           # Ed25519 signatures
│   ├── x25519.py            # X25519 ECDH
│   └── nist_curves.py       # P-256/P-384 ECDSA+ECDH
├── kdf/
│   ├── hkdf.py              # HKDF (RFC 5869)
│   └── pbkdf2.py            # PBKDF2 (RFC 2898)
├── utils/
│   ├── random.py            # CSPRNG wrapper
│   ├── drbg.py              # HMAC_DRBG_SHA256 (NIST SP 800-90A)
│   ├── digital_entropy.py   # DigitalURandom entropy collector
│   └── memory.py            # Secure memory, constant-time compare
└── aws/
    └── sigv4.py             # AWS Signature V4
```

## Dependencies

- **Python 3.7+**
- **Standard library only**: `os.urandom`, `urllib.request`, `datetime`, `dataclasses`, `threading`, `time`, `gc`, `sys`

No `pip install` required. No C extensions. No `hashlib`, `hmac`, or `secrets`.

## Implementation Notes

- **SHA-2**: Bit-level FIPS 180-4 (32-bit and 64-bit word versions)
- **SHA-3/Keccak**: Keccak-f[1600] sponge permutation, 24 rounds
- **AES-256**: Rijndael with 14 rounds, GF(2^8) arithmetic
- **GCM**: GHASH in GF(2^128), CTR mode encryption
- **ChaCha20**: 20-round quarter-function, Poly1305 over GF(2^130-5)
- **RSA**: Baillie-PSW primality, CRT-based decryption, small-prime sieve
- **Ed25519**: Twisted Edwards curve, extended coordinates, RFC 8032
- **X25519**: Montgomery ladder, clamped scalar, RFC 7748
- **ECDSA**: RFC 6979 deterministic k, DER signature encoding
- **OAEP/PSS**: MGF1-SHA256 mask generation
- **HMAC_DRBG**: NIST SP 800-90A §10.1.2, reseed interval 2^48
- **DigitalURandom**: Multi-source entropy conditioning via SHA-256 + HMAC_DRBG

## License

MIT
