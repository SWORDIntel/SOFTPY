# Pure-Python Crypto Toolkit v2.0

**Military-grade cryptography** with zero external dependencies. NSA Suite B / CNSA 2.0 compliant algorithms implemented entirely in Python stdlib.

[![Tests](https://github.com/SWORDIntel/SOFTPY/actions/workflows/test.yml/badge.svg)](https://github.com/SWORDIntel/SOFTPY/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](pyproject.toml)
[![290 tests](https://img.shields.io/badge/tests-290%20passing-brightgreen.svg)](tests/)
[![Zero deps](https://img.shields.io/badge/dependencies-zero-orange.svg)](pyproject.toml)

## Features

- **AES-256-GCM** (NIST SP 800-38D), **ChaCha20-Poly1305** (RFC 8439), AES-256-CBC/CTR
- **SHA-256/384/512** (FIPS 180-4), **SHA-3/SHAKE** (FIPS 202), HMAC, tagged hashing
- **HKDF** (RFC 5869), **PBKDF2** (RFC 2898, 600k+ iterations)
- **RSA** (OAEP, PSS, Baillie-PSW primality), **Ed25519** (RFC 8032), **X25519** (RFC 7748), **P-256/P-384** (ECDSA + ECDH)
- **HMAC_DRBG_SHA256** (NIST SP 800-90A), **DigitalURandom** (pure-Python entropy: TPM 2.0, /dev/hwrng, jitter, proc/sysfs)
- **AWS SigV4** request signing
- Secure memory, constant-time comparison

## Installation

```bash
pip install -e .
```

Or just copy the `src/crypto_standalone` directory.

## Quick Start

### Authenticated Encryption

```python
from crypto_standalone import ChaCha20Poly1305, AESGCM

cipher = ChaCha20Poly1305(key=b"\x00" * 32)
blob = cipher.encrypt_blob(b"secret message", aad=b"metadata")
plaintext = cipher.decrypt_blob(blob, aad=b"metadata")
```

### Signatures & Key Agreement

```python
from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify
from crypto_standalone import x25519_keygen, x25519

sk, pk = ed25519_keygen()
sig = ed25519_sign(b"message", sk)
assert ed25519_verify(b"message", sig, pk)

alice_sk, alice_pk = x25519_keygen()
bob_sk, bob_pk = x25519_keygen()
shared = x25519(alice_sk, bob_pk)  # == x25519(bob_sk, alice_pk)
```

### Key Derivation & Hashing

```python
from crypto_standalone import hkdf_sha256, pbkdf2_sha256, sha256, hmac_sha256

key = hkdf_sha256(b"salt", b"ikm", b"info", 32)
derived = pbkdf2_sha256(b"password", b"salt", 600_000, 32)
digest = sha256(b"data")
mac = hmac_sha256(key=b"secret", message=b"data")
```

### RSA

```python
from crypto_standalone import generate_rsa_keypair

kp = generate_rsa_keypair(2048)
ct = kp.public.encrypt_oaep(b"hello")
pt = kp.private.decrypt_oaep(ct)
sig = kp.private.sign_pss(b"message")
assert kp.public.verify_pss(b"message", sig)
```

### Random Bytes (no os.urandom)

```python
from crypto_standalone import random_bytes, DigitalURandom

key = random_bytes(32)  # uses DigitalURandom internally

rng = DigitalURandom()  # direct access
token = rng.urandom(32)
```



### Legacy Ciphers (Interoperability Only)

```python
# Import only one implementation/module when needed
from crypto_standalone.symmetric.tea import TEA
from crypto_standalone.symmetric.redpike import RedPike
from crypto_standalone.symmetric.avemaria import AveMariaCipher

# Backward-compatible aggregate import still works
from crypto_standalone.symmetric.legacy_ciphers import TEA, RedPike, AveMariaCipher
```

These legacy ciphers are for compatibility/migration workflows and are not recommended for new system designs.

## Algorithm Recommendations

| Purpose | Recommended | Avoid |
|---------|-------------|-------|
| Encryption | ChaCha20-Poly1305 or AES-GCM | AES-CBC without HMAC |
| Hashing | SHA-256 or SHA-384 | SHA-1 |
| Signatures | Ed25519 or P-384 ECDSA | RSA PKCS#1 v1.5 |
| Key agreement | X25519 or P-384 ECDH | — |
| Key derivation | HKDF-SHA256 | — |
| Passwords | PBKDF2-SHA256 (600k+ iter) | — |
| RNG | HMAC_DRBG + DigitalURandom | `random` module |

## Documentation

- **[Testing & Caveats](docs/TESTING.md)** — running tests, test categories, CI, security caveats
- **[Implementation Notes & Threat Model](docs/IMPLEMENTATION.md)** — per-algorithm notes, threat model, dependencies
- **[Random Number Generation](docs/RANDO.md)** — DigitalURandom, HMAC_DRBG_SHA256, CSPRNG architecture

## License

crimimal use only lol
