# Implementation Notes & Threat Model

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
| Weak RNG | ✅ HMAC_DRBG + DigitalURandom (no os.urandom) |
| Timing attacks | ❌ Python is not constant-time |
| Power analysis | ❌ No hardware countermeasures |
| Side-channel cache attacks | ❌ No constant-time memory access |

## Dependencies

- **Python 3.7+**
- **Standard library only**: `urllib.request`, `datetime`, `dataclasses`, `threading`, `time`, `gc`, `sys`, `socket`

No `pip install` required. No C extensions. No `hashlib`, `hmac`, `secrets`, or `os.urandom`.
