# Test Record — crypto_standalone v2.0.0

**Date**: 2026-05-04  
**Python**: 3.13.5  
**Platform**: Linux  

## Results

| Suite | Tests | Passed | Failed | Time |
|-------|-------|--------|--------|------|
| Unit | 66 | 66 | 0 | ~15s |
| Adversarial | 186 | 186 | 0 | ~95s |
| Self-test | 9 | 9 | 0 | ~2s |
| **Total** | **261** | **261** | **0** | ~112s |

## Unit Tests (66)

| File | Tests | Coverage |
|------|-------|----------|
| `test_aes.py` | 9 | AES-256 block, CBC, CTR, NIST FIPS 197 vector |
| `test_hashes.py` | 22 | SHA-2, SHA-3, HMAC, compare_digest, tagged_hash |
| `test_rsa.py` | 8 | Keygen, PKCS#1 v1.5, OAEP, PSS, cross-key |
| `test_ecc.py` | 13 | Ed25519, X25519, P-256, P-384 sign/verify/ECDH |
| `test_kdf_utils.py` | 14 | HKDF RFC 5869, PBKDF2 RFC 7914, CSPRNG, SecureBytes |

## Adversarial Tests (186)

| File | Tests | Attack Vectors |
|------|-------|----------------|
| `test_aes_gcm_wycheproof.py` | 22 | NIST CAVP vectors, tag tampering, AAD manipulation, nonce reuse, boundary sizes |
| `test_chacha20_wycheproof.py` | 10 | RFC 8439 vectors, tag/nonce/AAD attacks |
| `test_ed25519_wycheproof.py` | 12 | RFC 8032 vectors, malleability, tampered R/S, wrong key |
| `test_x25519_wycheproof.py` | 12 | RFC 7748 vectors, low-order points, small subgroup |
| `test_ecdsa_wycheproof.py` | 18 | Signature malleability (r,-s), invalid scalars (r=0,s≥n), cross-curve |
| `test_rsa_wycheproof.py` | 11 | OAEP/PSS roundtrips, tampered ct/sig, cross-key, key size |
| `test_hashes_kdf_wycheproof.py` | 30 | NIST/FIPS vectors, HMAC, HKDF RFC 5869, PBKDF2 RFC 7914, tagged hash |
| `test_attack_simulations.py` | 9 | GCM forbidden attack, ECDSA nonce reuse, ChaCha20 nonce reuse, cross-algo |
| `test_fuzz_hypothesis.py` | 62 | Property-based: AEAD roundtrip, hash determinism, HMAC, Ed25519, HKDF, tamper detection |

## Bugs Found and Fixed

| Bug | Severity | Fix |
|-----|----------|-----|
| `_encode_signature(0, x)` IndexError | Medium | Handle `x=0` in DER integer encoding |
| AES-GCM GHASH empty AAD | Medium | GHASH with empty AAD returns zero block |
| Ed25519 Edwards addition formula | High | `y1*y2+x1*x2` not `y1*y2-x1*x2` for extended coords |
| RSA Baillie-PSW replacing 40-round MR | Medium | Stronger primality test (no known counterexamples) |

## Known Limitations

- Pure Python: not constant-time (timing side-channels)
- SHA-256 ~200× slower than C-backed hashlib
- RSA keygen ~3-5s for 2048-bit
- ECDSA signature malleability: (r,s) and (r,-s mod n) both verify

## Verification Commands

```bash
pip install -e ".[dev]"
pytest tests/ -v                    # 252 pytest tests
python selftest.py                   # 9 self-test checks
python verify_pure_python.py         # No C-backed imports
```
