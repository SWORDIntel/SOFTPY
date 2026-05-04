# Testing & Caveats

## Running Tests

### Self-Test (9 checks)

```bash
python selftest.py
```

Covers: SHA-2, SHA-3, AEAD (GCM + ChaCha20-Poly1305), KDF, RSA, Ed25519, X25519, P-curves, utilities.

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

GitHub Actions: `.github/workflows/test.yml` — tests Python 3.8–3.12, unit + adversarial + self-test.

## Security Caveats

**Pure-Python implementation — not for adversarial timing environments.**

- **Timing side-channels**: Python integer arithmetic is variable-time
- **Performance**: SHA-256 is ~200× slower than C-backed `hashlib`
- **No hardware acceleration**: No AES-NI, no assembly

**Suitable for:**

- Embedded systems without C compilers
- Educational purposes
- Environments where external dependencies are forbidden
- Bootstrapping secure channels before installing native crypto

**For production, prefer:** `cryptography` (Rust/C), `pycryptodome` (C), or HSMs.
