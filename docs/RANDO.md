# Random Number Generation — crypto_standalone

## Architecture

Three-tier RNG stack, all pure-Python:

```
┌─────────────────────────────────────────┐
│  Application layer                       │
│  random_bytes(), random_below(), CSPRNG  │
├─────────────────────────────────────────┤
│  DRBG layer                              │
│  HMAC_DRBG_SHA256 (NIST SP 800-90A)      │
├─────────────────────────────────────────┤
│  Entropy layer                           │
│  DigitalURandom (no os.urandom)          │
└─────────────────────────────────────────┘
```

## DigitalURandom

Pure-Python entropy collector. **No os.urandom, secrets, random, hashlib, hmac, ctypes, or subprocess.**

### Entropy Sources

| Source | Method | Availability |
|--------|--------|-------------|
| TPM 2.0 | `/dev/tpmrm0`, `/dev/tpm0` | Linux with TPM |
| Hardware RNG | `/dev/hwrng` | Linux with HW RNG |
| Timer jitter | `time.perf_counter_ns()` delta hashing | Always |
| Thread scheduler | Thread race timing | Always |
| Allocator/GC | `gc.collect()` + allocation timing | Always |
| Linux proc/sysfs | `/proc/sys/kernel/random/entropy_avail`, etc. | Linux |

### Conditioning

1. **SHA-256 extractor**: All raw entropy pooled and hashed
2. **HMAC_DRBG_SHA256**: NIST SP 800-90A expansion with reseed interval 2^48

### Self-Test

```python
from crypto_standalone import self_test
self_test()  # Runs health checks on all entropy sources
```

## HMAC_DRBG_SHA256

NIST SP 800-90A §10.1.2 compliant deterministic random bit generator.

```python
from crypto_standalone import HMAC_DRBG_SHA256, DigitalURandom

# Initialize with 32+ bytes of entropy
rng = DigitalURandom()
drbg = HMAC_DRBG_SHA256(entropy_input=rng.urandom(32))

# Generate random bytes
data = drbg.random_bytes(32)

# Reseed with fresh entropy
drbg.reseed(rng.urandom(32))
```

### NIST Compliance

- **Reseed interval**: 2^48 generate calls
- **Max bytes per request**: 65536
- **Prediction resistance**: Optional via `reseed()`
- **Personalization string**: Optional domain separation
- **Additional input**: Supported per generate call

## CSPRNG Wrapper

High-level API used internally by all crypto operations:

```python
from crypto_standalone import random_bytes, random_below, random_bits, CSPRNG

# Random bytes
key = random_bytes(32)

# Random integer in [0, n)
k = random_below(P256.n)

# Random bits
r = random_bits(256)

# Class-based API
rng = CSPRNG()
nonce = rng.random_bytes(12)
```

## Drop-In Replacement Guide

Replace `os.urandom`, `secrets`, and `random` in any codebase:

| Replace this | With this |
|---|---|
| `os.urandom(n)` | `random_bytes(n)` or `DigitalURandom().urandom(n)` |
| `secrets.token_bytes(n)` | `random_bytes(n)` |
| `secrets.token_hex(n)` | `DigitalURandom().hex(n)` |
| `secrets.randbelow(n)` | `random_below(n)` |
| `secrets.randbits(k)` | `random_bits(k)` |
| `random.randint(a, b)` | `CSPRNG().random_int(a, b+1)` |
| `random.getrandbits(k)` | `random_bits(k)` |

### Quick patterns

```python
# One-liner: just need random bytes
from crypto_standalone import random_bytes
key = random_bytes(32)

# Hex tokens (API keys, session IDs, etc.)
from crypto_standalone import DigitalURandom
rng = DigitalURandom()
api_key = rng.hex(32)    # 64-char hex string

# Random integer in range (e.g. picking an index, nonce)
from crypto_standalone import random_below
idx = random_below(1000)  # 0 <= idx < 1000

# Random bitmask (e.g. flags, bit fields)
from crypto_standalone import random_bits
flags = random_bits(8)    # 0–255

# Persistent RNG instance (avoids re-seeding per call)
from crypto_standalone import CSPRNG
rng = CSPRNG()
nonce = rng.random_bytes(12)
counter = rng.random_below(2**32)
mask = rng.random_bits(128)
```

### Strict hardware mode

Require at least 32 bytes from TPM/hwrng before proceeding:

```python
rng = DigitalURandom(strict_hardware=True)  # raises if no HW entropy
```

### Network timing (optional supplemental source)

```python
rng = DigitalURandom(use_network=True)  # mixes socket timing into pool
```

## RNG Validation TUI

Interactive tool to swap RNG backends and run tests:

```bash
python tools/rng_tui.py
```

Features:
- **Switch backends**: `os.urandom` ↔ `DigitalURandom` at runtime
- **Quick sanity check**: 32-byte or 1 KiB throughput test
- **Run test suites**: unit / adversarial / all / self-test with chosen backend
- **Monkey-patch**: patch `os.urandom` system-wide so any code using it transparently uses DigitalURandom
- **Un-patch**: restore original `os.urandom`

## Security Notes

- **DigitalURandom** is designed for environments where `os.urandom` is unavailable or untrusted
- **HMAC_DRBG** provides backtracking resistance and prediction resistance
- **All entropy is conditioned** through SHA-256 before use — raw jitter is never used directly
- **Fallback**: If no entropy sources are available, raises `RuntimeError` rather than returning weak randomness
