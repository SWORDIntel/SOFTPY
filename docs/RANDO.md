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
│  DigitalURandom / os.urandom (fallback)  │
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
from crypto_standalone import HMAC_DRBG_SHA256

# Initialize with 32+ bytes of entropy
drbg = HMAC_DRBG_SHA256(entropy_input=os.urandom(32))

# Generate random bytes
data = drbg.generate(32)

# Reseed with fresh entropy
drbg.reseed(os.urandom(32))
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

## Security Notes

- **DigitalURandom** is designed for environments where `os.urandom` is unavailable or untrusted
- **HMAC_DRBG** provides backtracking resistance and prediction resistance
- **All entropy is conditioned** through SHA-256 before use — raw jitter is never used directly
- **Fallback**: If no entropy sources are available, raises `RuntimeError` rather than returning weak randomness
