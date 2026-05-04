"""Centralized CSPRNG — pure-Python, no os.urandom.

Uses DigitalURandom (entropy collection + HMAC-DRBG) as the sole
randomness source.  Zero calls to os.urandom, secrets, random,
hashlib, or hmac.

Import is instant — entropy collection is deferred to first use.
"""

from __future__ import annotations

import base64
import threading

from .digital_entropy import DigitalURandom, self_test


_rng: DigitalURandom | None = None
_rng_lock = threading.Lock()


def _get_rng() -> DigitalURandom:
    """Lazy-init the shared DigitalURandom (thread-safe)."""
    global _rng
    if _rng is not None:
        return _rng
    with _rng_lock:
        if _rng is None:
            self_test()
            _rng = DigitalURandom(strict_hardware=False)
        return _rng


class CSPRNG:
    """Cryptographically secure random number generator.

    Backed by DigitalURandom (pure-Python entropy collection +
    HMAC-DRBG-SHA256 per NIST SP 800-90A).  No os.urandom.
    """

    def __init__(self) -> None:
        self._test_entropy()

    def _test_entropy(self) -> None:
        """Basic health check: ensure the RNG doesn't return all zeros."""
        sample = _get_rng().urandom(32)
        if sample == b"\x00" * 32:
            raise RuntimeError("entropy source failure: all-zero output")
        if len(set(sample)) < 4:
            raise RuntimeError("entropy source failure: low diversity")

    def random_bytes(self, n: int) -> bytes:
        """Generate n random bytes."""
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        return _get_rng().urandom(n)

    def random_int(self, low: int, high: int) -> int:
        """Generate random integer in [low, high) (exclusive of high)."""
        if low >= high:
            raise ValueError("low must be < high")
        return low + self.random_below(high - low)

    def random_below(self, n: int) -> int:
        """Generate random integer in [0, n) with uniform distribution."""
        if n <= 0:
            raise ValueError("n must be positive")
        if n == 1:
            return 0
        k = n.bit_length()
        while True:
            r = int.from_bytes(self.random_bytes((k + 7) // 8), "big") >> ((-k) % 8)
            if r < n:
                return r

    def random_bits(self, k: int) -> int:
        """Generate k random bits as an integer."""
        if k < 0:
            raise ValueError("k must be non-negative")
        if k == 0:
            return 0
        return int.from_bytes(self.random_bytes((k + 7) // 8), "big") >> ((-k) % 8)


# ------------------------------------------------------------------
# Module-level convenience functions (lazy — no import-time cost)
# ------------------------------------------------------------------

def urandom(n: int) -> bytes:
    """Drop-in replacement for os.urandom(n)."""
    return _get_rng().urandom(n)


def random_bytes(n: int) -> bytes:
    """Generate n random bytes."""
    return _get_rng().urandom(n) if n > 0 else b""


def random_below(n: int) -> int:
    """Generate random integer in [0, n) with uniform distribution."""
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 0
    k = n.bit_length()
    while True:
        r = int.from_bytes(urandom((k + 7) // 8), "big") >> ((-k) % 8)
        if r < n:
            return r


def random_bits(k: int) -> int:
    """Generate k random bits as an integer."""
    if k < 0:
        raise ValueError("k must be non-negative")
    if k == 0:
        return 0
    return int.from_bytes(urandom((k + 7) // 8), "big") >> ((-k) % 8)


def token_bytes(n: int) -> bytes:
    """Return n random bytes (secrets.token_bytes compatible)."""
    return urandom(n)


def token_hex(n: int) -> str:
    """Return n random bytes as a hex string (secrets.token_hex compatible)."""
    return urandom(n).hex()


def token_urlsafe(n: int) -> str:
    """Return n random bytes as a URL-safe base64 string (secrets.token_urlsafe compatible)."""
    return base64.urlsafe_b64encode(urandom(n)).rstrip(b"=").decode("ascii")
