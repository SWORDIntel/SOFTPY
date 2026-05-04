"""Pure-Python key derivation functions: HKDF (RFC 5869) and PBKDF2 (RFC 2898)."""

from __future__ import annotations

try:
    from ..hashing.sha2 import hmac_sha256, hmac_sha512, compare_digest
except ImportError:
    try:
        from hashes import hmac_sha256, hmac_sha512, compare_digest
    except ImportError:
        from sha2 import hmac_sha256, hmac_sha512, compare_digest


def hkdf_extract(salt: bytes | None, ikm: bytes, hash_fn=None) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2). Extracts a pseudorandom key from input keying material."""
    if hash_fn is None:
        hash_fn = hmac_sha256
    if salt is None or len(salt) == 0:
        hash_len = len(hash_fn(b"", b""))
        salt = b"\x00" * hash_len
    return hash_fn(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes | None, length: int, hash_fn=None) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3). Expands a pseudorandom key to desired length."""
    if hash_fn is None:
        hash_fn = hmac_sha256
    if info is None:
        info = b""
    hash_len = len(hash_fn(b"", b""))
    if length > 255 * hash_len:
        raise ValueError("output length too large")
    
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hash_fn(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf(salt: bytes | None, ikm: bytes, info: bytes | None, length: int, hash_fn=None) -> bytes:
    """HKDF one-shot (RFC 5869). Combines extract and expand."""
    if hash_fn is None:
        hash_fn = hmac_sha256
    prk = hkdf_extract(salt, ikm, hash_fn)
    return hkdf_expand(prk, info, length, hash_fn)


def hkdf_sha256(salt: bytes | None, ikm: bytes, info: bytes | None, length: int) -> bytes:
    """HKDF with SHA-256."""
    return hkdf(salt, ikm, info, length, hmac_sha256)


def hkdf_sha512(salt: bytes | None, ikm: bytes, info: bytes | None, length: int) -> bytes:
    """HKDF with SHA-512."""
    return hkdf(salt, ikm, info, length, hmac_sha512)


def pbkdf2_hmac(password: bytes, salt: bytes, iterations: int, dklen: int, hash_fn=None) -> bytes:
    """PBKDF2-HMAC (RFC 2898). Password-based key derivation with iteration count."""
    if hash_fn is None:
        hash_fn = hmac_sha256
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    
    hash_len = len(hash_fn(b"", b""))
    if dklen > (2**32 - 1) * hash_len:
        raise ValueError("derived key too long")
    
    num_blocks = (dklen + hash_len - 1) // hash_len
    dk = b""
    
    for block_num in range(1, num_blocks + 1):
        u = hash_fn(password, salt + block_num.to_bytes(4, "big"))
        result = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hash_fn(password, u)
            result ^= int.from_bytes(u, "big")
        dk += result.to_bytes(hash_len, "big")
    
    return dk[:dklen]


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA256. OWASP 2023 recommends 600,000+ iterations."""
    return pbkdf2_hmac(password, salt, iterations, dklen, hmac_sha256)


def pbkdf2_sha512(password: bytes, salt: bytes, iterations: int, dklen: int = 64) -> bytes:
    """PBKDF2-HMAC-SHA512. OWASP 2023 recommends 210,000+ iterations."""
    return pbkdf2_hmac(password, salt, iterations, dklen, hmac_sha512)
