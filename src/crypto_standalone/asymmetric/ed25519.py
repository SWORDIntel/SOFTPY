"""Pure-Python Ed25519 signatures (RFC 8032). Curve25519 in Edwards form."""

from __future__ import annotations

try:
    from ..hashing.sha2 import sha512
except ImportError:
    try:
        from hashes import sha512
    except ImportError:
        from sha2 import sha512

try:
    from ..utils.random import random_bytes
except ImportError:
    try:
        from random_source import random_bytes
    except ImportError:
        from random import random_bytes

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _modp_inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _modp_inv(5) % _P
_BX = _xrecover(_BY)
_B = (_BX % _P, _BY % _P)


def _edwards_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    denom_x = (1 + _D * x1 * x2 * y1 * y2) % _P
    denom_y = (1 - _D * x1 * x2 * y1 * y2) % _P
    x3 = ((x1 * y2 + x2 * y1) * _modp_inv(denom_x)) % _P
    y3 = ((y1 * y2 + x1 * x2) * _modp_inv(denom_y)) % _P
    return (x3, y3)


def _edwards_scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = (0, 1)
    for i in range(255, -1, -1):
        Q = _edwards_add(Q, Q)
        if (e >> i) & 1:
            Q = _edwards_add(Q, P)
    return Q


def _point_compress(P: tuple[int, int]) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(s: bytes) -> tuple[int, int]:
    if len(s) != 32:
        raise ValueError("invalid point encoding")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    return (x, y)


def _hint(m: bytes) -> int:
    h = sha512(m)
    return int.from_bytes(h, "little") % _L


def ed25519_keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Generate Ed25519 keypair.
    Returns (private_key, public_key) where both are 32 bytes.
    """
    if seed is None:
        seed = random_bytes(32)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    
    h = sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    
    A = _edwards_scalarmult(_B, a)
    public_key = _point_compress(A)
    return seed, public_key


def ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign a message with Ed25519.
    Returns 64-byte signature.
    """
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    
    h = sha512(private_key)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    
    A = _edwards_scalarmult(_B, a)
    public_key = _point_compress(A)
    
    r = _hint(h[32:] + message)
    R = _edwards_scalarmult(_B, r)
    R_bytes = _point_compress(R)
    
    k = _hint(R_bytes + public_key + message)
    s = (r + k * a) % _L
    
    return R_bytes + s.to_bytes(32, "little")


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 signature.
    Returns True if valid, False otherwise.
    """
    if len(signature) != 64:
        return False
    if len(public_key) != 32:
        return False
    
    try:
        R_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        
        R = _point_decompress(R_bytes)
        A = _point_decompress(public_key)
        
        k = _hint(R_bytes + public_key + message)
        
        lhs = _edwards_scalarmult(_B, s)
        rhs = _edwards_add(R, _edwards_scalarmult(A, k))
        
        return lhs == rhs
    except Exception:
        return False


def ed25519_public_key(private_key: bytes) -> bytes:
    """Derive public key from private key."""
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    _, public_key = ed25519_keygen(private_key)
    return public_key
