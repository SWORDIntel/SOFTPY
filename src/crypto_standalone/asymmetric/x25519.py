"""Pure-Python X25519 ECDH (RFC 7748). Montgomery curve Curve25519."""

from __future__ import annotations

try:
    from ..utils.random import random_bytes
except ImportError:
    try:
        from random_source import random_bytes
    except ImportError:
        from random import random_bytes

_P = 2**255 - 19
_A24 = 121665


def _cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    """Constant-time conditional swap (best-effort in Python)."""
    dummy = swap * ((x_2 ^ x_3) & ((1 << 256) - 1))
    x_2 ^= dummy
    x_3 ^= dummy
    return x_2, x_3


def _x25519_scalarmult(k: bytes, u: bytes) -> bytes:
    """
    X25519 scalar multiplication (RFC 7748 §5).
    Computes k * u on Curve25519 using Montgomery ladder.
    """
    if len(k) != 32 or len(u) != 32:
        raise ValueError("k and u must be 32 bytes")
    
    k_scalar = int.from_bytes(k, "little")
    k_scalar &= (1 << 255) - 1
    k_scalar &= ~7
    k_scalar |= (1 << 254)
    
    u_coord = int.from_bytes(u, "little") % _P
    
    x_1 = u_coord
    x_2 = 1
    z_2 = 0
    x_3 = u_coord
    z_3 = 1
    swap = 0
    
    for t in range(254, -1, -1):
        k_t = (k_scalar >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t
        
        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x_3 = ((DA + CB) ** 2) % _P
        z_3 = (x_1 * ((DA - CB) ** 2)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P
    
    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    
    result = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


def x25519_keygen(private_key: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Generate X25519 keypair.
    Returns (private_key, public_key) where both are 32 bytes.
    """
    if private_key is None:
        private_key = random_bytes(32)
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    
    basepoint = bytes([9]) + bytes(31)
    public_key = _x25519_scalarmult(private_key, basepoint)
    return private_key, public_key


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """
    Perform X25519 ECDH.
    Returns 32-byte shared secret.
    """
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    
    return _x25519_scalarmult(private_key, public_key)


def x25519_public_key(private_key: bytes) -> bytes:
    """Derive public key from private key."""
    if len(private_key) != 32:
        raise ValueError("private key must be 32 bytes")
    _, public_key = x25519_keygen(private_key)
    return public_key
