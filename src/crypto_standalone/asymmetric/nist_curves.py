"""Pure-Python NIST P-256 and P-384 ECDSA + ECDH (FIPS 186-4)."""

from __future__ import annotations

try:
    from ..hashing.sha2 import sha256, sha384, compare_digest
except ImportError:
    try:
        from hashes import sha256, sha384, compare_digest
    except ImportError:
        from sha2 import sha256, sha384, compare_digest

try:
    from ..utils.random import random_bytes, random_below
except ImportError:
    try:
        from random_source import random_bytes, random_below
    except ImportError:
        from random import random_bytes, random_below


class _Curve:
    """Elliptic curve parameters."""
    def __init__(self, name: str, p: int, a: int, b: int, gx: int, gy: int, n: int):
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.g = (gx, gy)
        self.n = n
        self.h = 1


# NIST P-256 (secp256r1)
P256 = _Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

# NIST P-384 (secp384r1)
P384 = _Curve(
    "P-384",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)


def _modinv(a: int, m: int) -> int:
    """Modular inverse via Fermat's little theorem."""
    return pow(a, m - 2, m)


def _point_add(curve: _Curve, P: tuple[int, int] | None, Q: tuple[int, int] | None) -> tuple[int, int] | None:
    """Add two points on the curve."""
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2:
        if y1 == y2:
            return _point_double(curve, P)
        else:
            return None
    
    s = ((y2 - y1) * _modinv((x2 - x1) % curve.p, curve.p)) % curve.p
    x3 = (s * s - x1 - x2) % curve.p
    y3 = (s * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def _point_double(curve: _Curve, P: tuple[int, int]) -> tuple[int, int] | None:
    """Double a point on the curve."""
    x, y = P
    if y == 0:
        return None
    
    s = ((3 * x * x + curve.a) * _modinv((2 * y) % curve.p, curve.p)) % curve.p
    x3 = (s * s - 2 * x) % curve.p
    y3 = (s * (x - x3) - y) % curve.p
    return (x3, y3)


def _point_mul(curve: _Curve, k: int, P: tuple[int, int]) -> tuple[int, int] | None:
    """Scalar multiplication using double-and-add."""
    if k == 0:
        return None
    if k < 0:
        raise ValueError("scalar must be non-negative")
    
    result = None
    addend = P
    
    while k:
        if k & 1:
            result = _point_add(curve, result, addend)
        addend = _point_double(curve, addend) if addend else None
        k >>= 1
    
    return result


def _deterministic_k(curve: _Curve, private_key: int, message_hash: bytes) -> int:
    """RFC 6979 deterministic k generation (simplified)."""
    try:
        from ..hashing.sha2 import hmac_sha256
    except ImportError:
        try:
            from hashes import hmac_sha256
        except ImportError:
            from sha2 import hmac_sha256
    
    h = int.from_bytes(message_hash, "big")
    x = private_key
    q = curve.n
    
    h1 = h.to_bytes((curve.n.bit_length() + 7) // 8, "big")
    x_bytes = x.to_bytes((curve.n.bit_length() + 7) // 8, "big")
    
    v = b"\x01" * 32
    k_val = b"\x00" * 32
    
    k_val = hmac_sha256(k_val, v + b"\x00" + x_bytes + h1)
    v = hmac_sha256(k_val, v)
    k_val = hmac_sha256(k_val, v + b"\x01" + x_bytes + h1)
    v = hmac_sha256(k_val, v)
    
    while True:
        v = hmac_sha256(k_val, v)
        k_candidate = int.from_bytes(v, "big")
        if 1 <= k_candidate < q:
            return k_candidate
        k_val = hmac_sha256(k_val, v + b"\x00")
        v = hmac_sha256(k_val, v)


class ECDSAPrivateKey:
    """ECDSA private key."""
    
    def __init__(self, curve: _Curve, d: int):
        if not (1 <= d < curve.n):
            raise ValueError("invalid private key")
        self.curve = curve
        self.d = d
        self._public_key = None
    
    @property
    def public_key(self) -> 'ECDSAPublicKey':
        if self._public_key is None:
            Q = _point_mul(self.curve, self.d, self.curve.g)
            self._public_key = ECDSAPublicKey(self.curve, Q)
        return self._public_key
    
    def sign(self, message: bytes, hash_fn=None) -> bytes:
        """Sign a message. Returns DER-encoded signature."""
        if hash_fn is None:
            hash_fn = sha256 if self.curve.name == "P-256" else sha384
        
        z = int.from_bytes(hash_fn(message), "big")
        z = z % self.curve.n
        
        k = _deterministic_k(self.curve, self.d, hash_fn(message))
        R = _point_mul(self.curve, k, self.curve.g)
        if R is None:
            raise RuntimeError("signature generation failed")
        
        r = R[0] % self.curve.n
        if r == 0:
            raise RuntimeError("signature generation failed")
        
        s = (_modinv(k, self.curve.n) * (z + r * self.d)) % self.curve.n
        if s == 0:
            raise RuntimeError("signature generation failed")
        
        return _encode_signature(r, s)
    
    def ecdh(self, public_key: 'ECDSAPublicKey') -> bytes:
        """Perform ECDH key agreement."""
        if self.curve.name != public_key.curve.name:
            raise ValueError("curve mismatch")
        
        shared_point = _point_mul(self.curve, self.d, public_key.Q)
        if shared_point is None:
            raise ValueError("ECDH failed")
        
        coord_bytes = (self.curve.p.bit_length() + 7) // 8
        return shared_point[0].to_bytes(coord_bytes, "big")


class ECDSAPublicKey:
    """ECDSA public key."""
    
    def __init__(self, curve: _Curve, Q: tuple[int, int]):
        self.curve = curve
        self.Q = Q
    
    def verify(self, message: bytes, signature: bytes, hash_fn=None) -> bool:
        """Verify an ECDSA signature."""
        if hash_fn is None:
            hash_fn = sha256 if self.curve.name == "P-256" else sha384
        
        try:
            r, s = _decode_signature(signature)
            if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
                return False
            
            z = int.from_bytes(hash_fn(message), "big")
            z = z % self.curve.n
            
            w = _modinv(s, self.curve.n)
            u1 = (z * w) % self.curve.n
            u2 = (r * w) % self.curve.n
            
            point = _point_add(self.curve, _point_mul(self.curve, u1, self.curve.g), _point_mul(self.curve, u2, self.Q))
            if point is None:
                return False
            
            return point[0] % self.curve.n == r
        except Exception:
            return False


def _encode_signature(r: int, s: int) -> bytes:
    """Encode (r, s) as DER."""
    def _encode_int(x: int) -> bytes:
        if x == 0:
            b = b"\x00"
        else:
            b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    
    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    seq = r_enc + s_enc
    return b"\x30" + bytes([len(seq)]) + seq


def _decode_signature(sig: bytes) -> tuple[int, int]:
    """Decode DER signature to (r, s)."""
    if sig[0] != 0x30:
        raise ValueError("invalid signature")
    
    idx = 2
    if sig[idx] != 0x02:
        raise ValueError("invalid signature")
    idx += 1
    r_len = sig[idx]
    idx += 1
    r = int.from_bytes(sig[idx : idx + r_len], "big")
    idx += r_len
    
    if sig[idx] != 0x02:
        raise ValueError("invalid signature")
    idx += 1
    s_len = sig[idx]
    idx += 1
    s = int.from_bytes(sig[idx : idx + s_len], "big")
    
    return r, s


def p256_keygen(private_key: int | None = None) -> ECDSAPrivateKey:
    """Generate P-256 keypair."""
    if private_key is None:
        private_key = random_below(P256.n - 1) + 1
    return ECDSAPrivateKey(P256, private_key)


def p384_keygen(private_key: int | None = None) -> ECDSAPrivateKey:
    """Generate P-384 keypair."""
    if private_key is None:
        private_key = random_below(P384.n - 1) + 1
    return ECDSAPrivateKey(P384, private_key)
