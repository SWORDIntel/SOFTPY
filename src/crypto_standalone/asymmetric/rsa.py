"""Standalone RSA helpers with standard-library only primitives."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple

try:
    from ..hashing.sha2 import sha1, sha256, compare_digest
except ImportError:
    try:
        from hashes import sha1, sha256, compare_digest
    except ImportError:
        from sha2 import sha1, sha256, compare_digest

try:
    from ..utils.random import random_bits, random_below, random_bytes
except ImportError:
    try:
        from random_source import random_bits, random_below, random_bytes
    except ImportError:
        from random import random_bits, random_below, random_bytes


def _randbits(k: int) -> int:
    return random_bits(k)


def _randbelow(n: int) -> int:
    return random_below(n)


def _token_bytes(n: int) -> bytes:
    return random_bytes(n)


_HASH_SPECS = {
    "sha1": {
        "name": "SHA1",
        "hash": sha1,
        "len": 20,
        "digest_info": bytes.fromhex(
            "3021300D06052B0E03021A05000414"
        ),
    },
    "sha256": {
        "name": "SHA-256",
        "hash": sha256,
        "len": 32,
        "digest_info": bytes.fromhex(
            "3031300D060960864801650304020105000420"
        ),
    },
}

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
    1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
    1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
    1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361,
    1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
    1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531,
    1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
    1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699,
    1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
    1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
    1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
    1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083,
    2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273,
    2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
    2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441,
    2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
    2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663,
    2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
    2731, 2741, 2749, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833,
    2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939,
    2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041,
    3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
    3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
    3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347,
    3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461,
    3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
    3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631,
    3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
    3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833,
    3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923,
    3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021,
    4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129,
    4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,
    4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337,
    4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447,
    4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547,
    4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649,
    4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
    4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871,
    4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967,
    4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051,
    5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167,
    5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
    5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399,
    5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479,
    5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573,
    5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683,
    5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
    5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867,
    5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007,
    6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101,
    6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211,
    6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
    6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379,
    6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529,
    6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637,
    6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733,
    6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
    6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949,
    6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027,
    7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159,
    7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253,
    7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
    7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517,
    7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589,
    7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691,
    7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817,
    7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
]


def _i2osp(x: int, length: int) -> bytes:
    if x < 0 or x >= 1 << (8 * length):
        raise ValueError("integer too large")
    return x.to_bytes(length, "big")


def _os2ip(x: bytes) -> int:
    return int.from_bytes(x, "big")


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def _invmod(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def _miller_rabin_base2(n: int) -> bool:
    """Miller-Rabin primality test with base 2."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    x = pow(2, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def _jacobi(a: int, n: int) -> int:
    """Jacobi symbol (a/n). Used in Lucas test."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be odd positive")
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    return result if n == 1 else 0


def _strong_lucas_test(n: int) -> bool:
    """Strong Lucas primality test (Baillie-PSW component)."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    D = 5
    while True:
        if _jacobi(D, n) == -1:
            break
        D = -D - 2 if D > 0 else -D + 2
        if abs(D) > 10000:
            return False
    
    Q = (1 - D) // 4
    d = n + 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    def _lucas_chain(k: int) -> tuple[int, int]:
        U, V, Q_k = 0, 2, 1
        for bit in bin(k)[2:]:
            U_new = (U * V) % n
            V_new = (V * V - 2 * Q_k) % n
            Q_k = (Q_k * Q_k) % n
            U, V = U_new, V_new
            if bit == '1':
                U_new = (U + V) % n
                if U_new % 2 == 1:
                    U_new += n
                U_new //= 2
                V_new = (D * U + V) % n
                if V_new % 2 == 1:
                    V_new += n
                V_new //= 2
                Q_k = (Q_k * Q) % n
                U, V = U_new, V_new
        return U, V
    
    U, V = _lucas_chain(d)
    if U == 0 or V == 0:
        return True
    
    for _ in range(s):
        V = (V * V - 2 * pow(Q, d * (2 ** _), n)) % n
        if V == 0:
            return True
        d *= 2
    
    return False


def _is_probable_prime(n: int) -> bool:
    """Baillie-PSW primality test (no known composites pass as of 2026)."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    
    if not _miller_rabin_base2(n):
        return False
    if not _strong_lucas_test(n):
        return False
    return True


def _gen_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("prime size too small")
    while True:
        p = _randbits(bits)
        p |= (1 << (bits - 1))
        p |= 1
        for small_p in _SMALL_PRIMES:
            if p % small_p == 0 and p != small_p:
                break
        else:
            if _is_probable_prime(p):
                return p


def _pkcs1_v1_5_encode(message_digest: bytes, algorithm: str, em_len: int) -> bytes:
    spec = _HASH_SPECS[algorithm]
    digest_info = spec["digest_info"] + message_digest
    if len(digest_info) > em_len - 3:
        raise ValueError("hash too long for modulus")
    ps = b"\xFF" * (em_len - len(digest_info) - 3)
    if len(ps) < 8:
        raise ValueError("invalid RSA key length for this hash")
    return b"\x00\x01" + ps + b"\x00" + digest_info


def _pkcs1_v1_5_decode(plaintext: bytes, block_type: int) -> bytes:
    # block_type: 2 for encryption, 1 for signatures
    if len(plaintext) < 11 or plaintext[0] != 0:
        raise ValueError("invalid decrypted block")
    if plaintext[1] != block_type:
        raise ValueError("invalid block type")
    sep = plaintext.find(b"\x00", 2)
    if sep < 2 or sep < 10:
        raise ValueError("invalid padding")
    if block_type == 1 and plaintext[2:sep].rstrip(b"\xFF") != b"":
        raise ValueError("invalid private padding")
    if block_type == 2 and b"\x00" in plaintext[2:sep]:
        raise ValueError("invalid encryption padding")
    return plaintext[sep + 1 :]


def _pad_for_encryption(data: bytes, em_len: int) -> bytes:
    if len(data) > em_len - 11:
        raise ValueError("message too long")
    pad_len = em_len - len(data) - 3
    padding = bytearray()
    while len(padding) < pad_len:
        b = _token_bytes(1)
        if b != b"\x00":
            padding.extend(b)
    return b"\x00\x02" + bytes(padding) + b"\x00" + data


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(sha256(seed + counter.to_bytes(4, "big")))
        counter += 1
    return bytes(output[:length])


def _oaep_encode(message: bytes, em_len: int, label: bytes = b"") -> bytes:
    h_len = 32
    if len(message) > em_len - 2 * h_len - 2:
        raise ValueError("message too long")
    l_hash = sha256(label)
    ps = b"\x00" * (em_len - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = _token_bytes(h_len)
    db_mask = _mgf1_sha256(seed, em_len - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = _mgf1_sha256(masked_db, h_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def _oaep_decode(em: bytes, label: bytes = b"") -> bytes:
    h_len = 32
    if len(em) < 2 * h_len + 2:
        raise ValueError("decryption error")
    if em[0] != 0:
        raise ValueError("decryption error")
    masked_seed = em[1 : h_len + 1]
    masked_db = em[h_len + 1 :]
    seed_mask = _mgf1_sha256(masked_db, h_len)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = _mgf1_sha256(seed, len(masked_db))
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    l_hash = sha256(label)
    if not compare_digest(db[:h_len], l_hash):
        raise ValueError("decryption error")
    i = h_len
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError("decryption error")
    return db[i + 1 :]


def _pss_encode(m_hash: bytes, em_bits: int, s_len: int) -> bytes:
    h_len = 32
    em_len = (em_bits + 7) // 8
    if em_len < h_len + s_len + 2:
        raise ValueError("encoding error")
    salt = _token_bytes(s_len)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = sha256(m_prime)
    ps = b"\x00" * (em_len - s_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1_sha256(h, em_len - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    masked_db = bytes([(masked_db[0] & (0xFF >> (8 * em_len - em_bits)))] + list(masked_db[1:]))
    return masked_db + h + b"\xBC"


def _pss_verify(m_hash: bytes, em: bytes, em_bits: int, s_len: int) -> bool:
    h_len = 32
    em_len = (em_bits + 7) // 8
    if em_len < h_len + s_len + 2:
        return False
    if em[-1] != 0xBC:
        return False
    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : -1]
    if masked_db[0] & (0xFF << (8 - (8 * em_len - em_bits))):
        return False
    db_mask = _mgf1_sha256(h, em_len - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    db = bytes([(db[0] & (0xFF >> (8 * em_len - em_bits)))] + list(db[1:]))
    for i in range(em_len - h_len - s_len - 2):
        if db[i] != 0:
            return False
    if db[em_len - h_len - s_len - 2] != 1:
        return False
    salt = db[-s_len:] if s_len > 0 else b""
    m_prime = b"\x00" * 8 + m_hash + salt
    h_prime = sha256(m_prime)
    return compare_digest(h, h_prime)


@dataclass(frozen=True)
class RSAKeyPair:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inv: int

    @property
    def public(self) -> "RSAPublicKey":
        return RSAPublicKey(self.n, self.e)

    @property
    def private(self) -> "RSAPrivateKey":
        return RSAPrivateKey(self.n, self.e, self.d, self.p, self.q, self.dp, self.dq, self.q_inv)


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def encrypt(self, message: bytes) -> bytes:
        em = _pad_for_encryption(message, self.size)
        m = _os2ip(em)
        c = pow(m, self.e, self.n)
        return _i2osp(c, self.size)

    def encrypt_oaep(self, message: bytes, label: bytes = b"") -> bytes:
        em = _oaep_encode(message, self.size, label)
        m = _os2ip(em)
        c = pow(m, self.e, self.n)
        return _i2osp(c, self.size)

    def verify(self, message: bytes, signature: bytes, hash_name: str = "sha256") -> bool:
        if len(signature) != self.size:
            return False
        hash_name = hash_name.lower()
        if hash_name not in _HASH_SPECS:
            raise ValueError("unsupported hash")
        expected = _HASH_SPECS[hash_name]["hash"](message)
        expected_em = _pkcs1_v1_5_encode(expected, hash_name, self.size)
        m = pow(_os2ip(signature), self.e, self.n)
        actual_em = _i2osp(m, self.size)
        return compare_digest(actual_em, expected_em)

    def verify_pss(self, message: bytes, signature: bytes, hash_name: str = "sha256", salt_len: int = 32) -> bool:
        if len(signature) != self.size:
            return False
        hash_name = hash_name.lower()
        if hash_name not in _HASH_SPECS:
            raise ValueError("unsupported hash")
        m_hash = _HASH_SPECS[hash_name]["hash"](message)
        s = _os2ip(signature)
        m = pow(s, self.e, self.n)
        em_len = (self.n.bit_length() - 1 + 7) // 8
        em = _i2osp(m, em_len)
        return _pss_verify(m_hash, em, self.n.bit_length() - 1, salt_len)


@dataclass(frozen=True)
class RSAPrivateKey(RSAPublicKey):
    d: int
    p: int
    q: int
    dp: int
    dq: int
    q_inv: int

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.size:
            raise ValueError("invalid ciphertext length")
        c = _os2ip(ciphertext)
        m1 = pow(c, self.dp, self.p)
        m2 = pow(c, self.dq, self.q)
        h = (self.q_inv * (m1 - m2)) % self.p
        m = m2 + h * self.q
        em = _i2osp(m, self.size)
        return _pkcs1_v1_5_decode(em, 2)

    def decrypt_oaep(self, ciphertext: bytes, label: bytes = b"") -> bytes:
        if len(ciphertext) != self.size:
            raise ValueError("invalid ciphertext length")
        c = _os2ip(ciphertext)
        m1 = pow(c, self.dp, self.p)
        m2 = pow(c, self.dq, self.q)
        h = (self.q_inv * (m1 - m2)) % self.p
        m = m2 + h * self.q
        em = _i2osp(m, self.size)
        return _oaep_decode(em, label)

    def sign(self, message: bytes, hash_name: str = "sha256") -> bytes:
        hash_name = hash_name.lower()
        if hash_name not in _HASH_SPECS:
            raise ValueError("unsupported hash")
        digest = _HASH_SPECS[hash_name]["hash"](message)
        em = _pkcs1_v1_5_encode(digest, hash_name, self.size)
        m = _os2ip(em)
        s = pow(m, self.d, self.n)
        return _i2osp(s, self.size)

    def sign_pss(self, message: bytes, hash_name: str = "sha256", salt_len: int = 32) -> bytes:
        hash_name = hash_name.lower()
        if hash_name not in _HASH_SPECS:
            raise ValueError("unsupported hash")
        m_hash = _HASH_SPECS[hash_name]["hash"](message)
        em_bits = self.n.bit_length() - 1
        em = _pss_encode(m_hash, em_bits, salt_len)
        m = _os2ip(em)
        s = pow(m, self.d, self.n)
        return _i2osp(s, self.size)


def generate_rsa_keypair(modulus_bits: int = 2048, public_exponent: int = 65537) -> RSAKeyPair:
    if modulus_bits < 2048:
        raise ValueError("use at least 2048-bit RSA for practical security")
    if public_exponent & 1 == 0 or public_exponent <= 2:
        raise ValueError("invalid public exponent")

    half = modulus_bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % public_exponent == 0:
            continue
        try:
            d = _invmod(public_exponent, phi)
        except ValueError:
            continue
        break

    n = p * q
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = _invmod(q, p)
    return RSAKeyPair(n=n, e=public_exponent, d=d, p=p, q=q, dp=dp, dq=dq, q_inv=q_inv)
