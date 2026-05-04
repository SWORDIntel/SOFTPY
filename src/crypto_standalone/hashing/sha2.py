"""Pure-Python hash and HMAC primitives (no hashlib/hmac imports)."""

from __future__ import annotations


def _rotr(n: int, b: int) -> int:
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF


def _rotl(n: int, b: int) -> int:
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _parity(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def sha1(data: bytes) -> bytes:
    """Pure-Python SHA-1 (FIPS 180-4)."""
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    ml = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((55 - len(data)) % 64)
    data += ml.to_bytes(8, "big")

    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start : chunk_start + 64]
        w = list(int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4))
        for i in range(16, 80):
            w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f, k = _ch(b, c, d), 0x5A827999
            elif i < 40:
                f, k = _parity(b, c, d), 0x6ED9EBA1
            elif i < 60:
                f, k = _maj(b, c, d), 0x8F1BBCDC
            else:
                f, k = _parity(b, c, d), 0xCA62C1D6
            temp = (_rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, _rotl(b, 30), a, temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return b"".join(x.to_bytes(4, "big") for x in (h0, h1, h2, h3, h4))


def sha256(data: bytes) -> bytes:
    """Pure-Python SHA-256 (FIPS 180-4)."""
    K = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]

    h0, h1, h2, h3, h4, h5, h6, h7 = (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    )

    ml = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((55 - len(data)) % 64)
    data += ml.to_bytes(8, "big")

    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start : chunk_start + 64]
        w = [int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = _ch(e, f, g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = _maj(a, b, c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return b"".join(x.to_bytes(4, "big") for x in (h0, h1, h2, h3, h4, h5, h6, h7))


def sha1_hex(data: bytes) -> str:
    return sha1(data).hex()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def hmac_sha1(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA1 (RFC 2104)."""
    block_size = 64
    if len(key) > block_size:
        key = sha1(key)
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))
    o_key_pad = bytes(x ^ 0x5C for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return sha1(o_key_pad + sha1(i_key_pad + message))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 (RFC 2104)."""
    block_size = 64
    if len(key) > block_size:
        key = sha256(key)
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))
    o_key_pad = bytes(x ^ 0x5C for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return sha256(o_key_pad + sha256(i_key_pad + message))


def compare_digest(a: bytes, b: bytes) -> bool:
    """Constant-time comparison."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _rotr64(n: int, b: int) -> int:
    return ((n >> b) | (n << (64 - b))) & 0xFFFFFFFFFFFFFFFF


def _sha512_compress(state: list[int], chunk: bytes) -> None:
    K512 = [
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    ]
    M = 0xFFFFFFFFFFFFFFFF
    w = [int.from_bytes(chunk[i : i + 8], "big") for i in range(0, 128, 8)]
    for i in range(16, 80):
        s0 = _rotr64(w[i-15], 1) ^ _rotr64(w[i-15], 8) ^ (w[i-15] >> 7)
        s1 = _rotr64(w[i-2], 19) ^ _rotr64(w[i-2], 61) ^ (w[i-2] >> 6)
        w.append((w[i-16] + s0 + w[i-7] + s1) & M)
    a, b, c, d, e, f, g, h = state
    for i in range(80):
        S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + K512[i] + w[i]) & M
        S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & M
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & M, c, b, a, (temp1 + temp2) & M
    M64 = 0xFFFFFFFFFFFFFFFF
    state[0] = (state[0] + a) & M64
    state[1] = (state[1] + b) & M64
    state[2] = (state[2] + c) & M64
    state[3] = (state[3] + d) & M64
    state[4] = (state[4] + e) & M64
    state[5] = (state[5] + f) & M64
    state[6] = (state[6] + g) & M64
    state[7] = (state[7] + h) & M64


def _sha512_family(data: bytes, iv: list[int], out_len: int) -> bytes:
    ml = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((111 - len(data)) % 128)
    data += (0).to_bytes(8, "big") + ml.to_bytes(8, "big")
    state = list(iv)
    for i in range(0, len(data), 128):
        _sha512_compress(state, data[i : i + 128])
    raw = b"".join(x.to_bytes(8, "big") for x in state)
    return raw[:out_len]


def sha512(data: bytes) -> bytes:
    """Pure-Python SHA-512 (FIPS 180-4)."""
    iv = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    ]
    return _sha512_family(data, iv, 64)


def sha384(data: bytes) -> bytes:
    """Pure-Python SHA-384 (FIPS 180-4)."""
    iv = [
        0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
    ]
    return _sha512_family(data, iv, 48)


def sha512_hex(data: bytes) -> str:
    return sha512(data).hex()


def sha384_hex(data: bytes) -> str:
    return sha384(data).hex()


def hmac_sha384(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA384 (RFC 2104)."""
    block_size = 128
    if len(key) > block_size:
        key = sha384(key)
    key = key + b"\x00" * (block_size - len(key))
    o_key_pad = bytes(x ^ 0x5C for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return sha384(o_key_pad + sha384(i_key_pad + message))


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA512 (RFC 2104)."""
    block_size = 128
    if len(key) > block_size:
        key = sha512(key)
    key = key + b"\x00" * (block_size - len(key))
    o_key_pad = bytes(x ^ 0x5C for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return sha512(o_key_pad + sha512(i_key_pad + message))


def tagged_hash(tag: str, data: bytes, hash_fn=None) -> bytes:
    """Domain-separated hash per BIP-340 style (prevents cross-protocol attacks)."""
    if hash_fn is None:
        hash_fn = sha256
    tag_hash = hash_fn(tag.encode("utf-8"))
    return hash_fn(tag_hash + tag_hash + data)
