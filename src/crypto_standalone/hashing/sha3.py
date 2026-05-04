"""Pure-Python SHA-3 / Keccak (FIPS 202). No hashlib."""

from __future__ import annotations

_M64 = 0xFFFFFFFFFFFFFFFF

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_RHO_OFFSETS = [
    [0,  36,  3, 41, 18],
    [1,  44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M64


def _keccak_f1600(A: list[list[int]]) -> None:
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]

        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl64(A[x][y], _RHO_OFFSETS[x][y])

        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        A[0][0] ^= rc


def _keccak(data: bytes, rate_bytes: int, output_len: int, domain: int) -> bytes:
    rate = rate_bytes
    A = [[0] * 5 for _ in range(5)]

    msg = bytearray(data)
    msg.append(domain)
    while len(msg) % rate != rate - 1:
        msg.append(0x00)
    msg.append(0x80)

    for block_start in range(0, len(msg), rate):
        block = msg[block_start : block_start + rate]
        lane_count = rate // 8
        for i in range(lane_count):
            lane = int.from_bytes(block[8 * i : 8 * (i + 1)], "little")
            A[i % 5][i // 5] ^= lane
        _keccak_f1600(A)

    out = bytearray()
    while len(out) < output_len:
        lane_count = rate // 8
        for i in range(lane_count):
            out += A[i % 5][i // 5].to_bytes(8, "little")
            if len(out) >= output_len:
                break
        if len(out) < output_len:
            _keccak_f1600(A)

    return bytes(out[:output_len])


def sha3_224(data: bytes) -> bytes:
    """SHA3-224 (FIPS 202)."""
    return _keccak(data, 144, 28, 0x06)


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 (FIPS 202)."""
    return _keccak(data, 136, 32, 0x06)


def sha3_384(data: bytes) -> bytes:
    """SHA3-384 (FIPS 202)."""
    return _keccak(data, 104, 48, 0x06)


def sha3_512(data: bytes) -> bytes:
    """SHA3-512 (FIPS 202)."""
    return _keccak(data, 72, 64, 0x06)


def shake_128(data: bytes, output_len: int) -> bytes:
    """SHAKE-128 extendable output function (FIPS 202)."""
    return _keccak(data, 168, output_len, 0x1F)


def shake_256(data: bytes, output_len: int) -> bytes:
    """SHAKE-256 extendable output function (FIPS 202)."""
    return _keccak(data, 136, output_len, 0x1F)


def sha3_256_hex(data: bytes) -> str:
    return sha3_256(data).hex()


def sha3_512_hex(data: bytes) -> str:
    return sha3_512(data).hex()
