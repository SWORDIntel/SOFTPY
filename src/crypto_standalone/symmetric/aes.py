"""Pure-Python AES-256-CBC + PKCS7 helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os


def _xtime(a: int) -> int:
    a &= 0xFF
    carry = a & 0x80
    a = (a << 1) & 0xFF
    if carry:
        a ^= 0x1B
    return a


def _mul(a: int, b: int) -> int:
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _build_sbox_and_inv() -> tuple[list[int], list[int]]:
    sbox = [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5C,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]
    inv = [0] * 256
    for i, value in enumerate(sbox):
        inv[value] = i
    return sbox, inv


def _build_rcon() -> list[int]:
    rcon = [0x01]
    for _ in range(1, 15):
        rcon.append(_xtime(rcon[-1]))
    return rcon


SBOX, INV_SBOX = _build_sbox_and_inv()
RCON = _build_rcon()


def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


def _inv_sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]


def _shift_rows(state: list[list[int]]) -> None:
    for r in range(1, 4):
        state[r][:] = state[r][r:] + state[r][:r]


def _inv_shift_rows(state: list[list[int]]) -> None:
    for r in range(1, 4):
        state[r][:] = state[r][-r:] + state[r][:-r]


def _mix_column(col: list[int]) -> list[int]:
    a0, a1, a2, a3 = col
    return [
        _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3,
        a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3,
        a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3),
        _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2),
    ]


def _inv_mix_column(col: list[int]) -> list[int]:
    a0, a1, a2, a3 = col
    return [
        _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9),
        _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13),
        _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11),
        _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14),
    ]


def _mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        nc = _mix_column(col)
        for r in range(4):
            state[r][c] = nc[r]


def _inv_mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        nc = _inv_mix_column(col)
        for r in range(4):
            state[r][c] = nc[r]


def _add_round_key(state: list[list[int]], rk: bytes) -> None:
    for c in range(4):
        w = int.from_bytes(rk[4 * c: 4 * (c + 1)], "big")
        for r in range(4):
            state[r][c] ^= (w >> (24 - 8 * r)) & 0xFF


def _rot_word(w: int) -> int:
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)


def _sub_word(w: int) -> int:
    return (
        (SBOX[(w >> 24) & 0xFF] << 24)
        | (SBOX[(w >> 16) & 0xFF] << 16)
        | (SBOX[(w >> 8) & 0xFF] << 8)
        | SBOX[w & 0xFF]
    )


def _key_expand(key: bytes) -> list[bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    nb = 4
    nk = 8
    nr = 14
    w = [0] * (nb * (nr + 1))

    for i in range(nk):
        w[i] = int.from_bytes(key[4 * i : 4 * (i + 1)], "big")

    for i in range(nk, nb * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // nk - 1] << 24)
        elif i % nk == 4:
            temp = _sub_word(temp)
        w[i] = w[i - nk] ^ temp

    round_keys = []
    for r in range(nr + 1):
        rk = bytearray()
        for c in range(4):
            rk.extend(w[4 * r + c].to_bytes(4, "big"))
        round_keys.append(bytes(rk))
    return round_keys


def _xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad_pkcs7(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    if n == 0:
        n = 16
    return data + bytes([n]) * n


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("bad PKCS7 data length")
    n = data[-1]
    if n < 1 or n > 16:
        raise ValueError("bad PKCS7 padding")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 padding")
    return data[:-n]


@dataclass(frozen=True)
class AES256:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("key must be 32 bytes")
        object.__setattr__(self, "_rk", _key_expand(self.key))

    @property
    def _round_keys(self) -> list[bytes]:
        return self._rk

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        state = _bytes_to_state(block)
        rks = self._round_keys

        _add_round_key(state, rks[0])
        for round_idx in range(1, 14):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, rks[round_idx])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, rks[14])
        return _state_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be 16 bytes")
        state = _bytes_to_state(block)
        rks = self._round_keys

        _add_round_key(state, rks[14])
        for round_idx in range(13, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, rks[round_idx])
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, rks[0])
        return _state_to_bytes(state)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes | None = None) -> bytes:
        if iv is None:
            iv = os.urandom(16)
        if len(iv) != 16:
            raise ValueError("iv must be 16 bytes")

        padded = _pad_pkcs7(plaintext)
        out = bytearray(iv)
        prev = iv
        for i in range(0, len(padded), 16):
            block = _xor_block(padded[i : i + 16], prev)
            prev = self.encrypt_block(block)
            out.extend(prev)
        return bytes(out)

    def decrypt_cbc(self, data: bytes) -> bytes:
        if len(data) < 32 or len(data) % 16 != 0:
            raise ValueError("invalid CBC ciphertext length")
        iv = data[:16]
        ct = data[16:]
        prev = iv
        out = bytearray()
        for i in range(0, len(ct), 16):
            dec = self.decrypt_block(ct[i : i + 16])
            out.extend(_xor_block(dec, prev))
            prev = ct[i : i + 16]
        return _unpad_pkcs7(bytes(out))

    def encrypt_ctr(self, plaintext: bytes, nonce: bytes | None = None) -> bytes:
        if nonce is None:
            nonce = os.urandom(16)
        if len(nonce) != 16:
            raise ValueError("nonce must be 16 bytes")

        out = bytearray(nonce)
        counter = 0
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            ctr_block = nonce[:8] + counter.to_bytes(8, "big")
            keystream = self.encrypt_block(ctr_block)
            out.extend(_xor_block(block, keystream[: len(block)]))
            counter += 1
        return bytes(out)

    def decrypt_ctr(self, data: bytes) -> bytes:
        if len(data) < 16:
            raise ValueError("invalid CTR ciphertext length")
        nonce = data[:16]
        ct = data[16:]
        out = bytearray()
        counter = 0
        for i in range(0, len(ct), 16):
            block = ct[i : i + 16]
            ctr_block = nonce[:8] + counter.to_bytes(8, "big")
            keystream = self.encrypt_block(ctr_block)
            out.extend(_xor_block(block, keystream[: len(block)]))
            counter += 1
        return bytes(out)
