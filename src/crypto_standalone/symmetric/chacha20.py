"""Pure-Python ChaCha20-Poly1305 AEAD (RFC 8439). No external dependencies."""

from __future__ import annotations

import os

try:
    from ..hashing.sha2 import compare_digest
except ImportError:
    try:
        from hashes import compare_digest
    except ImportError:
        from sha2 import compare_digest

_M32 = 0xFFFFFFFF
_M128 = (1 << 128) - 1
_P = (1 << 130) - 5


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _M32


def _chacha20_quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    a = (a + b) & _M32; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & _M32; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & _M32; d ^= a; d = _rotl32(d, 8)
    c = (c + d) & _M32; b ^= c; b = _rotl32(b, 7)
    return a, b, c, d


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    nonce_words = [int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)]

    state = CONST + key_words + [counter & _M32] + nonce_words
    working = list(state)

    for _ in range(10):
        working[0], working[4], working[8],  working[12] = _chacha20_quarter_round(working[0], working[4], working[8],  working[12])
        working[1], working[5], working[9],  working[13] = _chacha20_quarter_round(working[1], working[5], working[9],  working[13])
        working[2], working[6], working[10], working[14] = _chacha20_quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = _chacha20_quarter_round(working[3], working[7], working[11], working[15])
        working[0], working[5], working[10], working[15] = _chacha20_quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = _chacha20_quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = _chacha20_quarter_round(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = _chacha20_quarter_round(working[3], working[4], working[9],  working[14])

    out = bytearray()
    for i in range(16):
        out += ((working[i] + state[i]) & _M32).to_bytes(4, "little")
    return bytes(out)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    """ChaCha20 stream cipher (RFC 8439 §2.4). counter is the initial block counter."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    out = bytearray()
    for i in range(0, len(plaintext), 64):
        keystream = _chacha20_block(key, counter + i // 64, nonce)
        block = plaintext[i : i + 64]
        out.extend(a ^ b for a, b in zip(block, keystream))
    return bytes(out)


def _poly1305_mac(key: bytes, msg: bytes) -> bytes:
    """Poly1305 MAC (RFC 8439 §2.5)."""
    assert len(key) == 32
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")

    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = (r * (acc + n)) % _P

    acc = (acc + s) & _M128
    return acc.to_bytes(16, "little")


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Generate Poly1305 one-time key using ChaCha20 block 0 (RFC 8439 §2.6)."""
    block = _chacha20_block(key, 0, nonce)
    return block[:32]


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data + b"\x00" * (16 - rem) if rem else data


class ChaCha20Poly1305:
    """ChaCha20-Poly1305 AEAD (RFC 8439)."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self._key = key

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        """Encrypt plaintext. Returns (ciphertext, 16-byte tag)."""
        if nonce is None:
            nonce = os.urandom(12)
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")

        otk = _poly1305_key_gen(self._key, nonce)
        ciphertext = chacha20_encrypt(self._key, 1, nonce, plaintext)
        mac_data = (
            _pad16(aad) +
            _pad16(ciphertext) +
            len(aad).to_bytes(8, "little") +
            len(ciphertext).to_bytes(8, "little")
        )
        tag = _poly1305_mac(otk, mac_data)
        return ciphertext, tag

    def encrypt_blob(self, plaintext: bytes, nonce: bytes | None = None, aad: bytes = b"") -> bytes:
        """Encrypt and return nonce + ciphertext + tag as a single blob."""
        if nonce is None:
            nonce = os.urandom(12)
        ct, tag = self.encrypt(plaintext, nonce, aad)
        return nonce + ct + tag

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Decrypt and verify. Raises ValueError if authentication fails."""
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        if len(tag) != 16:
            raise ValueError("tag must be 16 bytes")

        otk = _poly1305_key_gen(self._key, nonce)
        mac_data = (
            _pad16(aad) +
            _pad16(ciphertext) +
            len(aad).to_bytes(8, "little") +
            len(ciphertext).to_bytes(8, "little")
        )
        expected_tag = _poly1305_mac(otk, mac_data)
        if not compare_digest(tag, expected_tag):
            raise ValueError("authentication failed")

        return chacha20_encrypt(self._key, 1, nonce, ciphertext)

    def decrypt_blob(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Decrypt a blob produced by encrypt_blob: nonce(12) + ciphertext + tag(16)."""
        if len(blob) < 28:
            raise ValueError("blob too short")
        nonce = blob[:12]
        tag = blob[-16:]
        ciphertext = blob[12:-16]
        return self.decrypt(ciphertext, tag, nonce, aad)
