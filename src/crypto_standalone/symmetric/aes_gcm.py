"""Pure-Python AES-256-GCM authenticated encryption (NIST SP 800-38D)."""

from __future__ import annotations

import os

try:
    from .aes import AES256
except ImportError:
    from aes import AES256

try:
    from ..hashing.sha2 import compare_digest
except ImportError:
    try:
        from hashes import compare_digest
    except ImportError:
        from sha2 import compare_digest

_M128 = (1 << 128) - 1
_R = 0xE1000000000000000000000000000000


def _ghash_mul(X: int, Y: int) -> int:
    Z = 0
    V = Y
    for i in range(128):
        if (X >> (127 - i)) & 1:
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ _R
        else:
            V >>= 1
    return Z


def _ghash(H: int, aad: bytes, ciphertext: bytes) -> int:
    def _pad16(b: bytes) -> bytes:
        rem = len(b) % 16
        return b + b"\x00" * (16 - rem) if rem else b

    X = 0
    if aad:
        padded = _pad16(aad)
        for i in range(0, len(padded), 16):
            X = _ghash_mul(X ^ int.from_bytes(padded[i : i + 16], "big"), H)
    if ciphertext:
        padded = _pad16(ciphertext)
        for i in range(0, len(padded), 16):
            X = _ghash_mul(X ^ int.from_bytes(padded[i : i + 16], "big"), H)
    length_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    X = _ghash_mul(X ^ int.from_bytes(length_block, "big"), H)
    return X


def _gctr(aes: AES256, icb: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray()
    cb = int.from_bytes(icb, "big")
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        ks = aes.encrypt_block(cb.to_bytes(16, "big"))
        out.extend(b ^ k for b, k in zip(block, ks))
        cb = ((cb & ~0xFFFFFFFF) | ((cb + 1) & 0xFFFFFFFF))
    return bytes(out)


def _inc32(b: bytes) -> bytes:
    counter = int.from_bytes(b[12:], "big")
    return b[:12] + ((counter + 1) & 0xFFFFFFFF).to_bytes(4, "big")


class AESGCM:
    """AES-256-GCM authenticated encryption."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self._aes = AES256(key)
        self._H = int.from_bytes(self._aes.encrypt_block(b"\x00" * 16), "big")

    def _compute_tag(self, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        if len(nonce) == 12:
            j0 = nonce + b"\x00\x00\x00\x01"
        else:
            pad_len = (16 - len(nonce) % 16) % 16
            ghash_in_n = nonce + b"\x00" * pad_len + b"\x00" * 8 + (len(nonce) * 8).to_bytes(8, "big")
            j0 = _ghash(self._H, b"", ghash_in_n).to_bytes(16, "big")

        s = self._aes.encrypt_block(j0)
        ghash_val = _ghash(self._H, aad, ciphertext)
        tag = int.from_bytes(s, "big") ^ ghash_val
        return tag.to_bytes(16, "big")

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None, aad: bytes = b"") -> tuple[bytes, bytes]:
        """Encrypt plaintext. Returns (ciphertext, 16-byte tag)."""
        if nonce is None:
            nonce = os.urandom(12)
        if len(nonce) < 1:
            raise ValueError("nonce must be non-empty")

        if len(nonce) == 12:
            j0 = nonce + b"\x00\x00\x00\x01"
        else:
            pad_len = (16 - len(nonce) % 16) % 16
            ghash_in_n = nonce + b"\x00" * pad_len + b"\x00" * 8 + (len(nonce) * 8).to_bytes(8, "big")
            j0 = _ghash(self._H, b"", ghash_in_n).to_bytes(16, "big")

        icb = _inc32(j0)
        ciphertext = _gctr(self._aes, icb, plaintext)
        tag = self._compute_tag(nonce, aad, ciphertext)
        return ciphertext, tag

    def encrypt_blob(self, plaintext: bytes, nonce: bytes | None = None, aad: bytes = b"") -> bytes:
        """Encrypt and return nonce + ciphertext + tag as a single blob."""
        if nonce is None:
            nonce = os.urandom(12)
        ct, tag = self.encrypt(plaintext, nonce, aad)
        return nonce + ct + tag

    def decrypt(self, ciphertext: bytes, tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Decrypt and verify. Raises ValueError if authentication fails."""
        if len(tag) != 16:
            raise ValueError("tag must be 16 bytes")
        expected_tag = self._compute_tag(nonce, aad, ciphertext)
        if not compare_digest(tag, expected_tag):
            raise ValueError("authentication failed")

        if len(nonce) == 12:
            j0 = nonce + b"\x00\x00\x00\x01"
        else:
            pad_len = (16 - len(nonce) % 16) % 16
            ghash_in_n = nonce + b"\x00" * pad_len + b"\x00" * 8 + (len(nonce) * 8).to_bytes(8, "big")
            j0 = _ghash(self._H, b"", ghash_in_n).to_bytes(16, "big")

        icb = _inc32(j0)
        return _gctr(self._aes, icb, ciphertext)

    def decrypt_blob(self, blob: bytes, aad: bytes = b"") -> bytes:
        """Decrypt a blob produced by encrypt_blob: nonce(12) + ciphertext + tag(16)."""
        if len(blob) < 28:
            raise ValueError("blob too short")
        nonce = blob[:12]
        tag = blob[-16:]
        ciphertext = blob[12:-16]
        return self.decrypt(ciphertext, tag, nonce, aad)
