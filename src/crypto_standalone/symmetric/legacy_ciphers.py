"""Pure-Python legacy block ciphers: TEA and Red Pike.

These ciphers are provided for interoperability/testing only.
Do not use for new designs.
"""

from __future__ import annotations

from dataclasses import dataclass

_MASK32 = 0xFFFFFFFF


def _u32(v: int) -> int:
    return v & _MASK32


@dataclass(frozen=True)
class TEA:
    """Tiny Encryption Algorithm (TEA), 64-bit block and 128-bit key."""

    key: bytes
    rounds: int = 32

    def __post_init__(self) -> None:
        if len(self.key) != 16:
            raise ValueError("TEA key must be 16 bytes")
        if self.rounds <= 0:
            raise ValueError("TEA rounds must be positive")
        object.__setattr__(self, "_k", [int.from_bytes(self.key[i : i + 4], "big") for i in range(0, 16, 4)])

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("TEA block must be 8 bytes")
        v0 = int.from_bytes(block[:4], "big")
        v1 = int.from_bytes(block[4:], "big")
        delta = 0x9E3779B9
        acc = 0
        k0, k1, k2, k3 = self._k
        for _ in range(self.rounds):
            acc = _u32(acc + delta)
            v0 = _u32(v0 + (((v1 << 4) + k0) ^ (v1 + acc) ^ ((v1 >> 5) + k1)))
            v1 = _u32(v1 + (((v0 << 4) + k2) ^ (v0 + acc) ^ ((v0 >> 5) + k3)))
        return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("TEA block must be 8 bytes")
        v0 = int.from_bytes(block[:4], "big")
        v1 = int.from_bytes(block[4:], "big")
        delta = 0x9E3779B9
        acc = _u32(delta * self.rounds)
        k0, k1, k2, k3 = self._k
        for _ in range(self.rounds):
            v1 = _u32(v1 - (((v0 << 4) + k2) ^ (v0 + acc) ^ ((v0 >> 5) + k3)))
            v0 = _u32(v0 - (((v1 << 4) + k0) ^ (v1 + acc) ^ ((v1 >> 5) + k1)))
            acc = _u32(acc - delta)
        return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


@dataclass(frozen=True)
class RedPike:
    """RED PIKE 64-bit block cipher (legacy UK government algorithm).

    Interoperability profile: 64-bit block, 64-bit key, 16 rounds.
    """

    key: bytes
    rounds: int = 16

    def __post_init__(self) -> None:
        if len(self.key) != 8:
            raise ValueError("RedPike key must be 8 bytes")
        if self.rounds <= 0:
            raise ValueError("RedPike rounds must be positive")
        object.__setattr__(self, "_k0", int.from_bytes(self.key[:4], "big"))
        object.__setattr__(self, "_k1", int.from_bytes(self.key[4:], "big"))

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        x &= _MASK32
        return ((x << n) | (x >> (32 - n))) & _MASK32

    @staticmethod
    def _rotr32(x: int, n: int) -> int:
        x &= _MASK32
        return ((x >> n) | (x << (32 - n))) & _MASK32

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("RedPike block must be 8 bytes")
        x = int.from_bytes(block[:4], "big")
        y = int.from_bytes(block[4:], "big")
        rk = self._k0
        lk = self._k1
        for _ in range(self.rounds):
            rk = _u32(rk + 0x9E3779B9)
            lk = _u32(lk - 0x7F4A7C15)
            x ^= rk
            y ^= self._rotl32(x, 9)
            y = _u32(y + lk)
            x ^= self._rotr32(y, 14)
        return x.to_bytes(4, "big") + y.to_bytes(4, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("RedPike block must be 8 bytes")
        x = int.from_bytes(block[:4], "big")
        y = int.from_bytes(block[4:], "big")
        rk = _u32(self._k0 + (0x9E3779B9 * self.rounds))
        lk = _u32(self._k1 - (0x7F4A7C15 * self.rounds))
        for _ in range(self.rounds):
            x ^= self._rotr32(y, 14)
            y = _u32(y - lk)
            y ^= self._rotl32(x, 9)
            x ^= rk
            rk = _u32(rk - 0x9E3779B9)
            lk = _u32(lk + 0x7F4A7C15)
        return x.to_bytes(4, "big") + y.to_bytes(4, "big")



AVE_MARIA_TOKENS = (
    "ave", "maria", "gratia", "plena", "dominus", "tecum", "benedicta", "tu",
    "in", "mulieribus", "et", "benedictus", "fructus", "ventris", "tui", "iesus",
    "sancta", "dei", "mater", "ora", "pro", "nobis", "peccatoribus", "nunc",
    "et_in", "hora",
)


class AveMariaCipher:
    """Ave Maria substitution cipher.

    Maps letters a-z to a fixed 26-token vocabulary inspired by the historical
    Trithemius/Ave-Maria encoding style.
    Encoded letters are wrapped as ``<token>`` so non-letters are preserved
    exactly (digits, whitespace, punctuation).
    """

    def __init__(self) -> None:
        self._enc = {chr(ord('a') + i): AVE_MARIA_TOKENS[i] for i in range(26)}
        self._dec = {v: k for k, v in self._enc.items()}

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        out: list[str] = []
        for ch in plaintext.lower():
            if 'a' <= ch <= 'z':
                out.append(f"<{self._enc[ch]}>")
            else:
                out.append(ch)
        return ''.join(out)

    def decrypt(self, ciphertext: str) -> str:
        if not isinstance(ciphertext, str):
            raise TypeError("ciphertext must be str")
        out: list[str] = []
        i = 0
        while i < len(ciphertext):
            if ciphertext[i] == '<':
                j = ciphertext.find('>', i + 1)
                if j == -1:
                    out.append(ciphertext[i])
                    i += 1
                    continue
                tok = ciphertext[i + 1:j]
                out.append(self._dec.get(tok, '<' + tok + '>'))
                i = j + 1
            else:
                out.append(ciphertext[i])
                i += 1
        return ''.join(out)
