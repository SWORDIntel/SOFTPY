"""RED PIKE block cipher for legacy interoperability."""

import struct


class RedPike:
    def __init__(self, key: bytes, rounds: int = 16) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes-like")
        if len(key) != 8:
            raise ValueError("RedPike key must be 8 bytes")
        if rounds <= 0:
            raise ValueError("rounds must be positive")
        self._k0, self._k1 = struct.unpack(">2I", bytes(key))
        self.rounds = rounds

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rotr32(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def encrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes-like")
        if len(block) != 8:
            raise ValueError("RedPike block must be 8 bytes")
        x0, x1 = struct.unpack(">2I", bytes(block))
        k0, k1 = self._k0, self._k1
        for _ in range(self.rounds):
            x0 = self._rotl32((x0 ^ k0), 9)
            x1 = self._rotr32((x1 ^ k1), 9)
            x0 = (x0 + x1) & 0xFFFFFFFF
            x1 = (x1 + x0) & 0xFFFFFFFF
        return struct.pack(">2I", x0, x1)

    def decrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes-like")
        if len(block) != 8:
            raise ValueError("RedPike block must be 8 bytes")
        x0, x1 = struct.unpack(">2I", bytes(block))
        k0, k1 = self._k0, self._k1
        for _ in range(self.rounds):
            x1 = (x1 - x0) & 0xFFFFFFFF
            x0 = (x0 - x1) & 0xFFFFFFFF
            x1 = self._rotl32(x1, 9) ^ k1
            x0 = self._rotr32(x0, 9) ^ k0
        return struct.pack(">2I", x0, x1)
