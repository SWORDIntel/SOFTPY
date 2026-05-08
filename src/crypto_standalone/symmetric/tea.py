"""TEA (Tiny Encryption Algorithm) for legacy interoperability."""

import struct


class TEA:
    def __init__(self, key: bytes, rounds: int = 32) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes-like")
        if len(key) != 16:
            raise ValueError("TEA key must be 16 bytes")
        if rounds <= 0:
            raise ValueError("rounds must be positive")
        self._k = struct.unpack(">4I", bytes(key))
        self.rounds = rounds

    def encrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes-like")
        if len(block) != 8:
            raise ValueError("TEA block must be 8 bytes")
        v0, v1 = struct.unpack(">2I", bytes(block))
        delta = 0x9E3779B9
        s = 0
        k0, k1, k2, k3 = self._k
        for _ in range(self.rounds):
            s = (s + delta) & 0xFFFFFFFF
            v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        return struct.pack(">2I", v0, v1)

    def decrypt_block(self, block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray)):
            raise TypeError("block must be bytes-like")
        if len(block) != 8:
            raise ValueError("TEA block must be 8 bytes")
        v0, v1 = struct.unpack(">2I", bytes(block))
        delta = 0x9E3779B9
        s = (delta * self.rounds) & 0xFFFFFFFF
        k0, k1, k2, k3 = self._k
        for _ in range(self.rounds):
            v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
            s = (s - delta) & 0xFFFFFFFF
        return struct.pack(">2I", v0, v1)
