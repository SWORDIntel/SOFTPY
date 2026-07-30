from __future__ import annotations

from .aes import AES, _xor_block


class AESIGE:
    def __init__(self, cipher: AES) -> None:
        self._cipher = cipher

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        if len(iv) != 32:
            raise ValueError("AES-IGE IV must be exactly 32 bytes")
        if len(plaintext) % 16 != 0:
            raise ValueError("Plaintext length must be a multiple of the 16-byte block size")

        c_prev = iv[:16]  # C_0
        p_prev = iv[16:]  # P_0

        out = bytearray()
        for i in range(0, len(plaintext), 16):
            p_i = plaintext[i : i + 16]
            xored_in = _xor_block(p_i, c_prev)
            e_k = self._cipher.encrypt_block(xored_in)
            c_i = _xor_block(e_k, p_prev)

            out.extend(c_i)
            c_prev = c_i
            p_prev = p_i

        return bytes(out)

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        if len(iv) != 32:
            raise ValueError("AES-IGE IV must be exactly 32 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of the 16-byte block size")

        c_prev = iv[:16]  # C_0
        p_prev = iv[16:]  # P_0

        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            c_i = ciphertext[i : i + 16]
            xored_in = _xor_block(c_i, p_prev)
            d_k = self._cipher.decrypt_block(xored_in)
            p_i = _xor_block(d_k, c_prev)

            out.extend(p_i)
            c_prev = c_i
            p_prev = p_i

        return bytes(out)


def aes_ige_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts data using AES in Infinite Garble Extension (IGE) mode.

    AES-IGE provides confidentiality only. It does not provide authentication
    or integrity protection. It must be paired with a separate authentication
    mechanism when used in a protocol that does not already authenticate the
    encrypted data.

    Args:
        plaintext: The data to encrypt. Must be a multiple of 16 bytes.
        key: The AES key (16, 24, or 32 bytes).
        iv: The 32-byte IV (C_0 || P_0).

    Returns:
        The ciphertext bytes.
    """
    return AESIGE(AES(key)).encrypt(plaintext, iv)


def aes_ige_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts data using AES in Infinite Garble Extension (IGE) mode.

    AES-IGE provides confidentiality only. It does not provide authentication
    or integrity protection. It must be paired with a separate authentication
    mechanism when used in a protocol that does not already authenticate the
    encrypted data.

    Args:
        ciphertext: The data to decrypt. Must be a multiple of 16 bytes.
        key: The AES key (16, 24, or 32 bytes).
        iv: The 32-byte IV (C_0 || P_0).

    Returns:
        The plaintext bytes.
    """
    return AESIGE(AES(key)).decrypt(ciphertext, iv)
