from dataclasses import dataclass
from .aes import AES, _xor_block

@dataclass(frozen=True)
class AESIGE:
    cipher: AES

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypts data using AES-IGE (Infinite Garble Extension).

        Note: AES-IGE provides confidentiality only. It does not provide
        authentication or integrity protection.
        """
        if len(iv) != 32:
            raise ValueError("AES-IGE requires exactly a 32-byte IV")
        if len(plaintext) % 16 != 0:
            raise ValueError("Plaintext length must be a multiple of the 16-byte block size")

        iv1 = iv[:16]
        iv2 = iv[16:]

        out = bytearray()
        for i in range(0, len(plaintext), 16):
            p_i = plaintext[i:i+16]
            c_i = _xor_block(self.cipher.encrypt_block(_xor_block(p_i, iv1)), iv2)
            out.extend(c_i)
            iv1 = c_i
            iv2 = p_i

        return bytes(out)

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypts data using AES-IGE (Infinite Garble Extension).

        Note: AES-IGE provides confidentiality only. It does not provide
        authentication or integrity protection.
        """
        if len(iv) != 32:
            raise ValueError("AES-IGE requires exactly a 32-byte IV")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of the 16-byte block size")

        iv1 = iv[:16]
        iv2 = iv[16:]

        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            c_i = ciphertext[i:i+16]
            p_i = _xor_block(self.cipher.decrypt_block(_xor_block(c_i, iv2)), iv1)
            out.extend(p_i)
            iv1 = c_i
            iv2 = p_i

        return bytes(out)

def aes_ige_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Convenience function for AES-IGE encryption.

    Args:
        plaintext: The data to encrypt. Length must be a multiple of 16.
        key: The AES key (16, 24, or 32 bytes).
        iv: The 32-byte Initialization Vector.

    Returns:
        The encrypted ciphertext.
    """
    cipher = AES(key)
    ige = AESIGE(cipher)
    return ige.encrypt(plaintext, iv)

def aes_ige_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Convenience function for AES-IGE decryption.

    Args:
        ciphertext: The data to decrypt. Length must be a multiple of 16.
        key: The AES key (16, 24, or 32 bytes).
        iv: The 32-byte Initialization Vector.

    Returns:
        The decrypted plaintext.
    """
    cipher = AES(key)
    ige = AESIGE(cipher)
    return ige.decrypt(ciphertext, iv)
