import pytest
import os
from crypto_standalone.symmetric.aes_ige import aes_ige_encrypt, aes_ige_decrypt, AESIGE
from crypto_standalone.symmetric.aes import AES

class TestAESIGE:

    def test_known_answer_aes128(self):
        # From generate_ige_ctypes.py
        key = bytes.fromhex("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7")
        iv = bytes.fromhex("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283")
        pt = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        expected_ct = bytes.fromhex("78e264bebf5d88737280abef193490f73f4d4c01232cd08aeef7b7bb4353fad6")

        ct = aes_ige_encrypt(pt, key, iv)
        assert ct == expected_ct

        dec = aes_ige_decrypt(ct, key, iv)
        assert dec == pt

    def test_known_answer_aes192(self):
        key = bytes.fromhex("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
        iv = bytes.fromhex("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283")
        pt = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        expected_ct = bytes.fromhex("e59966ef8f40fb834a56701f53f54ee02512fc2b6fd2a4c700c601fc46e9f694")

        ct = aes_ige_encrypt(pt, key, iv)
        assert ct == expected_ct

        dec = aes_ige_decrypt(ct, key, iv)
        assert dec == pt

    def test_known_answer_aes256(self):
        key = bytes.fromhex("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7")
        iv = bytes.fromhex("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283")
        pt = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        expected_ct = bytes.fromhex("f30b9aa3dd1812bf61690ce99ff2e103354385c8ec7512515b1e4b177705cb7f")

        ct = aes_ige_encrypt(pt, key, iv)
        assert ct == expected_ct

        dec = aes_ige_decrypt(ct, key, iv)
        assert dec == pt

    def test_multi_block_roundtrip(self):
        for key_size in [16, 24, 32]:
            key = os.urandom(key_size)
            iv = os.urandom(32)
            pt = os.urandom(16 * 10) # 10 blocks

            ct = aes_ige_encrypt(pt, key, iv)
            assert len(ct) == len(pt)

            dec = aes_ige_decrypt(ct, key, iv)
            assert dec == pt

    def test_empty_input(self):
        key = os.urandom(32)
        iv = os.urandom(32)

        ct = aes_ige_encrypt(b"", key, iv)
        assert ct == b""

        dec = aes_ige_decrypt(b"", key, iv)
        assert dec == b""

    def test_invalid_key_size(self):
        with pytest.raises(ValueError, match="key must be 16, 24, or 32 bytes"):
            aes_ige_encrypt(b"0" * 16, os.urandom(15), os.urandom(32))

    def test_invalid_iv_size(self):
        key = os.urandom(32)
        with pytest.raises(ValueError, match="AES-IGE requires exactly a 32-byte IV"):
            aes_ige_encrypt(b"0" * 16, key, os.urandom(16))

        with pytest.raises(ValueError, match="AES-IGE requires exactly a 32-byte IV"):
            aes_ige_decrypt(b"0" * 16, key, os.urandom(31))

    def test_non_block_aligned_input(self):
        key = os.urandom(32)
        iv = os.urandom(32)

        with pytest.raises(ValueError, match="Plaintext length must be a multiple of the 16-byte block size"):
            aes_ige_encrypt(b"0" * 15, key, iv)

        with pytest.raises(ValueError, match="Ciphertext length must be a multiple of the 16-byte block size"):
            aes_ige_decrypt(b"0" * 17, key, iv)

    def test_incorrect_iv(self):
        key = os.urandom(32)
        iv1 = os.urandom(32)
        iv2 = os.urandom(32)
        pt = os.urandom(32)

        ct = aes_ige_encrypt(pt, key, iv1)
        dec = aes_ige_decrypt(ct, key, iv2)

        assert dec != pt

    def test_incorrect_key(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        iv = os.urandom(32)
        pt = os.urandom(32)

        ct = aes_ige_encrypt(pt, key1, iv)
        dec = aes_ige_decrypt(ct, key2, iv)

        assert dec != pt

    def test_corrupted_ciphertext(self):
        key = os.urandom(32)
        iv = os.urandom(32)
        pt = os.urandom(32)

        ct = aes_ige_encrypt(pt, key, iv)

        # Corrupt 1 byte
        corrupted_ct = bytearray(ct)
        corrupted_ct[0] ^= 0x01

        dec = aes_ige_decrypt(bytes(corrupted_ct), key, iv)

        assert dec != pt
