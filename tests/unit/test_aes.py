"""Unit tests for AES-256 (CBC, CTR modes)."""

import os
import pytest
from crypto_standalone import AES256


class TestAES256Block:
    """AES-256 single-block encrypt/decrypt."""

    def test_block_encrypt_decrypt(self):
        key = os.urandom(32)
        aes = AES256(key)
        block = b"\x00" * 16
        ct = aes.encrypt_block(block)
        assert len(ct) == 16
        assert ct != block
        # Verify roundtrip via decrypt (if available)
        pt = aes.decrypt_block(ct)
        assert pt == block

    def test_block_deterministic(self):
        key = os.urandom(32)
        aes = AES256(key)
        block = os.urandom(16)
        ct1 = aes.encrypt_block(block)
        ct2 = aes.encrypt_block(block)
        assert ct1 == ct2

    def test_nist_aes_256_vector(self):
        """NIST FIPS 197 Appendix C.3 test vector."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        aes = AES256(key)
        ct = aes.encrypt_block(pt)
        exp = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        assert ct == exp


class TestAES256CBC:
    """AES-256-CBC mode."""

    def test_cbc_roundtrip(self):
        key = os.urandom(32)
        aes = AES256(key)
        pt = b"hello world, this is a test of CBC mode"
        ct = aes.encrypt_cbc(pt)
        dec = aes.decrypt_cbc(ct)
        assert dec == pt

    def test_cbc_empty_produces_padded_output(self):
        """Empty input gets PKCS7 padded to one block + IV."""
        key = os.urandom(32)
        aes = AES256(key)
        ct = aes.encrypt_cbc(b"")
        assert len(ct) == 32  # 16-byte IV + 16-byte padded block

    def test_cbc_different_ciphertexts(self):
        """CBC with random IV produces different ciphertexts."""
        key = os.urandom(32)
        aes = AES256(key)
        pt = b"same message"
        ct1 = aes.encrypt_cbc(pt)
        ct2 = aes.encrypt_cbc(pt)
        assert ct1 != ct2  # Different IVs


class TestAES256CTR:
    """AES-256-CTR mode."""

    def test_ctr_roundtrip(self):
        key = os.urandom(32)
        aes = AES256(key)
        pt = b"hello world, this is a test of CTR mode"
        ct = aes.encrypt_ctr(pt)
        dec = aes.decrypt_ctr(ct)
        assert dec == pt

    def test_ctr_output_includes_iv(self):
        """CTR mode prepends 16-byte IV to ciphertext."""
        key = os.urandom(32)
        aes = AES256(key)
        pt = b"test"
        ct = aes.encrypt_ctr(pt)
        assert len(ct) == len(pt) + 16  # 16-byte IV + ciphertext

    def test_ctr_empty_produces_iv(self):
        """Empty input still produces 16-byte IV output."""
        key = os.urandom(32)
        aes = AES256(key)
        ct = aes.encrypt_ctr(b"")
        assert len(ct) == 16  # Just the IV
