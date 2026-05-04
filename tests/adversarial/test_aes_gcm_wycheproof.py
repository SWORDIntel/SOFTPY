"""
Wycheproof-style adversarial tests for AES-256-GCM.

Tests cover:
- Valid encryption/decryption roundtrips
- Invalid authentication tags (tampered)
- Empty plaintext / empty AAD
- Nonce reuse detection
- Tag truncation
- Boundary conditions
- Malformed inputs
"""

import os
import pytest
from crypto_standalone import AESGCM


class TestAESGCMValid:
    """Valid encryption/decryption cases."""

    def test_roundtrip_short_message(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        pt = b"hello"
        # blob API roundtrip
        blob = gcm.encrypt_blob(pt)
        assert gcm.decrypt_blob(blob) == pt

    def test_roundtrip_empty_plaintext(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"")
        assert gcm.decrypt_blob(blob) == b""

    def test_roundtrip_empty_aad(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret", aad=b"")
        assert gcm.decrypt_blob(blob, aad=b"") == b"secret"

    def test_roundtrip_with_aad(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret", aad=b"metadata")
        assert gcm.decrypt_blob(blob, aad=b"metadata") == b"secret"

    def test_roundtrip_exact_block_size(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        pt = b"x" * 16  # exactly one AES block
        blob = gcm.encrypt_blob(pt)
        assert gcm.decrypt_blob(blob) == pt

    def test_roundtrip_multiple_blocks(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        pt = b"x" * 64  # 4 blocks
        blob = gcm.encrypt_blob(pt)
        assert gcm.decrypt_blob(blob) == pt

    def test_roundtrip_large_message(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        pt = os.urandom(4096)
        blob = gcm.encrypt_blob(pt)
        assert gcm.decrypt_blob(blob) == pt

    def test_nist_cavp_vector(self):
        """NIST CAVP AES-256-GCM test vector."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        gcm = AESGCM(key)
        ct, tag = gcm.encrypt(pt, nonce, aad)
        exp_ct = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
        assert ct == exp_ct
        pt2 = gcm.decrypt(ct, tag, nonce, aad)
        assert pt2 == pt


class TestAESGCMInvalidTag:
    """Invalid authentication tag tests (Wycheproof-style)."""

    def test_tampered_ciphertext(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret")
        # Flip a bit in ciphertext
        tampered = bytearray(blob)
        tampered[13] ^= 0x01  # flip bit in ciphertext portion
        with pytest.raises(ValueError, match="authentication failed"):
            gcm.decrypt_blob(bytes(tampered))

    def test_tampered_tag(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret")
        # Flip a bit in tag
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with pytest.raises(ValueError, match="authentication failed"):
            gcm.decrypt_blob(bytes(tampered))

    def test_all_zero_tag(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = os.urandom(12)
        ct, _ = gcm.encrypt(b"secret", nonce)
        with pytest.raises(ValueError, match="authentication failed"):
            gcm.decrypt(ct, b"\x00" * 16, nonce)

    def test_wrong_tag_length(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        with pytest.raises(ValueError):
            gcm.decrypt(b"ct", b"\x00" * 15, os.urandom(12))

    def test_swapped_tags(self):
        """Two messages encrypted with same key — swap tags."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
        ct1, tag1 = gcm.encrypt(b"message1", nonce1)
        ct2, tag2 = gcm.encrypt(b"message2", nonce2)
        # Tag from msg2 should not validate msg1
        with pytest.raises(ValueError):
            gcm.decrypt(ct1, tag2, nonce1)


class TestAESGCMAADManipulation:
    """AAD manipulation tests."""

    def test_wrong_aad(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret", aad=b"correct-aad")
        with pytest.raises(ValueError, match="authentication failed"):
            gcm.decrypt_blob(blob, aad=b"wrong-aad")

    def test_missing_aad(self):
        """Encrypted with AAD but decrypted without."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret", aad=b"metadata")
        with pytest.raises(ValueError):
            gcm.decrypt_blob(blob, aad=b"")

    def test_added_aad(self):
        """Encrypted without AAD but decrypted with AAD."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        blob = gcm.encrypt_blob(b"secret", aad=b"")
        with pytest.raises(ValueError):
            gcm.decrypt_blob(blob, aad=b"unexpected")

    def test_aad_bit_flip(self):
        """Single bit flip in AAD."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        aad = b"authorization: admin"
        blob = gcm.encrypt_blob(b"secret", aad=aad)
        # Flip one bit in AAD
        aad_bad = bytearray(aad)
        aad_bad[5] ^= 0x01
        with pytest.raises(ValueError):
            gcm.decrypt_blob(blob, aad=bytes(aad_bad))


class TestAESGCMEdgeCases:
    """Edge cases and boundary conditions."""

    def test_zero_key(self):
        """All-zero key should still work (just insecure)."""
        gcm = AESGCM(b"\x00" * 32)
        blob = gcm.encrypt_blob(b"test")
        assert gcm.decrypt_blob(blob) == b"test"

    def test_repeated_nonce_different_messages(self):
        """Nonce reuse with different messages reveals XOR of plaintexts."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = os.urandom(12)
        ct1, tag1 = gcm.encrypt(b"msg1", nonce)
        ct2, tag2 = gcm.encrypt(b"msg2", nonce)
        # ct1 XOR ct2 reveals msg1 XOR msg2 — this is a known GCM weakness
        # We just verify both decrypt correctly with the same nonce
        assert gcm.decrypt(ct1, tag1, nonce) == b"msg1"
        assert gcm.decrypt(ct2, tag2, nonce) == b"msg2"

    def test_blob_too_short(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        with pytest.raises(ValueError, match="blob too short"):
            gcm.decrypt_blob(b"short")

    def test_explicit_nonce(self):
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = bytes(range(12))
        ct, tag = gcm.encrypt(b"test", nonce)
        assert gcm.decrypt(ct, tag, nonce) == b"test"

    def test_16_byte_nonce(self):
        """Non-12-byte nonce (16 bytes) should also work per spec."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = os.urandom(16)
        ct, tag = gcm.encrypt(b"test", nonce)
        assert gcm.decrypt(ct, tag, nonce) == b"test"


class TestAESGCMFuzz:
    """Fuzz-style tests with random inputs."""

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 255, 256, 1024])
    def test_various_plaintext_sizes(self, size):
        key = os.urandom(32)
        gcm = AESGCM(key)
        pt = os.urandom(size)
        blob = gcm.encrypt_blob(pt)
        assert gcm.decrypt_blob(blob) == pt

    @pytest.mark.parametrize("aad_size", [0, 1, 16, 32, 128])
    def test_various_aad_sizes(self, aad_size):
        key = os.urandom(32)
        gcm = AESGCM(key)
        aad = os.urandom(aad_size)
        blob = gcm.encrypt_blob(b"test", aad=aad)
        assert gcm.decrypt_blob(blob, aad=aad) == b"test"
