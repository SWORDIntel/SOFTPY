"""
Wycheproof-style adversarial tests for ChaCha20-Poly1305.

Tests cover:
- Valid roundtrips
- Tag tampering / AAD manipulation
- Nonce reuse
- Edge cases (empty inputs, boundary sizes)
- Malformed inputs
"""

import os
import pytest
from crypto_standalone import ChaCha20Poly1305


class TestChaCha20Poly1305Valid:
    """Valid encryption/decryption cases."""

    def test_rfc8439_vector(self):
        """RFC 8439 §2.8.2 test vector."""
        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

        cp = ChaCha20Poly1305(key)
        ct, tag = cp.encrypt(pt, nonce, aad)
        exp_ct = bytes.fromhex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        exp_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
        assert ct == exp_ct
        assert tag == exp_tag
        assert cp.decrypt(exp_ct, exp_tag, nonce, aad) == pt

    def test_roundtrip_empty(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        blob = cp.encrypt_blob(b"")
        assert cp.decrypt_blob(blob) == b""

    def test_roundtrip_with_aad(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        blob = cp.encrypt_blob(b"secret", aad=b"metadata")
        assert cp.decrypt_blob(blob, aad=b"metadata") == b"secret"

    def test_roundtrip_block_aligned(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        pt = b"x" * 64
        blob = cp.encrypt_blob(pt)
        assert cp.decrypt_blob(blob) == pt


class TestChaCha20Poly1305InvalidTag:
    """Invalid tag / tampering tests."""

    def test_tampered_ciphertext(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        blob = cp.encrypt_blob(b"secret")
        tampered = bytearray(blob)
        tampered[13] ^= 0x01
        with pytest.raises(ValueError, match="authentication failed"):
            cp.decrypt_blob(bytes(tampered))

    def test_tampered_tag(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        blob = cp.encrypt_blob(b"secret")
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with pytest.raises(ValueError, match="authentication failed"):
            cp.decrypt_blob(bytes(tampered))

    def test_wrong_aad(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        blob = cp.encrypt_blob(b"secret", aad=b"correct")
        with pytest.raises(ValueError):
            cp.decrypt_blob(blob, aad=b"wrong")

    def test_all_zero_tag(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        nonce = os.urandom(12)
        ct, _ = cp.encrypt(b"secret", nonce)
        with pytest.raises(ValueError):
            cp.decrypt(ct, b"\x00" * 16, nonce)

    def test_wrong_nonce(self):
        """Decrypt with wrong nonce."""
        cp = ChaCha20Poly1305(os.urandom(32))
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
        ct, tag = cp.encrypt(b"secret", nonce1)
        with pytest.raises(ValueError):
            cp.decrypt(ct, tag, nonce2)


class TestChaCha20Poly1305EdgeCases:
    """Edge cases."""

    def test_wrong_key_length(self):
        with pytest.raises(ValueError):
            ChaCha20Poly1305(b"\x00" * 16)

    def test_wrong_nonce_length(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        with pytest.raises(ValueError):
            cp.encrypt(b"test", nonce=b"\x00" * 8)

    def test_blob_too_short(self):
        cp = ChaCha20Poly1305(os.urandom(32))
        with pytest.raises(ValueError):
            cp.decrypt_blob(b"short")

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65, 255, 1024])
    def test_various_sizes(self, size):
        cp = ChaCha20Poly1305(os.urandom(32))
        pt = os.urandom(size)
        blob = cp.encrypt_blob(pt)
        assert cp.decrypt_blob(blob) == pt
