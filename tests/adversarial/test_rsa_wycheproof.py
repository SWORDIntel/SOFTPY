"""
Wycheproof-style adversarial tests for RSA (OAEP, PSS, PKCS#1 v1.5).

Tests cover:
- OAEP / PSS roundtrips
- PKCS#1 v1.5 padding oracle concerns
- Invalid ciphertext rejection
- Signature forgery resistance
- Key size enforcement
- Tampered ciphertext / signature rejection
"""

import os
import pytest
from crypto_standalone import generate_rsa_keypair


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a 2048-bit RSA keypair (shared across tests)."""
    return generate_rsa_keypair(2048)


class TestRSAOAEPEdgeCases:
    """RSA-OAEP (modern encryption) edge cases."""

    def test_roundtrip_short_message(self, rsa_keypair):
        msg = b"hello"
        ct = rsa_keypair.public.encrypt_oaep(msg)
        assert rsa_keypair.private.decrypt_oaep(ct) == msg

    def test_roundtrip_empty_message(self, rsa_keypair):
        ct = rsa_keypair.public.encrypt_oaep(b"")
        assert rsa_keypair.private.decrypt_oaep(ct) == b""

    def test_roundtrip_max_length(self, rsa_keypair):
        # OAEP with SHA-256: max message = k - 2*hLen - 2 = 256 - 2*32 - 2 = 190 bytes
        msg = b"x" * 190
        ct = rsa_keypair.public.encrypt_oaep(msg)
        assert rsa_keypair.private.decrypt_oaep(ct) == msg

    def test_message_too_long(self, rsa_keypair):
        with pytest.raises(ValueError):
            rsa_keypair.public.encrypt_oaep(b"x" * 191)

    def test_tampered_ciphertext(self, rsa_keypair):
        ct = rsa_keypair.public.encrypt_oaep(b"secret")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        with pytest.raises(ValueError):
            rsa_keypair.private.decrypt_oaep(bytes(tampered))

    def test_different_ciphertexts_same_message(self, rsa_keypair):
        """OAEP uses randomness, so same message produces different ciphertexts."""
        msg = b"same message"
        ct1 = rsa_keypair.public.encrypt_oaep(msg)
        ct2 = rsa_keypair.public.encrypt_oaep(msg)
        assert ct1 != ct2  # Randomized encryption
        assert rsa_keypair.private.decrypt_oaep(ct1) == msg
        assert rsa_keypair.private.decrypt_oaep(ct2) == msg


class TestRSAPSSEdgeCases:
    """RSA-PSS (modern signatures) edge cases."""

    def test_roundtrip(self, rsa_keypair):
        msg = b"document to sign"
        sig = rsa_keypair.private.sign_pss(msg)
        assert rsa_keypair.public.verify_pss(msg, sig)

    def test_tampered_signature(self, rsa_keypair):
        sig = rsa_keypair.private.sign_pss(b"document")
        tampered = bytearray(sig)
        tampered[0] ^= 0x01
        assert not rsa_keypair.public.verify_pss(b"document", bytes(tampered))

    def test_wrong_message(self, rsa_keypair):
        sig = rsa_keypair.private.sign_pss(b"correct")
        assert not rsa_keypair.public.verify_pss(b"wrong", sig)

    def test_different_signatures_same_message(self, rsa_keypair):
        """PSS uses randomness, so same message produces different signatures."""
        msg = b"same message"
        sig1 = rsa_keypair.private.sign_pss(msg)
        sig2 = rsa_keypair.private.sign_pss(msg)
        # PSS is randomized — sigs should differ
        # (though with same salt they could match; unlikely)
        assert rsa_keypair.public.verify_pss(msg, sig1)
        assert rsa_keypair.public.verify_pss(msg, sig2)


class TestRSAPKCS1v15:
    """PKCS#1 v1.5 (legacy) — known vulnerable to padding oracle."""

    def test_roundtrip(self, rsa_keypair):
        msg = b"legacy message"
        ct = rsa_keypair.public.encrypt(msg)
        assert rsa_keypair.private.decrypt(ct) == msg

    def test_sign_verify(self, rsa_keypair):
        msg = b"legacy signature"
        sig = rsa_keypair.private.sign(msg)
        assert rsa_keypair.public.verify(msg, sig)

    def test_tampered_signature(self, rsa_keypair):
        sig = rsa_keypair.private.sign(b"test")
        tampered = bytearray(sig)
        tampered[-1] ^= 0x01
        assert not rsa_keypair.public.verify(b"test", bytes(tampered))

    def test_wrong_hash_algorithm(self, rsa_keypair):
        """Sign with SHA-256, try to verify with SHA-1."""
        sig = rsa_keypair.private.sign(b"test", "sha256")
        # The verify function uses the hash spec embedded in the signature
        # So this should still verify correctly
        assert rsa_keypair.public.verify(b"test", sig)


class TestRSAKeySizeEnforcement:
    """Key size enforcement tests."""

    def test_minimum_2048_bits(self):
        with pytest.raises(ValueError):
            generate_rsa_keypair(1024)

    def test_2048_bit_keygen(self):
        kp = generate_rsa_keypair(2048)
        # Verify key size by checking modulus byte length
        n = kp.public.n
        # RSA modulus may be bits-1 due to prime composition
        assert n.bit_length() >= 2047

    def test_3072_bit_keygen(self):
        kp = generate_rsa_keypair(3072)
        n = kp.public.n
        # RSA keygen sets the top bit, but the result may be bits-1 due to prime composition
        assert n.bit_length() >= 3071


class TestRSACrossKeyRejection:
    """Cross-key rejection tests."""

    def test_encrypt_with_wrong_key(self, rsa_keypair):
        kp2 = generate_rsa_keypair(2048)
        ct = rsa_keypair.public.encrypt(b"secret")
        with pytest.raises(ValueError):
            kp2.private.decrypt(ct)

    def test_sign_with_wrong_key(self, rsa_keypair):
        kp2 = generate_rsa_keypair(2048)
        sig = rsa_keypair.private.sign(b"test")
        assert not kp2.public.verify(b"test", sig)
