"""Unit tests for RSA key generation, encryption, and signing."""

import os
import pytest
from crypto_standalone import generate_rsa_keypair


class TestRSAKeygen:
    """RSA key generation."""

    def test_2048_bit_keygen(self):
        kp = generate_rsa_keypair(2048)
        assert kp.public.n.bit_length() >= 2047
        assert kp.public.e == 65537

    def test_minimum_key_size(self):
        with pytest.raises(ValueError):
            generate_rsa_keypair(1024)


class TestRSAEncryptDecrypt:
    """RSA encryption/decryption."""

    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_rsa_keypair(2048)

    def test_pkcs1v15_roundtrip(self, keypair):
        msg = b"hello RSA"
        ct = keypair.public.encrypt(msg)
        assert keypair.private.decrypt(ct) == msg

    def test_oaep_roundtrip(self, keypair):
        msg = b"hello OAEP"
        ct = keypair.public.encrypt_oaep(msg)
        assert keypair.private.decrypt_oaep(ct) == msg

    def test_oaep_empty(self, keypair):
        ct = keypair.public.encrypt_oaep(b"")
        assert keypair.private.decrypt_oaep(ct) == b""


class TestRSASignVerify:
    """RSA signing/verification."""

    @pytest.fixture(scope="class")
    def keypair(self):
        return generate_rsa_keypair(2048)

    def test_pkcs1v15_sign_verify(self, keypair):
        msg = b"document"
        sig = keypair.private.sign(msg)
        assert keypair.public.verify(msg, sig)

    def test_pss_sign_verify(self, keypair):
        msg = b"document"
        sig = keypair.private.sign_pss(msg)
        assert keypair.public.verify_pss(msg, sig)

    def test_wrong_message_rejected(self, keypair):
        sig = keypair.private.sign(b"correct")
        assert not keypair.public.verify(b"wrong", sig)
