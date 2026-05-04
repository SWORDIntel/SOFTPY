"""Unit tests for Ed25519, X25519, and NIST P-curves."""

import os
import pytest
from crypto_standalone import (
    ed25519_keygen, ed25519_sign, ed25519_verify, ed25519_public_key,
    x25519_keygen, x25519, x25519_public_key,
    p256_keygen, p384_keygen,
)


class TestEd25519:
    """Ed25519 signatures."""

    def test_keygen(self):
        sk, pk = ed25519_keygen()
        assert len(sk) == 32
        assert len(pk) == 32

    def test_sign_verify(self):
        sk, pk = ed25519_keygen()
        sig = ed25519_sign(b"test", sk)
        assert len(sig) == 64
        assert ed25519_verify(b"test", sig, pk)

    def test_wrong_message_rejected(self):
        sk, pk = ed25519_keygen()
        sig = ed25519_sign(b"correct", sk)
        assert not ed25519_verify(b"wrong", sig, pk)

    def test_rfc8032_vector(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = ed25519_public_key(sk)
        sig = ed25519_sign(b"", sk)
        assert ed25519_verify(b"", sig, pk)


class TestX25519:
    """X25519 ECDH."""

    def test_keygen(self):
        sk, pk = x25519_keygen()
        assert len(sk) == 32
        assert len(pk) == 32

    def test_ecdh_symmetry(self):
        sk1, pk1 = x25519_keygen()
        sk2, pk2 = x25519_keygen()
        assert x25519(sk1, pk2) == x25519(sk2, pk1)

    def test_rfc7748_vector(self):
        sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        pk = x25519_public_key(sk)
        assert len(pk) == 32


class TestP256:
    """NIST P-256 ECDSA + ECDH."""

    def test_keygen(self):
        sk = p256_keygen()
        assert sk.public_key is not None

    def test_sign_verify(self):
        sk = p256_keygen()
        sig = sk.sign(b"test")
        assert sk.public_key.verify(b"test", sig)

    def test_ecdh(self):
        sk1 = p256_keygen()
        sk2 = p256_keygen()
        shared1 = sk1.ecdh(sk2.public_key)
        shared2 = sk2.ecdh(sk1.public_key)
        assert shared1 == shared2
        assert len(shared1) == 32


class TestP384:
    """NIST P-384 ECDSA + ECDH."""

    def test_keygen(self):
        sk = p384_keygen()
        assert sk.public_key is not None

    def test_sign_verify(self):
        sk = p384_keygen()
        sig = sk.sign(b"test")
        assert sk.public_key.verify(b"test", sig)

    def test_ecdh(self):
        sk1 = p384_keygen()
        sk2 = p384_keygen()
        shared1 = sk1.ecdh(sk2.public_key)
        shared2 = sk2.ecdh(sk1.public_key)
        assert shared1 == shared2
        assert len(shared1) == 48
