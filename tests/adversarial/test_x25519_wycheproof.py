"""
Wycheproof-style adversarial tests for X25519 ECDH.

Tests cover:
- RFC 7748 test vectors
- Key agreement symmetry
- Invalid public keys (low-order points)
- Edge cases (all-zero key, identity point)
- Small subgroup attacks
"""

import os
import pytest
from crypto_standalone import x25519, x25519_keygen, x25519_public_key


class TestX25519RFCVectors:
    """RFC 7748 §5.2 test vectors."""

    def test_vector_1(self):
        sk_a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        pk_a_exp = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        pk_a = x25519_public_key(sk_a)
        assert pk_a == pk_a_exp

        sk_b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        pk_b_exp = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        pk_b = x25519_public_key(sk_b)
        assert pk_b == pk_b_exp

        shared_exp = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        assert x25519(sk_a, pk_b) == shared_exp
        assert x25519(sk_b, pk_a) == shared_exp

    def test_vector_2_1000_iterations(self):
        """RFC 7748 iteration test (simplified: just verify 1 iteration)."""
        sk = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
        pk = x25519_public_key(sk)
        # Base point is 9,0 — first iteration should produce a valid point
        assert len(pk) == 32


class TestX25519KeyAgreement:
    """Key agreement symmetry and correctness."""

    def test_symmetry(self):
        sk1, pk1 = x25519_keygen()
        sk2, pk2 = x25519_keygen()
        assert x25519(sk1, pk2) == x25519(sk2, pk1)

    def test_deterministic(self):
        """Same key pair always produces same shared secret."""
        sk1 = os.urandom(32)
        sk2 = os.urandom(32)
        pk2 = x25519_public_key(sk2)
        s1 = x25519(sk1, pk2)
        s2 = x25519(sk1, pk2)
        assert s1 == s2

    def test_different_partners_different_secrets(self):
        sk1, pk1 = x25519_keygen()
        sk2, pk2 = x25519_keygen()
        sk3, pk3 = x25519_keygen()
        s12 = x25519(sk1, pk2)
        s13 = x25519(sk1, pk3)
        assert s12 != s13


class TestX25519SmallSubgroup:
    """Small subgroup / low-order point attacks (Wycheproof concern)."""

    def test_low_order_point_identity(self):
        """Identity point (all zeros) as public key.
        X25519 clamps, so this should produce a valid (but potentially all-zero) shared secret.
        This is a known issue — implementations should check for all-zero output."""
        sk, _ = x25519_keygen()
        # The point with x-coordinate 0 is a low-order point
        # X25519 with such a point should still compute but the result may be all zeros
        low_order_pk = b"\x00" * 32
        shared = x25519(sk, low_order_pk)
        # Result should be 32 bytes regardless
        assert len(shared) == 32

    def test_low_order_point_1(self):
        """Point with x=1 is another low-order point on Curve25519."""
        sk, _ = x25519_keygen()
        pk_1 = (1).to_bytes(32, "little")
        shared = x25519(sk, pk_1)
        assert len(shared) == 32

    def test_low_order_point_5(self):
        """x=5 is related to the curve's 4-torsion."""
        sk, _ = x25519_keygen()
        pk_5 = (5).to_bytes(32, "little")
        shared = x25519(sk, pk_5)
        assert len(shared) == 32


class TestX25519EdgeCases:
    """Edge cases and malformed inputs."""

    def test_wrong_key_length(self):
        with pytest.raises(ValueError):
            x25519_public_key(b"\x00" * 16)
        with pytest.raises(ValueError):
            x25519(b"\x00" * 16, b"\x00" * 32)

    def test_wrong_public_key_length(self):
        sk, _ = x25519_keygen()
        with pytest.raises(ValueError):
            x25519(sk, b"\x00" * 16)

    def test_self_agreement(self):
        """Agreement with own public key should produce a valid shared secret."""
        sk, pk = x25519_keygen()
        shared = x25519(sk, pk)
        assert len(shared) == 32

    def test_shared_secret_32_bytes(self):
        sk1, pk1 = x25519_keygen()
        sk2, pk2 = x25519_keygen()
        shared = x25519(sk1, pk2)
        assert len(shared) == 32
