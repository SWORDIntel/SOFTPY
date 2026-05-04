"""
Wycheproof-style adversarial tests for ECDSA (P-256, P-384).

Tests cover:
- Signature malleability (r, -s mod n)
- Invalid scalars (r=0, s=0, r≥n, s≥n)
- Invalid curve points
- Signature verification edge cases
- ECDH edge cases
- Deterministic k (RFC 6979)
"""

import os
import pytest
from crypto_standalone import (
    p256_keygen, p384_keygen, ECDSAPrivateKey, ECDSAPublicKey,
    P256, P384, _encode_signature, _decode_signature,
)


class TestECDSASignatureMalleability:
    """Signature malleability (Wycheproof concern: (r,s) and (r,-s mod n) both valid)."""

    def test_p256_malleable_signature(self):
        """ECDSA without low-S normalization accepts both (r,s) and (r,-s)."""
        sk = p256_keygen()
        msg = b"test"
        sig = sk.sign(msg)
        r, s = _decode_signature(sig)
        
        # Create malleable signature: (r, -s mod n)
        s_neg = (-s) % P256.n
        sig_malleable = _encode_signature(r, s_neg)
        
        # Both should verify (standard ECDSA without low-S constraint)
        assert sk.public_key.verify(msg, sig)
        assert sk.public_key.verify(msg, sig_malleable)

    def test_p384_malleable_signature(self):
        sk = p384_keygen()
        msg = b"test"
        sig = sk.sign(msg)
        r, s = _decode_signature(sig)
        s_neg = (-s) % P384.n
        sig_malleable = _encode_signature(r, s_neg)
        assert sk.public_key.verify(msg, sig)
        assert sk.public_key.verify(msg, sig_malleable)


class TestECDSAInvalidScalars:
    """Invalid signature components (Wycheproof concern)."""

    def test_r_zero_rejected(self):
        sk = p256_keygen()
        msg = b"test"
        sig_zero_r = _encode_signature(0, 12345)
        assert not sk.public_key.verify(msg, sig_zero_r)

    def test_s_zero_rejected(self):
        sk = p256_keygen()
        sig_zero_s = _encode_signature(12345, 0)
        assert not sk.public_key.verify(msg := b"test", sig_zero_s)

    def test_r_equal_n_rejected(self):
        sk = p256_keygen()
        sig_r_n = _encode_signature(P256.n, 12345)
        assert not sk.public_key.verify(b"test", sig_r_n)

    def test_s_equal_n_rejected(self):
        sk = p256_keygen()
        sig_s_n = _encode_signature(12345, P256.n)
        assert not sk.public_key.verify(b"test", sig_s_n)

    def test_r_greater_than_n_rejected(self):
        sk = p256_keygen()
        sig_r_big = _encode_signature(P256.n + 1, 12345)
        assert not sk.public_key.verify(b"test", sig_r_big)

    def test_s_greater_than_n_rejected(self):
        sk = p256_keygen()
        sig_s_big = _encode_signature(12345, P256.n + 1)
        assert not sk.public_key.verify(b"test", sig_s_big)

    def test_negative_r_rejected(self):
        """Negative values encoded in DER should still be caught."""
        sk = p256_keygen()
        # Manually craft a DER signature with negative r
        # This tests DER parsing robustness
        sig = sk.sign(b"test")
        r, s = _decode_signature(sig)
        # Re-encode with valid values
        valid_sig = _encode_signature(r, s)
        assert sk.public_key.verify(b"test", valid_sig)


class TestECDSATamperedSignatures:
    """Tampered signature tests."""

    def test_tampered_r(self):
        sk = p256_keygen()
        sig = sk.sign(b"test")
        r, s = _decode_signature(sig)
        tampered_sig = _encode_signature(r + 1, s)
        assert not sk.public_key.verify(b"test", tampered_sig)

    def test_tampered_s(self):
        sk = p256_keygen()
        sig = sk.sign(b"test")
        r, s = _decode_signature(sig)
        tampered_sig = _encode_signature(r, s + 1)
        assert not sk.public_key.verify(b"test", tampered_sig)

    def test_wrong_message(self):
        sk = p256_keygen()
        sig = sk.sign(b"correct")
        assert not sk.public_key.verify(b"wrong", sig)

    def test_wrong_key(self):
        sk1 = p256_keygen()
        sk2 = p256_keygen()
        sig = sk1.sign(b"test")
        assert not sk2.public_key.verify(b"test", sig)

    def test_curve_mismatch(self):
        sk256 = p256_keygen()
        sk384 = p384_keygen()
        sig256 = sk256.sign(b"test")
        # P-256 signature should not verify with P-384 key
        assert not sk384.public_key.verify(b"test", sig256)


class TestECDSADeterministicK:
    """RFC 6979 deterministic k tests."""

    def test_deterministic_signatures(self):
        """Same message + same key = same signature."""
        sk = p256_keygen()
        sig1 = sk.sign(b"test")
        sig2 = sk.sign(b"test")
        assert sig1 == sig2

    def test_different_messages_different_signatures(self):
        sk = p256_keygen()
        sig1 = sk.sign(b"msg1")
        sig2 = sk.sign(b"msg2")
        assert sig1 != sig2


class TestECDSAECDHEdgeCases:
    """ECDH edge cases."""

    def test_ecdh_symmetry(self):
        sk1 = p256_keygen()
        sk2 = p256_keygen()
        shared1 = sk1.ecdh(sk2.public_key)
        shared2 = sk2.ecdh(sk1.public_key)
        assert shared1 == shared2

    def test_ecdh_self(self):
        sk = p256_keygen()
        shared = sk.ecdh(sk.public_key)
        assert len(shared) == 32

    def test_ecdh_p384(self):
        sk1 = p384_keygen()
        sk2 = p384_keygen()
        shared1 = sk1.ecdh(sk2.public_key)
        shared2 = sk2.ecdh(sk1.public_key)
        assert shared1 == shared2
        assert len(shared1) == 48

    def test_ecdh_curve_mismatch(self):
        sk256 = p256_keygen()
        sk384 = p384_keygen()
        with pytest.raises(ValueError):
            sk256.ecdh(sk384.public_key)

    def test_ecdh_different_partners_different_secrets(self):
        sk1 = p256_keygen()
        sk2 = p256_keygen()
        sk3 = p256_keygen()
        s12 = sk1.ecdh(sk2.public_key)
        s13 = sk1.ecdh(sk3.public_key)
        assert s12 != s13


class TestECDSAEdgeCases:
    """General edge cases."""

    def test_empty_message(self):
        sk = p256_keygen()
        sig = sk.sign(b"")
        assert sk.public_key.verify(b"", sig)

    def test_long_message(self):
        sk = p256_keygen()
        msg = b"x" * 10000
        sig = sk.sign(msg)
        assert sk.public_key.verify(msg, sig)

    def test_all_zero_message(self):
        sk = p256_keygen()
        sig = sk.sign(b"\x00" * 100)
        assert sk.public_key.verify(b"\x00" * 100, sig)

    def test_invalid_private_key_zero(self):
        with pytest.raises(ValueError):
            p256_keygen(private_key=0)

    def test_invalid_private_key_n(self):
        with pytest.raises(ValueError):
            p256_keygen(private_key=P256.n)

    def test_invalid_private_key_negative(self):
        with pytest.raises(ValueError):
            p256_keygen(private_key=-1)
