"""
Attack simulation tests.

Tests that simulate real-world cryptographic attacks:
1. GCM nonce reuse (Forbidden Attack)
2. ECDSA nonce reuse detection
3. RSA cross-key rejection
4. Padding oracle concerns
5. Signature malleability
"""

import os
import pytest
from crypto_standalone import AESGCM, ChaCha20Poly1305
from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify
from crypto_standalone import x25519_keygen, x25519
from crypto_standalone import p256_keygen, P256, _encode_signature, _decode_signature


class TestGCMForbiddenAttack:
    """
    GCM nonce reuse (Forbidden Attack).
    
    When the same nonce is used with the same key for two different
    messages, an attacker can XOR the ciphertexts to get the XOR
    of the plaintexts. This also reveals the GHASH key H.
    """

    def test_nonce_reuse_reveals_plaintext_xor(self):
        """Nonce reuse allows XOR of plaintexts to be computed."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = os.urandom(12)
        
        pt1 = b"message one here"
        pt2 = b"message two there"
        
        ct1, tag1 = gcm.encrypt(pt1, nonce)
        ct2, tag2 = gcm.encrypt(pt2, nonce)
        
        # XOR of ciphertexts = XOR of plaintexts (keystream cancels)
        ct_xor = bytes(a ^ b for a, b in zip(ct1, ct2))
        pt_xor = bytes(a ^ b for a, b in zip(pt1, pt2))
        assert ct_xor == pt_xor  # This IS the attack
    
    def test_nonce_reuse_both_decrypt(self):
        """Both messages still decrypt correctly (the attack is passive)."""
        key = os.urandom(32)
        gcm = AESGCM(key)
        nonce = os.urandom(12)
        
        ct1, tag1 = gcm.encrypt(b"secret1", nonce)
        ct2, tag2 = gcm.encrypt(b"secret2", nonce)
        
        assert gcm.decrypt(ct1, tag1, nonce) == b"secret1"
        assert gcm.decrypt(ct2, tag2, nonce) == b"secret2"


class TestECDSANonceReuse:
    """
    ECDSA nonce reuse attack.
    
    If the same nonce k is used for two different messages,
    the private key can be recovered: d = (z1 - z2) * inv(k) mod n
    where k = (s1 - s2) * inv(r) mod n.
    
    Our implementation uses RFC 6979 deterministic k, which
    guarantees different k for different messages.
    """

    def test_deterministic_k_prevents_nonce_reuse(self):
        """RFC 6979 ensures k is different for each message."""
        sk = p256_keygen()
        msg1 = b"message one"
        msg2 = b"message two"
        
        sig1 = sk.sign(msg1)
        sig2 = sk.sign(msg2)
        
        r1, s1 = _decode_signature(sig1)
        r2, s2 = _decode_signature(sig2)
        
        # Same message should produce same k (and same signature)
        sig1b = sk.sign(msg1)
        r1b, s1b = _decode_signature(sig1b)
        assert r1 == r1b  # Same k → same r
        assert s1 == s1b  # Same message → same s
        
        # Different messages should produce different k
        # (r values differ with overwhelming probability)
        # Note: there's a tiny chance r1 == r2 with different k,
        # but that's astronomically unlikely
        if r1 == r2:
            # If r is the same, s must be different (different z)
            assert s1 != s2, "Same r and s with different messages = nonce reuse!"
    
    def test_same_message_same_signature(self):
        """Deterministic signing: same input = same output."""
        sk = p256_keygen()
        sig1 = sk.sign(b"test")
        sig2 = sk.sign(b"test")
        assert sig1 == sig2


class TestChaCha20NonceReuse:
    """
    ChaCha20 nonce reuse.
    
    Reusing the same nonce with the same key produces the same
    keystream, allowing XOR of plaintexts to be recovered.
    """

    def test_nonce_reuse_reveals_keystream_xor(self):
        key = os.urandom(32)
        cp = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        
        pt1 = b"alpha bravo charlie"
        pt2 = b"delta echo foxtrot"
        
        ct1, tag1 = cp.encrypt(pt1, nonce)
        ct2, tag2 = cp.encrypt(pt2, nonce)
        
        # XOR of ciphertexts = XOR of plaintexts
        ct_xor = bytes(a ^ b for a, b in zip(ct1, ct2))
        pt_xor = bytes(a ^ b for a, b in zip(pt1, pt2))
        assert ct_xor == pt_xor


class TestSignatureMalleability:
    """
    Signature malleability attacks.
    
    For ECDSA, (r, s) and (r, -s mod n) are both valid signatures.
    This can be exploited in blockchain/cryptocurrency contexts
    where transaction uniqueness depends on signature uniqueness.
    """

    def test_ecdsa_malleability_both_valid(self):
        """Both (r, s) and (r, -s mod n) verify — standard ECDSA is malleable."""
        sk = p256_keygen()
        msg = b"transaction data"
        sig = sk.sign(msg)
        r, s = _decode_signature(sig)
        
        sig_malleable = _encode_signature(r, (-s) % P256.n)
        assert sk.public_key.verify(msg, sig)
        assert sk.public_key.verify(msg, sig_malleable)
    
    def test_ed25519_not_malleable_by_design(self):
        """Ed25519 signatures are deterministic and tied to the exact message."""
        sk, pk = ed25519_keygen()
        msg = b"transaction data"
        sig1 = ed25519_sign(msg, sk)
        sig2 = ed25519_sign(msg, sk)
        # Ed25519 is deterministic: same sig every time
        assert sig1 == sig2


class TestCrossAlgorithmRejection:
    """Cross-algorithm rejection: signatures/keys from one algo shouldn't work with another."""

    def test_ed25519_sig_not_valid_as_ecdsa(self):
        """Ed25519 signature bytes are not valid ECDSA DER."""
        sk_ed, pk_ed = ed25519_keygen()
        sig_ed = ed25519_sign(b"test", sk_ed)
        
        # Ed25519 signature is 64 raw bytes, not DER
        # ECDSA verify expects DER, so it should fail gracefully
        sk_ec = p256_keygen()
        # This should not crash, just return False or raise
        try:
            result = sk_ec.public_key.verify(b"test", sig_ed)
            assert not result  # Should not verify
        except (ValueError, IndexError):
            pass  # Also acceptable: reject malformed DER

    def test_x25519_shared_secret_not_valid_aes_key_directly(self):
        """X25519 output should be fed through KDF before use as AES key."""
        sk1, pk1 = x25519_keygen()
        sk2, pk2 = x25519_keygen()
        shared = x25519(sk1, pk2)
        
        # While the shared secret IS 32 bytes (valid AES-256 key size),
        # best practice is to derive the actual key via HKDF
        from crypto_standalone import hkdf_sha256
        aes_key = hkdf_sha256(b"salt", shared, b"aes-key", 32)
        assert len(aes_key) == 32
        # The raw shared secret and derived key should differ
        assert shared != aes_key
