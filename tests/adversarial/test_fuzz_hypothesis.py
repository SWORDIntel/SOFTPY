"""
Property-based fuzzing tests using Hypothesis.

These tests use random input generation to find edge cases
that hand-written tests might miss.
"""

import os
import pytest

try:
    from hypothesis import given, settings, strategies as st, assume
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

pytestmark = pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")

from crypto_standalone import AESGCM, ChaCha20Poly1305, sha256, sha512
from crypto_standalone import hmac_sha256, hkdf_sha256, pbkdf2_sha256
from crypto_standalone import ed25519_keygen, ed25519_sign, ed25519_verify
from crypto_standalone import x25519_keygen, x25519
from crypto_standalone import compare_digest


# --- AEAD roundtrip property ---

@given(
    plaintext=st.binary(min_size=0, max_size=512),
    aad=st.binary(min_size=0, max_size=128),
)
@settings(max_examples=50, deadline=None)
def test_aes_gcm_roundtrip_property(plaintext, aad):
    """Property: decrypt(encrypt(pt, aad), aad) == pt for all inputs."""
    key = os.urandom(32)
    gcm = AESGCM(key)
    blob = gcm.encrypt_blob(plaintext, aad=aad)
    assert gcm.decrypt_blob(blob, aad=aad) == plaintext


@given(
    plaintext=st.binary(min_size=0, max_size=512),
    aad=st.binary(min_size=0, max_size=128),
)
@settings(max_examples=50, deadline=None)
def test_chacha20_poly1305_roundtrip_property(plaintext, aad):
    """Property: decrypt(encrypt(pt, aad), aad) == pt for all inputs."""
    key = os.urandom(32)
    cp = ChaCha20Poly1305(key)
    blob = cp.encrypt_blob(plaintext, aad=aad)
    assert cp.decrypt_blob(blob, aad=aad) == plaintext


# --- Hash determinism property ---

@given(data=st.binary(min_size=0, max_size=256))
@settings(max_examples=50, deadline=None)
def test_sha256_deterministic(data):
    """Property: sha256(data) == sha256(data) always."""
    assert sha256(data) == sha256(data)


@given(data=st.binary(min_size=0, max_size=256))
@settings(max_examples=50, deadline=None)
def test_sha512_deterministic(data):
    assert sha512(data) == sha512(data)


@given(data=st.binary(min_size=0, max_size=256))
@settings(max_examples=50, deadline=None)
def test_sha256_different_inputs_different_hashes(data):
    """Property: different inputs produce different hashes (with high probability)."""
    if len(data) == 0:
        return
    modified = data[:-1] + bytes([(data[-1] ^ 0x01) & 0xFF]) if data else b"\x01"
    if modified != data:
        assert sha256(data) != sha256(modified)


# --- HMAC determinism property ---

@given(
    key=st.binary(min_size=1, max_size=128),
    message=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=50, deadline=None)
def test_hmac_sha256_deterministic(key, message):
    assert hmac_sha256(key, message) == hmac_sha256(key, message)


# --- Compare digest property ---

@given(a=st.binary(min_size=0, max_size=64))
@settings(max_examples=50, deadline=None)
def test_compare_digest_reflexive(a):
    """Property: compare_digest(a, a) is always True."""
    assert compare_digest(a, a)


@given(
    a=st.binary(min_size=1, max_size=64),
    b=st.binary(min_size=1, max_size=64),
)
@settings(max_examples=50, deadline=None)
def test_compare_digest_different(a, b):
    """Property: different byte sequences are not equal."""
    assume(a != b)
    assert not compare_digest(a, b)


# --- Ed25519 sign/verify property ---

@given(message=st.binary(min_size=0, max_size=256))
@settings(max_examples=20, deadline=None)
def test_ed25519_sign_verify_property(message):
    """Property: every signed message verifies."""
    sk, pk = ed25519_keygen()
    sig = ed25519_sign(message, sk)
    assert ed25519_verify(message, sig, pk)


# --- X25519 agreement property ---

def test_x25519_agreement_property():
    """Property: ECDH agreement is symmetric."""
    sk1, pk1 = x25519_keygen()
    sk2, pk2 = x25519_keygen()
    assert x25519(sk1, pk2) == x25519(sk2, pk1)


# --- HKDF output length property ---

@given(
    ikm=st.binary(min_size=1, max_size=64),
    length=st.integers(min_value=1, max_value=64),
)
@settings(max_examples=50, deadline=None)
def test_hkdf_output_length_property(ikm, length):
    """Property: HKDF output length matches requested length."""
    okm = hkdf_sha256(b"salt", ikm, b"info", length)
    assert len(okm) == length


# --- AEAD tamper detection property ---

@given(
    plaintext=st.binary(min_size=1, max_size=256),
    aad=st.binary(min_size=0, max_size=64),
    flip_pos=st.integers(min_value=0, max_value=300),
)
@settings(max_examples=30, deadline=None)
def test_aes_gcm_tamper_detection(plaintext, aad, flip_pos):
    """Property: any single-bit flip in blob causes authentication failure."""
    key = os.urandom(32)
    gcm = AESGCM(key)
    blob = gcm.encrypt_blob(plaintext, aad=aad)
    
    if flip_pos >= len(blob):
        return  # skip if flip position is beyond blob
    
    tampered = bytearray(blob)
    tampered[flip_pos] ^= 0x01
    with pytest.raises(ValueError):
        gcm.decrypt_blob(bytes(tampered), aad=aad)
