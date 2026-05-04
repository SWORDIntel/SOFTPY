"""Unit tests for KDFs (HKDF, PBKDF2) and utilities."""

import os
import pytest
from crypto_standalone import (
    hkdf_sha256, hkdf_sha512, hkdf_extract, hkdf_expand,
    pbkdf2_sha256, pbkdf2_sha512,
    random_bytes, random_below, random_bits, CSPRNG,
    secure_zero, SecureBytes, constant_time_compare,
)


class TestHKDF:
    """HKDF (RFC 5869)."""

    def test_rfc5869_vector(self):
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf_sha256(salt, ikm, info, 42)
        expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        assert okm == expected

    def test_output_length(self):
        okm = hkdf_sha256(b"salt", b"ikm", b"info", 32)
        assert len(okm) == 32

    def test_sha512_variant(self):
        okm = hkdf_sha512(b"salt", b"ikm", b"info", 64)
        assert len(okm) == 64


class TestPBKDF2:
    """PBKDF2 (RFC 2898)."""

    def test_rfc7914_vector(self):
        dk = pbkdf2_sha256(b"passwd", b"salt", 1, 64)
        expected = bytes.fromhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
        assert dk == expected

    def test_output_length(self):
        dk = pbkdf2_sha256(b"password", b"salt", 100, 32)
        assert len(dk) == 32

    def test_iterations_zero_rejected(self):
        with pytest.raises(ValueError):
            pbkdf2_sha256(b"password", b"salt", 0, 32)


class TestCSPRNG:
    """CSPRNG wrapper."""

    def test_random_bytes(self):
        r = random_bytes(32)
        assert len(r) == 32
        assert r != b"\x00" * 32

    def test_random_below(self):
        r = random_below(100)
        assert 0 <= r < 100

    def test_random_bits(self):
        r = random_bits(256)
        assert r < (1 << 256)

    def test_csprng_class(self):
        rng = CSPRNG()
        assert len(rng.random_bytes(16)) == 16


class TestSecureMemory:
    """Secure memory utilities."""

    def test_secure_zero(self):
        data = bytearray(b"sensitive")
        secure_zero(data)
        assert data == bytearray(len(data))

    def test_secure_zero_wrong_type(self):
        with pytest.raises(TypeError):
            secure_zero(b"immutable")

    def test_secure_bytes_context(self):
        with SecureBytes(32) as sb:
            sb[:] = b"\xaa" * 32
            assert len(sb) == 32
        # After exit, data is zeroed

    def test_constant_time_compare(self):
        assert constant_time_compare(b"abc", b"abc")
        assert not constant_time_compare(b"abc", b"abd")
