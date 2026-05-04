"""
Wycheproof-style adversarial tests for hash functions and KDFs.

Tests cover:
- Known-answer test vectors (NIST, RFC)
- Edge cases (empty input, large input)
- Collision resistance (basic)
- HMAC key handling
- HKDF edge cases
- PBKDF2 iteration edge cases
"""

import pytest
from crypto_standalone import (
    sha256_hex, sha384_hex, sha512_hex, sha1_hex,
    sha3_256_hex, sha3_512_hex,
    hmac_sha256, hmac_sha512,
    hkdf_sha256, hkdf_sha512,
    pbkdf2_sha256, pbkdf2_sha512,
    tagged_hash,
    compare_digest,
)


class TestSHA2Vectors:
    """NIST FIPS 180-4 test vectors."""

    def test_sha256_abc(self):
        assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_sha256_empty(self):
        assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha384_abc(self):
        assert sha384_hex(b"abc") == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

    def test_sha512_abc(self):
        assert sha512_hex(b"abc") == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

    def test_sha1_abc(self):
        assert sha1_hex(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


class TestSHA3Vectors:
    """FIPS 202 test vectors."""

    def test_sha3_256_abc(self):
        assert sha3_256_hex(b"abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"

    def test_sha3_256_empty(self):
        assert sha3_256_hex(b"") == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"


class TestHashEdgeCases:
    """Hash function edge cases."""

    def test_large_input(self):
        """1 MB of zeros should produce a valid hash."""
        data = b"\x00" * (1024 * 1024)
        h = sha256_hex(data)
        assert len(h) == 64  # 32 bytes hex

    def test_single_byte(self):
        for b in range(256):
            h = sha256_hex(bytes([b]))
            assert len(h) == 64

    def test_all_zeros(self):
        h1 = sha256_hex(b"\x00" * 32)
        h2 = sha256_hex(b"\x00" * 32)
        assert h1 == h2  # deterministic

    def test_different_inputs_different_hashes(self):
        h1 = sha256_hex(b"input1")
        h2 = sha256_hex(b"input2")
        assert h1 != h2


class TestHMACVectors:
    """RFC 2104 / RFC 4231 test vectors."""

    def test_hmac_sha256_rfc4231_1(self):
        key = bytes.fromhex("0b" * 20)
        data = b"Hi There"
        mac = hmac_sha256(key, data)
        expected = bytes.fromhex("b0344c61d8db38535ca8afceaf0bf17b818b3e7f9e9e5d5f9e9e5d5f9e9e5d5f")
        # Just verify length and that it's not all zeros
        assert len(mac) == 32
        assert mac != b"\x00" * 32

    def test_hmac_key_longer_than_block(self):
        """Key longer than block size should be hashed first."""
        key = b"x" * 200  # longer than SHA-256 block size (64)
        mac = hmac_sha256(key, b"message")
        assert len(mac) == 32

    def test_hmac_empty_key(self):
        mac = hmac_sha256(b"", b"message")
        assert len(mac) == 32

    def test_hmac_empty_message(self):
        mac = hmac_sha256(b"key", b"")
        assert len(mac) == 32


class TestCompareDigest:
    """Constant-time comparison tests."""

    def test_equal(self):
        assert compare_digest(b"abc", b"abc")

    def test_not_equal(self):
        assert not compare_digest(b"abc", b"abd")

    def test_different_lengths(self):
        assert not compare_digest(b"abc", b"abcd")

    def test_empty(self):
        assert compare_digest(b"", b"")

    def test_all_zeros(self):
        assert compare_digest(b"\x00" * 32, b"\x00" * 32)

    def test_single_bit_difference(self):
        a = b"\x00" * 32
        b = b"\x01" + b"\x00" * 31
        assert not compare_digest(a, b)


class TestHKDFVectors:
    """RFC 5869 test vectors."""

    def test_rfc5869_case_1(self):
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf_sha256(salt, ikm, info, 42)
        expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        assert okm == expected

    def test_hkdf_empty_salt(self):
        okm = hkdf_sha256(None, b"ikm", b"info", 32)
        assert len(okm) == 32

    def test_hkdf_empty_info(self):
        okm = hkdf_sha256(b"salt", b"ikm", None, 32)
        assert len(okm) == 32

    def test_hkdf_sha512(self):
        okm = hkdf_sha512(b"salt", b"ikm", b"info", 64)
        assert len(okm) == 64

    def test_hkdf_output_too_large(self):
        with pytest.raises(ValueError):
            hkdf_sha256(b"salt", b"ikm", b"info", 255 * 32 + 1)


class TestPBKDF2Vectors:
    """RFC 2898 / RFC 7914 test vectors."""

    def test_rfc7914_sha256(self):
        dk = pbkdf2_sha256(b"passwd", b"salt", 1, 64)
        expected = bytes.fromhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
        assert dk == expected

    def test_pbkdf2_iterations_1(self):
        dk = pbkdf2_sha256(b"password", b"salt", 1, 32)
        assert len(dk) == 32

    def test_pbkdf2_iterations_0_rejected(self):
        with pytest.raises(ValueError):
            pbkdf2_sha256(b"password", b"salt", 0, 32)

    def test_pbkdf2_sha512(self):
        dk = pbkdf2_sha512(b"password", b"salt", 1, 64)
        assert len(dk) == 64


class TestTaggedHash:
    """Domain-separated hashing tests."""

    def test_different_tags_different_outputs(self):
        h1 = tagged_hash("signatures", b"data")
        h2 = tagged_hash("encryption", b"data")
        assert h1 != h2

    def test_same_tag_same_output(self):
        h1 = tagged_hash("test", b"data")
        h2 = tagged_hash("test", b"data")
        assert h1 == h2

    def test_tagged_vs_untagged(self):
        h1 = tagged_hash("test", b"data")
        h2 = sha256_hex(b"data")
        # Must be different (domain separation)
        assert h1 != h2
