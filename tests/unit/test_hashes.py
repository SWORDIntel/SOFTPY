"""Unit tests for SHA-2 and SHA-3 hash functions."""

import pytest
from crypto_standalone import (
    sha1, sha256, sha384, sha512,
    sha1_hex, sha256_hex, sha384_hex, sha512_hex,
    sha3_256, sha3_512, sha3_256_hex,
    shake_128, shake_256,
    hmac_sha256, hmac_sha512,
    compare_digest, tagged_hash,
)


class TestSHA2:
    """SHA-2 family unit tests."""

    def test_sha256_length(self):
        assert len(sha256(b"test")) == 32

    def test_sha384_length(self):
        assert len(sha384(b"test")) == 48

    def test_sha512_length(self):
        assert len(sha512(b"test")) == 64

    def test_sha1_length(self):
        assert len(sha1(b"test")) == 20

    def test_sha256_empty(self):
        h = sha256(b"")
        assert len(h) == 32
        assert h != b"\x00" * 32

    def test_sha256_abc(self):
        assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_sha384_abc(self):
        assert sha384_hex(b"abc") == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"

    def test_sha512_abc(self):
        assert sha512_hex(b"abc") == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"


class TestSHA3:
    """SHA-3 family unit tests."""

    def test_sha3_256_length(self):
        assert len(sha3_256(b"test")) == 32

    def test_sha3_512_length(self):
        assert len(sha3_512(b"test")) == 64

    def test_sha3_256_abc(self):
        assert sha3_256_hex(b"abc") == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"

    def test_shake128_variable_length(self):
        assert len(shake_128(b"test", 16)) == 16
        assert len(shake_128(b"test", 32)) == 32
        assert len(shake_128(b"test", 64)) == 64

    def test_shake256_variable_length(self):
        assert len(shake_256(b"test", 32)) == 32


class TestHMAC:
    """HMAC unit tests."""

    def test_hmac_sha256_length(self):
        assert len(hmac_sha256(b"key", b"msg")) == 32

    def test_hmac_sha512_length(self):
        assert len(hmac_sha512(b"key", b"msg")) == 64

    def test_hmac_key_dependency(self):
        mac1 = hmac_sha256(b"key1", b"msg")
        mac2 = hmac_sha256(b"key2", b"msg")
        assert mac1 != mac2

    def test_hmac_message_dependency(self):
        mac1 = hmac_sha256(b"key", b"msg1")
        mac2 = hmac_sha256(b"key", b"msg2")
        assert mac1 != mac2


class TestCompareDigest:
    """Constant-time comparison."""

    def test_equal(self):
        assert compare_digest(b"abc", b"abc")

    def test_not_equal(self):
        assert not compare_digest(b"abc", b"abd")

    def test_different_lengths(self):
        assert not compare_digest(b"abc", b"abcd")


class TestTaggedHash:
    """Domain-separated hashing."""

    def test_different_tags(self):
        h1 = tagged_hash("tag1", b"data")
        h2 = tagged_hash("tag2", b"data")
        assert h1 != h2

    def test_same_tag(self):
        h1 = tagged_hash("tag", b"data")
        h2 = tagged_hash("tag", b"data")
        assert h1 == h2
