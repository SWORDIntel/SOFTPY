import os
import pytest

from crypto_standalone import TEA, RedPike


def _hamming_distance(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


class TestTEA:
    def test_known_vector(self):
        key = bytes.fromhex("00000000000000000000000000000000")
        pt = bytes.fromhex("0000000000000000")
        tea = TEA(key)
        # Public TEA KAT for 32 rounds, zero key/plaintext.
        assert tea.encrypt_block(pt).hex() == "41ea3a0a94baa940"

    def test_roundtrip_random(self):
        tea = TEA(os.urandom(16))
        for _ in range(128):
            pt = os.urandom(8)
            assert tea.decrypt_block(tea.encrypt_block(pt)) == pt


class TestRedPike:
    def test_roundtrip_random(self):
        c = RedPike(os.urandom(8))
        for _ in range(128):
            pt = os.urandom(8)
            assert c.decrypt_block(c.encrypt_block(pt)) == pt

    def test_avalanche_sanity(self):
        key = b"\x00" * 8
        c = RedPike(key)
        pt = b"\x00" * 8
        ct1 = c.encrypt_block(pt)
        ct2 = c.encrypt_block(b"\x01" + b"\x00" * 7)
        assert _hamming_distance(ct1, ct2) >= 16


class TestValidation:
    def test_invalid_lengths(self):
        with pytest.raises(ValueError):
            TEA(b"short")
        with pytest.raises(ValueError):
            RedPike(b"short")
        with pytest.raises(ValueError):
            TEA(b"\x00" * 16).encrypt_block(b"\x00")
        with pytest.raises(ValueError):
            RedPike(b"\x00" * 8).decrypt_block(b"\x00")


class TestModularUsageAndCompatibility:
    def test_single_implementation_import(self):
        from crypto_standalone.symmetric.tea import TEA as LegacyTEA

        c = LegacyTEA(b"\x00" * 16)
        pt = b"\x00" * 8
        assert c.decrypt_block(c.encrypt_block(pt)) == pt

    def test_python37_syntax_compatibility(self):
        import ast
        from pathlib import Path

        for rel in ("tea.py", "redpike.py", "avemaria.py", "legacy_ciphers.py"):
            source = Path("src/crypto_standalone/symmetric").joinpath(rel).read_text()
            ast.parse(source, feature_version=(3, 7))
