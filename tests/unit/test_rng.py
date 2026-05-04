"""Unit tests for HMAC_DRBG_SHA256 and DigitalURandom."""

import pytest
from crypto_standalone import HMAC_DRBG_SHA256, DigitalURandom, self_test
from crypto_standalone.utils.drbg import _OUTLEN, _MAX_BYTES_PER_REQUEST


class TestHMACDRBGInit:
    """HMAC_DRBG_SHA256 instantiation."""

    def test_basic_init(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        assert drbg.reseed_counter == 1

    def test_insufficient_entropy_rejected(self):
        with pytest.raises(ValueError, match=">= 32"):
            HMAC_DRBG_SHA256(entropy_input=b"\x00" * 16)

    def test_with_personalization(self):
        drbg = HMAC_DRBG_SHA256(
            entropy_input=b"\x00" * 32,
            personalization=b"test-domain",
        )
        assert drbg.reseed_counter == 1

    def test_with_explicit_nonce(self):
        drbg = HMAC_DRBG_SHA256(
            entropy_input=b"\x00" * 32,
            nonce=b"\xaa" * 16,
        )
        assert drbg.reseed_counter == 1

    def test_different_seeds_produce_different_output(self):
        d1 = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        d2 = HMAC_DRBG_SHA256(entropy_input=b"\xff" * 32)
        assert d1.random_bytes(32) != d2.random_bytes(32)

    def test_different_personalization_produces_different_output(self):
        d1 = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32, personalization=b"A")
        d2 = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32, personalization=b"B")
        assert d1.random_bytes(32) != d2.random_bytes(32)


class TestHMACDRBGGenerate:
    """HMAC_DRBG_SHA256 generation."""

    def test_output_length(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        assert len(drbg.random_bytes(0)) == 0
        assert len(drbg.random_bytes(1)) == 1
        assert len(drbg.random_bytes(32)) == 32
        assert len(drbg.random_bytes(100)) == 100

    def test_deterministic_kat(self):
        """Same seed + personalization → same first output."""
        seed = b"\xab" * 32
        d1 = HMAC_DRBG_SHA256(entropy_input=seed, personalization=b"KAT")
        d2 = HMAC_DRBG_SHA256(entropy_input=seed, personalization=b"KAT")
        assert d1.random_bytes(32) == d2.random_bytes(32)

    def test_consecutive_outputs_differ(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        a = drbg.random_bytes(32)
        b = drbg.random_bytes(32)
        assert a != b

    def test_not_all_zero(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        out = drbg.random_bytes(32)
        assert out != b"\x00" * 32

    def test_negative_length_rejected(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        with pytest.raises(ValueError, match="non-negative"):
            drbg.random_bytes(-1)

    def test_max_bytes_limit(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        with pytest.raises(ValueError, match="65536"):
            drbg.random_bytes(65537)

    def test_max_bytes_ok(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        out = drbg.random_bytes(65536)
        assert len(out) == 65536

    def test_reseed_counter_increments(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        assert drbg.reseed_counter == 1
        drbg.random_bytes(32)
        assert drbg.reseed_counter == 2
        drbg.random_bytes(32)
        assert drbg.reseed_counter == 3

    def test_additional_input_changes_output(self):
        seed = b"\x00" * 32
        d1 = HMAC_DRBG_SHA256(entropy_input=seed)
        d2 = HMAC_DRBG_SHA256(entropy_input=seed)
        # Same seed, same first call
        a1 = d1.random_bytes(32)
        a2 = d2.random_bytes(32, additional_input=b"extra")
        assert a1 != a2  # additional_input changes state before generation


class TestHMACDRBGReseed:
    """HMAC_DRBG_SHA256 reseed."""

    def test_reseed_resets_counter(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        drbg.random_bytes(32)
        drbg.random_bytes(32)
        assert drbg.reseed_counter == 3
        drbg.reseed(entropy_input=b"\xff" * 32)
        assert drbg.reseed_counter == 1

    def test_reseed_changes_output(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        before = drbg.random_bytes(32)
        drbg.reseed(entropy_input=b"\xff" * 32)
        after = drbg.random_bytes(32)
        assert before != after

    def test_reseed_with_additional_input(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        drbg.reseed(entropy_input=b"\xaa" * 32, additional_input=b"extra")
        assert drbg.reseed_counter == 1


class TestDigitalURandom:
    """DigitalURandom entropy-based RNG."""

    def test_urandom_length(self):
        rng = DigitalURandom(strict_hardware=False)
        assert len(rng.urandom(0)) == 0
        assert len(rng.urandom(1)) == 1
        assert len(rng.urandom(32)) == 32

    def test_urandom_not_all_zero(self):
        rng = DigitalURandom(strict_hardware=False)
        out = rng.urandom(32)
        assert out != b"\x00" * 32

    def test_consecutive_calls_differ(self):
        rng = DigitalURandom(strict_hardware=False)
        a = rng.urandom(32)
        b = rng.urandom(32)
        assert a != b

    def test_hex_output(self):
        rng = DigitalURandom(strict_hardware=False)
        h = rng.hex(16)
        assert len(h) == 32  # 16 bytes = 32 hex chars
        assert all(c in "0123456789abcdef" for c in h)

    def test_negative_n_rejected(self):
        rng = DigitalURandom(strict_hardware=False)
        with pytest.raises(ValueError, match="non-negative"):
            rng.urandom(-1)

    def test_report_has_events(self):
        rng = DigitalURandom(strict_hardware=False)
        r = rng.report
        assert "events" in r
        assert "hardware_bytes" in r
        assert len(r["events"]) > 0

    def test_strict_hardware_without_hw_raises(self):
        """strict_hardware=True requires TPM/HWRNG, likely absent in CI."""
        with pytest.raises(RuntimeError, match="strict_hardware"):
            DigitalURandom(strict_hardware=True)


class TestSelfTest:
    """self_test() integration."""

    def test_self_test_passes(self):
        assert self_test() is True
