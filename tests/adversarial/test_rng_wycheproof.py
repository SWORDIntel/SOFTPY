"""Adversarial tests for HMAC_DRBG_SHA256 and DigitalURandom."""

import pytest
from crypto_standalone import HMAC_DRBG_SHA256, DigitalURandom


class TestDRBGStateCompromise:
    """If DRBG state leaks, future outputs should still be unpredictable
    given that reseed is called with fresh entropy."""

    def test_reseed_after_state_leak_changes_output(self):
        """Simulate: attacker learns internal state, then we reseed."""
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        # Attacker "knows" state after this call
        out1 = drbg.random_bytes(32)
        # Reseed with fresh entropy
        drbg.reseed(entropy_input=b"\xff" * 32)
        out2 = drbg.random_bytes(32)
        # Output after reseed differs from what attacker could predict
        assert out1 != out2

    def test_backtracking_resistance(self):
        """Knowing current output should not reveal previous outputs."""
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        out1 = drbg.random_bytes(32)
        out2 = drbg.random_bytes(32)
        # Post-generation update ensures out2 doesn't reveal out1
        # We can't prove this cryptographically, but verify they differ
        assert out1 != out2


class TestDRBGInvalidInputs:
    """Malformed inputs to DRBG."""

    def test_empty_entropy_rejected(self):
        with pytest.raises(ValueError):
            HMAC_DRBG_SHA256(entropy_input=b"")

    def test_31_byte_entropy_rejected(self):
        with pytest.raises(ValueError):
            HMAC_DRBG_SHA256(entropy_input=b"\x00" * 31)

    def test_zero_length_generate_ok(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        out = drbg.random_bytes(0)
        assert out == b""

    def test_oversized_generate_rejected(self):
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        with pytest.raises(ValueError):
            drbg.random_bytes(65537)

    def test_reseed_with_short_entropy(self):
        """Reseed doesn't validate entropy length — but should still work."""
        drbg = HMAC_DRBG_SHA256(entropy_input=b"\x00" * 32)
        # Reseed with less than 32 bytes — DRBG doesn't enforce, but output changes
        drbg.reseed(entropy_input=b"\xaa" * 16)
        out = drbg.random_bytes(32)
        assert len(out) == 32


class TestDRBGPredictionResistance:
    """Verify DRBG with additional_input provides prediction resistance."""

    def test_additional_input_breaks_prediction(self):
        seed = b"\x00" * 32
        d1 = HMAC_DRBG_SHA256(entropy_input=seed)
        d2 = HMAC_DRBG_SHA256(entropy_input=seed)
        # Without additional_input, outputs are identical
        a1 = d1.random_bytes(32)
        a2 = d2.random_bytes(32)
        assert a1 == a2
        # With additional_input, outputs diverge
        b1 = d1.random_bytes(32, additional_input=b"fresh-entropy")
        b2 = d2.random_bytes(32)  # no additional input
        assert b1 != b2


class TestDigitalURandomAdversarial:
    """Adversarial tests for DigitalURandom."""

    def test_large_request(self):
        rng = DigitalURandom(strict_hardware=False)
        out = rng.urandom(1024)
        assert len(out) == 1024

    def test_many_small_requests(self):
        """Many small requests should not produce identical outputs."""
        rng = DigitalURandom(strict_hardware=False)
        outputs = [rng.urandom(4) for _ in range(32)]
        # At least some should differ (probability of all same is ~2^-248)
        assert len(set(outputs)) > 1

    def test_output_not_constant(self):
        """Two DigitalURandom instances should produce different outputs."""
        rng1 = DigitalURandom(strict_hardware=False)
        rng2 = DigitalURandom(strict_hardware=False)
        out1 = rng1.urandom(32)
        out2 = rng2.urandom(32)
        assert out1 != out2

    def test_bit_distribution_not_degenerate(self):
        """Output should not be all-zeros or all-ones."""
        rng = DigitalURandom(strict_hardware=False)
        out = rng.urandom(256)
        ones = sum(bin(b).count("1") for b in out)
        total = 256 * 8
        # Should be roughly 50% ones, but we're generous: 10%-90%
        assert total // 10 < ones < total * 9 // 10
