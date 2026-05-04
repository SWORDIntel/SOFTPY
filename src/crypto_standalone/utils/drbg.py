"""HMAC_DRBG_SHA256 — NIST SP 800-90A deterministic random bit generator.

Pure-Python, zero-dependency implementation using only the project's
own sha256() and hmac_sha256() from hashing.sha2.
"""

from __future__ import annotations

from ..hashing.sha2 import sha256, hmac_sha256


_OUTLEN = 32  # SHA-256 output length in bytes
_SEEDLEN = 32  # HMAC-DRBG-256 seed length
_RESEED_INTERVAL = 2**48  # max generate calls before mandatory reseed
_MAX_BYTES_PER_REQUEST = 65536  # NIST limit per generate call


class HMAC_DRBG_SHA256:
    """HMAC_DRBG with SHA-256 per NIST SP 800-90A §10.1.2.

    Parameters
    ----------
    entropy_input : bytes
        At least 32 bytes of entropy (the seed).
    personalization : bytes | None
        Optional personalization string (domain separation).
    nonce : bytes | None
        Optional nonce; if *None* a SHA-256 derived value is used.
    """

    def __init__(
        self,
        entropy_input: bytes,
        personalization: bytes | None = None,
        nonce: bytes | None = None,
    ) -> None:
        if len(entropy_input) < _SEEDLEN:
            raise ValueError(
                f"entropy_input must be >= {_SEEDLEN} bytes, got {len(entropy_input)}"
            )

        if personalization is None:
            personalization = b""
        if nonce is None:
            nonce = sha256(b"HMAC-DRBG-256-NONCE|" + entropy_input[:_SEEDLEN])

        # NIST SP 800-90A §10.1.2.3 (Instantiate)
        seed_material = entropy_input + nonce + personalization
        self._key = b"\x00" * _OUTLEN
        self._v = b"\x01" * _OUTLEN
        self._reseed_counter = 1
        self._update(seed_material)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update(self, provided_data: bytes) -> None:
        """HMAC_DRBG_Update (NIST SP 800-90A §10.1.2.2)."""
        k = hmac_sha256(self._key, self._v + b"\x00" + provided_data)
        v = hmac_sha256(k, self._v)
        if not provided_data:
            self._key = k
            self._v = v
            return
        k = hmac_sha256(k, v + b"\x01" + provided_data)
        v = hmac_sha256(k, v)
        self._key = k
        self._v = v

    def _reseed(self, entropy_input: bytes, additional_input: bytes = b"") -> None:
        """HMAC_DRBG_Reseed (NIST SP 800-90A §10.1.2.4)."""
        reseed_material = entropy_input + additional_input
        self._key = b"\x00" * _OUTLEN
        self._v = b"\x01" * _OUTLEN
        self._update(reseed_material)
        self._reseed_counter = 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def random_bytes(
        self,
        n: int,
        additional_input: bytes = b"",
    ) -> bytes:
        """Generate *n* pseudorandom bytes (NIST SP 800-90A §10.1.2.5).

        Parameters
        ----------
        n : int
            Number of bytes requested (0 .. 65536).
        additional_input : bytes
            Optional additional input mixed in before generation.
        """
        if n < 0:
            raise ValueError("n must be non-negative")
        if n > _MAX_BYTES_PER_REQUEST:
            raise ValueError(
                f"n must be <= {_MAX_BYTES_PER_REQUEST} per NIST SP 800-90A"
            )

        if additional_input:
            self._update(additional_input)

        if self._reseed_counter > _RESEED_INTERVAL:
            # In a standalone DRBG without an external entropy source
            # we cannot reseed, so we raise to signal the caller.
            raise RuntimeError(
                "HMAC_DRBG_SHA256: reseed interval exceeded — "
                "provide fresh entropy via reseed()"
            )

        out = bytearray()
        while len(out) < n:
            self._v = hmac_sha256(self._key, self._v)
            out.extend(self._v)

        result = bytes(out[:n])

        # Post-generation update (step 8-10 of §10.1.2.5)
        self._update(additional_input)
        self._reseed_counter += 1

        return result

    def reseed(self, entropy_input: bytes, additional_input: bytes = b"") -> None:
        """Explicit reseed with fresh entropy."""
        self._reseed(entropy_input, additional_input)

    @property
    def reseed_counter(self) -> int:
        return self._reseed_counter
