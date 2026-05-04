"""Lightweight RNG-only import.

Use this when you only need random number generation and don't want
to pull in the full crypto_standalone package (AES, RSA, etc.).

    from crypto_standalone.rng import urandom, token_hex, DigitalURandom
"""

from .utils.digital_entropy import DigitalURandom, self_test
from .utils.drbg import HMAC_DRBG_SHA256
from .utils.random import (
    urandom,
    random_bytes,
    random_below,
    random_bits,
    token_bytes,
    token_hex,
    token_urlsafe,
    CSPRNG,
)

__all__ = [
    "urandom",
    "random_bytes",
    "random_below",
    "random_bits",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
    "CSPRNG",
    "DigitalURandom",
    "HMAC_DRBG_SHA256",
    "self_test",
]
