import importlib
import os

import pytest

from crypto_standalone import AveMariaCipher, RedPike, TEA


@pytest.mark.parametrize(
    "name,key_len,block_len",
    [
        ("TEA", 16, 8),
        ("RedPike", 8, 8),
    ],
)
def test_block_cipher_roundtrip_matrix(name: str, key_len: int, block_len: int) -> None:
    cipher_cls = {"TEA": TEA, "RedPike": RedPike}[name]
    c = cipher_cls(os.urandom(key_len))
    for _ in range(256):
        pt = os.urandom(block_len)
        assert c.decrypt_block(c.encrypt_block(pt)) == pt


def test_ave_maria_cycle_vs_fixed_determinism() -> None:
    plaintext = "attackatdawn"
    cycle = AveMariaCipher(table_mode="cycle")
    fixed = AveMariaCipher(table_mode="fixed")

    cycle_ct = cycle.encrypt(plaintext)
    fixed_ct = fixed.encrypt(plaintext)

    assert cycle_ct != fixed_ct
    assert cycle.decrypt(cycle_ct) == plaintext
    assert fixed.decrypt(fixed_ct) == plaintext


def test_ave_maria_decrypt_passthrough_unknown_tokens() -> None:
    c = AveMariaCipher()
    ct = "<9:unknown><missing_colon><0:not_in_table>"
    assert c.decrypt(ct) == ct


def test_kasumi_symbol_presence_or_explicit_skip() -> None:
    module = importlib.import_module("crypto_standalone.symmetric.legacy_ciphers")
    if hasattr(module, "KASUMI"):
        kasumi = getattr(module, "KASUMI")
        assert callable(kasumi)
    else:
        pytest.skip("KASUMI cipher is not yet implemented/exported in legacy_ciphers")
