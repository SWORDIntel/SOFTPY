import pytest
import binascii
from src.crypto_standalone.symmetric.aes import AES, AES256
from src.crypto_standalone.symmetric.aes_ige import aes_ige_encrypt, aes_ige_decrypt

# Test Vectors Generated using OpenSSL equivalent functionality
AES_128_IGE = {
    "key": "9c5deda82f20fd389c3158f8948741d8",
    "iv": "5f5093204e42d4c8f61ba70ac0b044edd01515f67299b102a538d0baddab46c3",
    "pt": "99844ed5c600021004f9fea56b978ca9b314b45d885a484c1fdc9ad1cc6e8f239aeb160d3a44afbf76624761686eded43b95645c451265c7825711c97bc808d2",
    "ct": "626e8fab4bd8c0d807674de8ac3f57a2e096dcc22eb5f21721d3611ad2ce7cbff09325393639e5b0586d87dd529629b4c5f205420a0788a51ce197e17d4df474",
}

AES_192_IGE = {
    "key": "eb662821f13222939a7dcb798066465523f64574bee4ba92",
    "iv": "7e73adfb7a244e2c531d97c3963ae530d66ab8c480a08a4bf1420924b1f8b7e0",
    "pt": "2826dfa50a9e7bd8ef9dd7dae9a63814230509f529d5dd8261a74c5c68e4583e6e07bc364a72a4a3c99da5fd8c91b199f2eaad6811e61995f59656faf1dde6ea",
    "ct": "a4cb85365267b110ec87ad00e5f9128537fe40e2c801c02c8345486af40da3a25f6448b18cd311ce9d8d028855da9a60bf6d43a9c944c986229abe25fddf2eaf",
}

AES_256_IGE = {
    "key": "df9533a306cab216fe8ea0e85894a576d6ddf201a5623542b4438bbcfce107b7",
    "iv": "3ad730c66484bb5287ddc74b2130b8f19883e5bddec9484d0ec5b899ae28ca1a",
    "pt": "ab2810ff8f4d39ddb54e4238f7ad59d189cb056b1bf5c6f56d250a02bc8a970f0f7869391d9dc7ae68a782f24f8d248030ed6015c7fe03627c861099311c78f1",
    "ct": "9577723b7397ce6f969e44c520ee92363130a44b8ae1be984256442a7722ceacf950044f8fdd6bff8ad7fb9d658a9129f04b964e476ec2a25bbd7020eb799fea",
}


class TestAESIGE:
    @pytest.mark.parametrize("vector", [AES_128_IGE, AES_192_IGE, AES_256_IGE])
    def test_kat(self, vector):
        key = binascii.unhexlify(vector["key"])
        iv = binascii.unhexlify(vector["iv"])
        pt = binascii.unhexlify(vector["pt"])
        expected_ct = binascii.unhexlify(vector["ct"])

        ct = aes_ige_encrypt(pt, key, iv)
        assert ct == expected_ct

        dec_pt = aes_ige_decrypt(expected_ct, key, iv)
        assert dec_pt == pt

    def test_invalid_iv_length(self):
        key = b"\x00" * 32
        pt = b"\x00" * 16
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            aes_ige_encrypt(pt, key, b"\x00" * 16)
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            aes_ige_decrypt(pt, key, b"\x00" * 16)

    def test_invalid_plaintext_length(self):
        key = b"\x00" * 32
        iv = b"\x00" * 32
        pt = b"\x00" * 15
        with pytest.raises(ValueError, match="must be a multiple"):
            aes_ige_encrypt(pt, key, iv)
        with pytest.raises(ValueError, match="must be a multiple"):
            aes_ige_decrypt(pt, key, iv)

    def test_empty_input(self):
        key = b"\x00" * 32
        iv = b"\x00" * 32
        assert aes_ige_encrypt(b"", key, iv) == b""
        assert aes_ige_decrypt(b"", key, iv) == b""


class TestAES:
    def test_key_lengths(self):
        AES(b"\x00" * 16)
        AES(b"\x00" * 24)
        AES(b"\x00" * 32)

        with pytest.raises(ValueError):
            AES(b"\x00" * 15)

    def test_aes256_compat(self):
        AES256(b"\x00" * 32)
        with pytest.raises(ValueError):
            AES256(b"\x00" * 16)
