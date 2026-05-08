import pytest

from crypto_standalone import AveMariaCipher


class TestAveMariaCipher:
    def test_roundtrip_alpha(self):
        c = AveMariaCipher()
        pt = "defendtheeastwall"
        ct = c.encrypt(pt)
        assert c.decrypt(ct) == pt

    def test_preserves_non_letters(self):
        c = AveMariaCipher()
        pt = "abc-123 xyz"
        ct = c.encrypt(pt)
        assert "-" in ct and "123" in ct
        assert c.decrypt(ct) == pt

    def test_expected_prefix(self):
        c = AveMariaCipher()
        assert c.encrypt("abc") == "<ave><maria><gratia>"

    def test_type_errors(self):
        c = AveMariaCipher()
        with pytest.raises(TypeError):
            c.encrypt(b"abc")
        with pytest.raises(TypeError):
            c.decrypt(123)
