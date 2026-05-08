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

    def test_cycle_table_tags(self):
        c = AveMariaCipher(table_mode="cycle")
        assert c.encrypt("abc") == "<0:altissimus><1:caelestis><2:elevatio>"

    def test_fixed_table_mode(self):
        c = AveMariaCipher(table_mode="fixed")
        assert c.encrypt("abc") == "<0:altissimus><0:benignitas><0:caritas>"

    def test_legacy_token_decode(self):
        c = AveMariaCipher()
        assert c.decrypt("<ave><maria><gratia>") == "abc"

    def test_invalid_mode(self):
        with pytest.raises(ValueError):
            AveMariaCipher(table_mode="random")

    def test_type_errors(self):
        c = AveMariaCipher()
        with pytest.raises(TypeError):
            c.encrypt(b"abc")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            c.decrypt(123)  # type: ignore[arg-type]