AVE_MARIA_TABLES = (
    ("altissimus", "beata", "clementia"),
    ("benignitas", "caelestis", "devotio"),
    ("caritas", "dignitas", "elevatio"),
    ("dominus", "exultatio", "fidelitas"),
    ("electio", "felicitas", "gloria"),
    ("fortitudo", "gratia", "humilitas"),
    ("gaudium", "honor", "illuminatio"),
    ("humanitas", "integritas", "justitia"),
    ("indulgentia", "jubilatio", "kyrie"),
    ("jucunditas", "karitas", "laetitia"),
    ("kenosis", "lumen", "misericordia"),
    ("largitas", "magnitudo", "novitas"),
    ("mansuetudo", "nobilitas", "obedientia"),
    ("nativitas", "oratio", "patientia"),
    ("oikonomia", "pietas", "quies"),
    ("praesentia", "quietudo", "reverentia"),
    ("puritas", "rectitudo", "sanctitas"),
    ("regnum", "sapientia", "tranquillitas"),
    ("salus", "temperantia", "unitas"),
    ("trinitas", "utilitas", "veritas"),
    ("ubertas", "virtus", "wisdom"),
    ("veneratio", "xristus", "xenium"),
    ("vigilantia", "ymnus", "zephyrus"),
    ("xenodochium", "zelus", "aleluia"),
    ("ymnus", "agape", "benedictio"),
    ("zelus", "beatitudo", "concordia"),
)

AVE_MARIA_TOKENS = (
    "ave", "maria", "gratia", "plena", "dominus", "tecum", "benedicta", "tu",
    "in", "mulieribus", "et", "benedictus", "fructus", "ventris", "tui", "iesus",
    "sancta", "dei", "mater", "ora", "pro", "nobis", "peccatoribus", "nunc",
    "et_in", "hora",
)


class AveMariaCipher:
    """Trithemius-inspired Ave Maria steganographic substitution.

    Interoperability functionality only; not modern cryptographic security.

    Modes:
    - ``cycle``: rotate across three phrase tables; emits ``<table:phrase>``.
    - ``fixed``: use table 0 only; emits ``<0:phrase>``.

    The decryptor also accepts the older single-token format ``<token>`` using
    ``AVE_MARIA_TOKENS`` for backward compatibility.
    """

    def __init__(self, table_mode: str = "cycle") -> None:
        if table_mode not in {"cycle", "fixed"}:
            raise ValueError("table_mode must be 'cycle' or 'fixed'")

        self.table_mode = table_mode

        self._enc: list[dict[str, str]] = []
        self._dec: list[dict[str, str]] = []

        for table_idx in range(3):
            enc = {
                chr(ord("a") + i): AVE_MARIA_TABLES[i][table_idx]
                for i in range(26)
            }
            dec = {token: letter for letter, token in enc.items()}
            self._enc.append(enc)
            self._dec.append(dec)

        self._legacy_dec = {
            token: chr(ord("a") + i)
            for i, token in enumerate(AVE_MARIA_TOKENS)
        }

    def _table_index(self, letter_count: int) -> int:
        if self.table_mode == "fixed":
            return 0
        return letter_count % 3

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")

        out: list[str] = []
        letter_count = 0

        for ch in plaintext.lower():
            if "a" <= ch <= "z":
                table_idx = self._table_index(letter_count)
                out.append(f"<{table_idx}:{self._enc[table_idx][ch]}>")
                letter_count += 1
            else:
                out.append(ch)

        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        if not isinstance(ciphertext, str):
            raise TypeError("ciphertext must be str")

        out: list[str] = []
        i = 0

        while i < len(ciphertext):
            if ciphertext[i] != "<":
                out.append(ciphertext[i])
                i += 1
                continue

            j = ciphertext.find(">", i + 1)
            if j == -1:
                out.append(ciphertext[i])
                i += 1
                continue

            body = ciphertext[i + 1:j]

            if ":" in body:
                table_str, phrase = body.split(":", 1)
                if table_str.isdigit():
                    table_idx = int(table_str)
                    if 0 <= table_idx < len(self._dec):
                        out.append(self._dec[table_idx].get(phrase, f"<{body}>"))
                    else:
                        out.append(f"<{body}>")
                else:
                    out.append(f"<{body}>")
            else:
                out.append(self._legacy_dec.get(body, f"<{body}>"))

            i = j + 1

        return "".join(out)