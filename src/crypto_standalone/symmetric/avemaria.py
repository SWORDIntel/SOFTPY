"""Trithemius-inspired Ave Maria substitution cipher (legacy/interoperability)."""

from typing import Dict, List

AVE_MARIA_TABLES = (
    ("altissimus", "beata", "clementia"), ("benignitas", "caelestis", "devotio"), ("caritas", "dignitas", "elevatio"),
    ("dominus", "exultatio", "fidelitas"), ("electio", "felicitas", "gloria"), ("fortitudo", "gratia", "humilitas"),
    ("gaudium", "honor", "illuminatio"), ("humanitas", "integritas", "justitia"), ("indulgentia", "jubilatio", "kyrie"),
    ("jucunditas", "karitas", "laetitia"), ("kenosis", "lumen", "misericordia"), ("largitas", "magnitudo", "novitas"),
    ("mansuetudo", "nobilitas", "obedientia"), ("nativitas", "oratio", "patientia"), ("oikonomia", "pietas", "quies"),
    ("praesentia", "quietudo", "reverentia"), ("puritas", "rectitudo", "sanctitas"), ("regnum", "sapientia", "tranquillitas"),
    ("salus", "temperantia", "unitas"), ("trinitas", "utilitas", "veritas"), ("ubertas", "virtus", "wisdom"),
    ("veneratio", "xristus", "xenium"), ("vigilantia", "ymnus", "zephyrus"), ("xenodochium", "zelus", "aleluia"),
    ("ymnus", "agape", "benedictio"), ("zelus", "beatitudo", "concordia"),
)
AVE_MARIA_TOKENS = ("ave", "maria", "gratia", "plena", "dominus", "tecum", "benedicta", "tu", "in", "mulieribus", "et", "benedictus", "fructus", "ventris", "tui", "iesus", "sancta", "dei", "mater", "ora", "pro", "nobis", "peccatoribus", "nunc", "et_in", "hora")

class AveMariaCipher:
    def __init__(self, table_mode: str = "cycle") -> None:
        if table_mode not in {"cycle", "fixed"}:
            raise ValueError("table_mode must be 'cycle' or 'fixed'")
        self.table_mode = table_mode
        self._enc = []  # type: List[Dict[str, str]]
        self._dec = []  # type: List[Dict[str, str]]
        for table_idx in range(3):
            enc = {chr(ord("a") + i): AVE_MARIA_TABLES[i][table_idx] for i in range(26)}
            self._enc.append(enc)
            self._dec.append({token: letter for letter, token in enc.items()})
        self._legacy_dec = {token: chr(ord("a") + i) for i, token in enumerate(AVE_MARIA_TOKENS)}

    def _table_index(self, letter_count: int) -> int:
        return 0 if self.table_mode == "fixed" else letter_count % 3

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        out = []  # type: List[str]
        letter_count = 0
        for ch in plaintext.lower():
            if "a" <= ch <= "z":
                t = self._table_index(letter_count)
                out.append("<{0}:{1}>".format(t, self._enc[t][ch]))
                letter_count += 1
            else:
                out.append(ch)
        return "".join(out)

    def decrypt(self, ciphertext: str) -> str:
        if not isinstance(ciphertext, str):
            raise TypeError("ciphertext must be str")
        out = []  # type: List[str]
        i = 0
        while i < len(ciphertext):
            if ciphertext[i] != "<":
                out.append(ciphertext[i]); i += 1; continue
            j = ciphertext.find(">", i + 1)
            if j == -1:
                out.append(ciphertext[i]); i += 1; continue
            body = ciphertext[i + 1:j]
            if ":" in body:
                table_str, phrase = body.split(":", 1)
                if table_str.isdigit() and 0 <= int(table_str) < len(self._dec):
                    out.append(self._dec[int(table_str)].get(phrase, "<{0}>".format(body)))
                else:
                    out.append("<{0}>".format(body))
            else:
                out.append(self._legacy_dec.get(body, "<{0}>".format(body)))
            i = j + 1
        return "".join(out)
