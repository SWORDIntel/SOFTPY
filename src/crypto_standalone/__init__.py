"""Pure-Python Military-Grade Cryptography (zero dependencies)."""

__version__ = "2.0.0"

from .symmetric import AES256, AESGCM, ChaCha20Poly1305, chacha20_encrypt
from .hashing import *
from .asymmetric import *
from .asymmetric import _encode_signature, _decode_signature
from .kdf import hkdf, hkdf_extract, hkdf_expand, hkdf_sha256, hkdf_sha512
from .kdf import pbkdf2_hmac, pbkdf2_sha256, pbkdf2_sha512
from .aws import sign_aws_request, build_signed_request, send_signed_request
from .utils import random_bytes, random_below, random_bits, CSPRNG
from .utils import secure_zero, SecureBytes, constant_time_compare
from .utils import DigitalURandom, self_test, HMAC_DRBG_SHA256

RECOMMENDED_ALGORITHMS = {
    "aead": "ChaCha20Poly1305 or AESGCM",
    "hash": "SHA-256 or SHA-384",
    "kdf": "HKDF-SHA256 or HKDF-SHA512",
    "signature": "Ed25519 or P-384 ECDSA",
    "key_agreement": "X25519 or P-384 ECDH",
    "password_kdf": "PBKDF2-SHA256 (600k+ iterations)",
}

DEPRECATED = {
    "AES-CBC": "Use AESGCM or ChaCha20Poly1305",
    "RSA PKCS#1 v1.5": "Use RSA-OAEP for encryption, RSA-PSS for signatures",
    "SHA-1": "Use SHA-256 or better",
}
