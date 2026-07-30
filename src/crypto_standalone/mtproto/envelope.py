import struct
import os
from dataclasses import dataclass

from ..symmetric.aes import AES256
from ..hashing.sha2 import sha256, compare_digest
from .core import MessageDirection
from .session import SessionValidationState
from .errors import (
    InvalidFrameLengthError,
    MessageKeyMismatchError,
    SessionMismatchError,
    MTProtoFramingError,
    ReplayDetectedError
)

@dataclass
class UnencryptedMessage:
    msg_id: int
    body: bytes

@dataclass
class EncryptedMessage:
    server_salt: int
    session_id: int
    msg_id: int
    seq_no: int
    body: bytes

def encode_unencrypted_message(
    *,
    msg_id: int,
    body: bytes,
) -> bytes:
    if len(body) % 4 != 0:
        raise InvalidFrameLengthError("Body length must be divisible by 4")

    return struct.pack("<QQI", 0, msg_id, len(body)) + body

def decode_unencrypted_message(
    data: bytes,
) -> UnencryptedMessage:
    if len(data) < 20:
        raise MTProtoFramingError("Unencrypted message too small")

    auth_key_id, msg_id, length = struct.unpack("<QQI", data[:20])
    if auth_key_id != 0:
        raise MTProtoFramingError("auth_key_id must be 0 for unencrypted messages")

    if length < 0 or length % 4 != 0:
        raise InvalidFrameLengthError("Invalid body length")

    if len(data) - 20 < length:
        raise InvalidFrameLengthError("Declared length exceeds available data")

    body = data[20:20+length]
    return UnencryptedMessage(msg_id=msg_id, body=body)

def _derive_aes_key_iv(
    auth_key: bytes, msg_key: bytes, direction: MessageDirection
) -> tuple[bytes, bytes]:
    """Derives AES key and IV for MTProto 2.0."""
    x = 0 if direction == MessageDirection.CLIENT_TO_SERVER else 8

    sha256_a = sha256(msg_key + auth_key[x:x+36])
    sha256_b = sha256(auth_key[x+40:x+76] + msg_key)

    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]

    return aes_key, aes_iv

def encode_encrypted_message(
    *,
    auth_key: bytes,
    server_salt: int,
    session_id: int,
    msg_id: int,
    seq_no: int,
    body: bytes,
    direction: MessageDirection,
) -> bytes:
    if len(auth_key) != 256:
        raise ValueError("auth_key must be exactly 256 bytes")
    if len(body) % 4 != 0:
        raise ValueError("body length must be divisible by 4")

    # Internal header
    internal_header = struct.pack("<QQQII", server_salt, session_id, msg_id, seq_no, len(body))

    payload = internal_header + body

    # Padding 12..1024 bytes, resulting in % 16 == 0
    padding_len = (16 - (len(payload) % 16)) % 16
    if padding_len < 12:
        padding_len += 16
    padding = os.urandom(padding_len)

    payload_with_padding = payload + padding

    # msg_key
    # auth_key_fragment is auth_key[88:88+32]
    auth_key_fragment = auth_key[88:120]
    msg_key_hash = sha256(auth_key_fragment + payload_with_padding)
    msg_key = msg_key_hash[8:24]

    aes_key, aes_iv = _derive_aes_key_iv(auth_key, msg_key, direction)
    aes = AES256(aes_key)

    encrypted_data = aes.encrypt_ige(payload_with_padding, aes_iv)

    # Using lower 64 bits of SHA1 of auth_key as auth_key_id.
    # We will simulate sha1 since our sha1 might not be readily exposed via simple function.
    # Actually, we can use the library's sha1 from hashing.
    from ..hashing.sha2 import sha1
    auth_key_id = struct.unpack("<Q", sha1(auth_key)[-8:])[0]

    return struct.pack("<Q", auth_key_id) + msg_key + encrypted_data


def decode_encrypted_message(
    *,
    data: bytes,
    auth_key: bytes,
    expected_session_id: int,
    direction: MessageDirection,
    validation_state: SessionValidationState,
) -> EncryptedMessage:
    if len(auth_key) != 256:
        raise ValueError("auth_key must be exactly 256 bytes")

    if len(data) < 24:
        raise InvalidFrameLengthError("Data too small for external header")

    _auth_key_id = struct.unpack("<Q", data[:8])[0]
    msg_key = data[8:24]
    encrypted_data = data[24:]

    if len(encrypted_data) == 0 or len(encrypted_data) % 16 != 0:
        raise InvalidFrameLengthError("encrypted_data length must be >0 and divisible by 16")

    aes_key, aes_iv = _derive_aes_key_iv(auth_key, msg_key, direction)
    aes = AES256(aes_key)

    # Decrypt into bounded buffer
    decrypted = aes.decrypt_ige(encrypted_data, aes_iv)

    # Recompute msg_key
    auth_key_fragment = auth_key[88:120]
    expected_msg_key_hash = sha256(auth_key_fragment + decrypted)
    expected_msg_key = expected_msg_key_hash[8:24]

    if not compare_digest(msg_key, expected_msg_key):
        raise MessageKeyMismatchError("msg_key mismatch")

    if len(decrypted) < 32:
        raise InvalidFrameLengthError("Minimum plaintext size not met")

    server_salt, session_id, msg_id, seq_no, msg_len = struct.unpack("<QQQII", decrypted[:32])

    if session_id != expected_session_id:
        raise SessionMismatchError(f"Expected session {expected_session_id}, got {session_id}")

    if msg_len < 0 or msg_len % 4 != 0:
        raise InvalidFrameLengthError("Invalid message body length")

    if len(decrypted) - 32 < msg_len:
        raise InvalidFrameLengthError("Message length exceeds decrypted buffer")

    padding_len = len(decrypted) - 32 - msg_len
    if padding_len < 12 or padding_len > 1024:
        raise InvalidFrameLengthError(f"Invalid padding length: {padding_len}")

    # Validate msg_id via validation_state
    expected_client = (direction == MessageDirection.CLIENT_TO_SERVER)
    try:
        validation_state.validate_msg_id(msg_id, expected_client=expected_client)
    except Exception as e:
        if "Duplicate" in str(e):
            raise ReplayDetectedError(str(e))
        raise MTProtoFramingError(f"msg_id validation failed: {e}")

    body = decrypted[32:32+msg_len]
    return EncryptedMessage(
        server_salt=server_salt,
        session_id=session_id,
        msg_id=msg_id,
        seq_no=seq_no,
        body=body
    )
