import pytest
import os
import struct

from crypto_standalone.mtproto.envelope import (
    encode_encrypted_message,
    decode_encrypted_message,
    encode_unencrypted_message,
    decode_unencrypted_message
)
from crypto_standalone.mtproto.session import SessionValidationState
from crypto_standalone.mtproto.core import MessageDirection
from crypto_standalone.mtproto.errors import (
    InvalidFrameLengthError,
    MessageKeyMismatchError,
    SessionMismatchError,
    MTProtoFramingError
)

def test_unencrypted_message_roundtrip():
    body = b"\x01\x02\x03\x04"
    msg_id = 123456789

    enc = encode_unencrypted_message(msg_id=msg_id, body=body)
    assert len(enc) == 20 + len(body)

    dec = decode_unencrypted_message(enc)
    assert dec.msg_id == msg_id
    assert dec.body == body

def test_encrypted_message_roundtrip():
    auth_key = os.urandom(256)
    server_salt = 11111111111
    session_id = 22222222222

    val_state = SessionValidationState()
    msg_id = val_state.generate_msg_id(is_client=True)
    seq_no = 1
    body = b"hello world\x00"

    direction = MessageDirection.CLIENT_TO_SERVER

    enc = encode_encrypted_message(
        auth_key=auth_key,
        server_salt=server_salt,
        session_id=session_id,
        msg_id=msg_id,
        seq_no=seq_no,
        body=body,
        direction=direction
    )

    # msg_id parity for CLIENT is checked during decoding
    dec = decode_encrypted_message(
        data=enc,
        auth_key=auth_key,
        expected_session_id=session_id,
        direction=direction,
        validation_state=val_state
    )

    assert dec.server_salt == server_salt
    assert dec.session_id == session_id
    assert dec.msg_id == msg_id
    assert dec.seq_no == seq_no
    assert dec.body == body

def test_encrypted_message_invalid_msg_key():
    auth_key = os.urandom(256)
    val_state = SessionValidationState()
    enc = encode_encrypted_message(
        auth_key=auth_key,
        server_salt=1,
        session_id=2,
        msg_id=val_state.generate_msg_id(),
        seq_no=1,
        body=b"1234",
        direction=MessageDirection.CLIENT_TO_SERVER
    )

    # modify msg_key
    enc_modified = bytearray(enc)
    enc_modified[8] ^= 0x01

    with pytest.raises(MessageKeyMismatchError):
        decode_encrypted_message(
            data=bytes(enc_modified),
            auth_key=auth_key,
            expected_session_id=2,
            direction=MessageDirection.CLIENT_TO_SERVER,
            validation_state=val_state
        )

def test_encrypted_message_invalid_session():
    auth_key = os.urandom(256)
    val_state = SessionValidationState()
    enc = encode_encrypted_message(
        auth_key=auth_key,
        server_salt=1,
        session_id=2,
        msg_id=val_state.generate_msg_id(),
        seq_no=1,
        body=b"1234",
        direction=MessageDirection.CLIENT_TO_SERVER
    )

    with pytest.raises(SessionMismatchError):
        decode_encrypted_message(
            data=enc,
            auth_key=auth_key,
            expected_session_id=3,
            direction=MessageDirection.CLIENT_TO_SERVER,
            validation_state=val_state
        )

def test_encrypted_message_padding_bounds():
    auth_key = os.urandom(256)
    val_state = SessionValidationState()
    body = b"A" * 1024 # will force large padding or large frame
    enc = encode_encrypted_message(
        auth_key=auth_key,
        server_salt=1,
        session_id=2,
        msg_id=val_state.generate_msg_id(),
        seq_no=1,
        body=body,
        direction=MessageDirection.CLIENT_TO_SERVER
    )
    # verify it succeeds
    dec = decode_encrypted_message(
        data=enc,
        auth_key=auth_key,
        expected_session_id=2,
        direction=MessageDirection.CLIENT_TO_SERVER,
        validation_state=val_state
    )
    assert dec.body == body
