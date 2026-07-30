import pytest

from crypto_standalone.mtproto.containers import (
    ContainerMessage,
    encode_msg_container,
    decode_msg_container
)
from crypto_standalone.mtproto.errors import MTProtoFramingError

def test_msg_container_roundtrip():
    msg1 = ContainerMessage(msg_id=100, seq_no=1, body=b"A"*4)
    msg2 = ContainerMessage(msg_id=101, seq_no=2, body=b"B"*8)

    enc = encode_msg_container([msg1, msg2])
    dec = decode_msg_container(enc)

    assert len(dec) == 2
    assert dec[0].msg_id == 100
    assert dec[1].msg_id == 101
    assert dec[0].body == b"A"*4

def test_msg_container_limits():
    messages = [ContainerMessage(msg_id=i, seq_no=i, body=b"A"*4) for i in range(1025)]
    with pytest.raises(MTProtoFramingError):
        encode_msg_container(messages)

def test_msg_container_nesting_check():
    msg1 = ContainerMessage(msg_id=100, seq_no=1, body=b"A"*4)
    enc_inner = encode_msg_container([msg1])

    msg_outer = ContainerMessage(msg_id=101, seq_no=2, body=enc_inner)
    enc_outer = encode_msg_container([msg_outer])

    with pytest.raises(MTProtoFramingError, match="Nested simple containers are rejected"):
        decode_msg_container(enc_outer)

def test_msg_container_msg_id_strict_lower():
    msg1 = ContainerMessage(msg_id=100, seq_no=1, body=b"A"*4)
    enc = encode_msg_container([msg1])

    # If container_msg_id is provided, nested must be strictly lower
    with pytest.raises(MTProtoFramingError):
        decode_msg_container(enc, container_msg_id=100) # strictly lower means <

    # Should pass if container is higher
    dec = decode_msg_container(enc, container_msg_id=101)
    assert len(dec) == 1
