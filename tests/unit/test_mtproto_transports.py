import pytest
import struct
import binascii

from crypto_standalone.mtproto.transports import (
    AbridgedTransportCodec,
    IntermediateTransportCodec,
    PaddedIntermediateTransportCodec,
    FullTransportCodec
)
from crypto_standalone.mtproto.core import PayloadFrame, QuickAck, TransportError
from crypto_standalone.mtproto.errors import FrameTooLargeError, InvalidFrameLengthError, TransportChecksumError, TransportSequenceError


def test_abridged_transport():
    codec = AbridgedTransportCodec()
    assert codec.connection_header() == b"\xef"
    assert codec.connection_header() == b""

    payload = b"\x00" * 4
    enc = codec.encode(payload)
    assert enc == b"\x01\x00\x00\x00\x00"

    events = codec.feed_data(enc)
    assert len(events) == 1
    assert isinstance(events[0], PayloadFrame)
    assert events[0].payload == payload

    # Extended length
    payload2 = b"\x00" * 508
    enc2 = codec.encode(payload2)
    assert enc2[0] == 0x7F
    assert enc2[1:4] == struct.pack("<I", 127)[:3]
    events2 = codec.feed_data(enc2)
    assert len(events2) == 1
    assert events2[0].payload == payload2

    # Quick ack encoding
    enc3 = codec.encode(payload, request_quick_ack=True)
    assert enc3[0] == 0x81

    # Quick ack parsing
    token = 0x80000001
    token_bytes = struct.pack(">I", token)
    events3 = codec.feed_data(token_bytes)
    assert len(events3) == 1
    assert isinstance(events3[0], QuickAck)
    assert events3[0].token == token

    # Fragmented stream
    for i in range(len(enc)):
        evt = codec.feed_data(bytes([enc[i]]))
        if i < len(enc) - 1:
            assert len(evt) == 0
        else:
            assert len(evt) == 1
            assert evt[0].payload == payload


def test_intermediate_transport():
    codec = IntermediateTransportCodec()
    assert codec.connection_header() == b"\xee\xee\xee\xee"

    payload = b"\x00" * 4
    enc = codec.encode(payload)
    assert enc == b"\x04\x00\x00\x00" + payload

    events = codec.feed_data(enc)
    assert len(events) == 1
    assert events[0].payload == payload

    enc_quick_ack = codec.encode(payload, request_quick_ack=True)
    assert enc_quick_ack[3] == 0x80

    # Fragmented
    for i in range(len(enc)):
        evt = codec.feed_data(bytes([enc[i]]))
        if i < len(enc) - 1:
            assert len(evt) == 0
        else:
            assert len(evt) == 1
            assert evt[0].payload == payload


def test_padded_intermediate_transport():
    codec = PaddedIntermediateTransportCodec()
    assert codec.connection_header() == b"\xdd\xdd\xdd\xdd"

    payload = b"\x00" * 4
    enc = codec.encode(payload)
    events = codec.feed_data(enc)
    assert len(events) == 1
    assert events[0].payload.startswith(payload)

    # Error
    err_enc = struct.pack("<i", -404)
    events2 = codec.feed_data(err_enc)
    assert len(events2) == 1
    assert isinstance(events2[0], TransportError)
    assert events2[0].code == 404


def test_full_transport():
    codec = FullTransportCodec()
    assert codec.connection_header() == b""

    payload = b"\x00" * 4
    enc = codec.encode(payload)
    # length: 4 + 4 + 4 + 4 = 16
    assert len(enc) == 16
    assert struct.unpack("<I", enc[:4])[0] == 16
    assert struct.unpack("<I", enc[4:8])[0] == 0

    events = codec.feed_data(enc)
    assert len(events) == 1
    assert events[0].payload == payload

    # Sequence error
    enc2 = codec.encode(payload)
    codec.in_seq_no = 0 # force error
    with pytest.raises(TransportSequenceError):
        codec.feed_data(enc2)

    codec.reset()
    # CRC error
    enc3 = bytearray(codec.encode(payload))
    enc3[-1] ^= 0x01
    with pytest.raises(TransportChecksumError):
        codec.feed_data(enc3)
