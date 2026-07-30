# Containers for MTProto messages
pass
import struct
from dataclasses import dataclass
from typing import List

from .errors import InvalidFrameLengthError, MTProtoFramingError
from .core import ResourceLimits, DEFAULT_LIMITS

@dataclass
class ContainerMessage:
    msg_id: int
    seq_no: int
    body: bytes

def encode_msg_container(
    messages: List[ContainerMessage],
    limits: ResourceLimits = DEFAULT_LIMITS
) -> bytes:
    """
    Encodes a msg_container containing a list of messages.
    msg_container constructor ID is 0x73f1f8dc.
    """
    if len(messages) > limits.max_contained_message_count:
        raise MTProtoFramingError(f"Too many messages in container: {len(messages)}")

    out = bytearray(struct.pack("<II", 0x73f1f8dc, len(messages)))

    for msg in messages:
        if len(msg.body) % 4 != 0:
            raise InvalidFrameLengthError("Nested message body length must be divisible by 4")
        out.extend(struct.pack("<QQI", msg.msg_id, msg.seq_no, len(msg.body)))
        out.extend(msg.body)

    if len(out) > limits.max_container_size:
        raise MTProtoFramingError("Container aggregate size exceeds limit")

    return bytes(out)

def decode_msg_container(
    data: bytes,
    container_msg_id: int | None = None,
    limits: ResourceLimits = DEFAULT_LIMITS
) -> List[ContainerMessage]:
    """
    Decodes a msg_container constructor.
    Does not parse recursively.
    """
    if len(data) < 8:
        raise InvalidFrameLengthError("Container data too small")

    constructor, count = struct.unpack("<II", data[:8])
    if constructor != 0x73f1f8dc:
        raise MTProtoFramingError(f"Not a msg_container constructor: {hex(constructor)}")

    if count > limits.max_contained_message_count:
        raise MTProtoFramingError(f"Container declares too many messages: {count}")

    messages = []
    offset = 8

    for _ in range(count):
        if len(data) - offset < 20:
            raise InvalidFrameLengthError("Truncated nested message header")

        msg_id, seq_no, length = struct.unpack("<QQI", data[offset:offset+20])
        offset += 20

        if length < 0 or length % 4 != 0:
            raise InvalidFrameLengthError(f"Invalid nested message length: {length}")

        if len(data) - offset < length:
            raise InvalidFrameLengthError("Truncated nested message body")

        if container_msg_id is not None and msg_id >= container_msg_id:
            raise MTProtoFramingError(f"Nested msg_id {msg_id} not strictly lower than container msg_id {container_msg_id}")

        # Optional: verify not a nested simple container.
        # We can look at the first 4 bytes if length >= 4
        if length >= 4:
            inner_constructor = struct.unpack("<I", data[offset:offset+4])[0]
            if inner_constructor == 0x73f1f8dc:
                raise MTProtoFramingError("Nested simple containers are rejected")

        body = data[offset:offset+length]
        messages.append(ContainerMessage(msg_id=msg_id, seq_no=seq_no, body=body))
        offset += length

    # Check for trailing bytes
    if offset != len(data):
        raise InvalidFrameLengthError("Trailing bytes after declared final nested message")

    return messages
