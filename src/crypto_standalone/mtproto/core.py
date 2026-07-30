"""Core data types and limits for MTProto framing."""

import enum
from dataclasses import dataclass
from typing import Optional


class MessageDirection(enum.Enum):
    """Direction of the MTProto message."""
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2


@dataclass(frozen=True)
class ResourceLimits:
    """Configurable limits for parsing and container unpacking to prevent resource exhaustion."""
    max_transport_frame_size: int = 1048576 * 2  # 2 MiB
    max_encrypted_payload_size: int = 1048576 * 2
    max_unencrypted_payload_size: int = 65536
    max_decrypted_plaintext_size: int = 1048576 * 2
    max_container_size: int = 1048576 * 2
    max_contained_message_count: int = 1024
    max_retained_incremental_buffer_size: int = 1048576 * 4  # 4 MiB


DEFAULT_LIMITS = ResourceLimits()


class TransportEvent:
    """Base class for events emitted by a transport codec."""
    pass


@dataclass(frozen=True)
class PayloadFrame(TransportEvent):
    """A standard MTProto payload frame."""
    payload: bytes
    transport_padding: Optional[bytes] = None


@dataclass(frozen=True)
class QuickAck(TransportEvent):
    """A quick acknowledgment frame."""
    token: int


@dataclass(frozen=True)
class TransportError(TransportEvent):
    """A transport-level error frame."""
    code: int
