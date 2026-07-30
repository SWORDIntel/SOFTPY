"""MTProto exception hierarchy."""

class MTProtoFramingError(Exception):
    """Base exception for all MTProto framing and parsing errors."""


class IncompleteFrameError(MTProtoFramingError):
    """Raised when more data is needed to parse a complete frame."""


class InvalidFrameLengthError(MTProtoFramingError):
    """Raised when a frame length is outside permitted limits or structurally invalid."""


class FrameTooLargeError(MTProtoFramingError):
    """Raised when a frame exceeds the configured hard limits."""


class TransportSequenceError(MTProtoFramingError):
    """Raised when a transport sequence number (e.g., full transport) is incorrect."""


class TransportChecksumError(MTProtoFramingError):
    """Raised when a transport checksum (e.g., CRC32) fails validation."""


class MessageKeyMismatchError(MTProtoFramingError):
    """Raised when an encrypted message's msg_key does not match the decrypted and verified payload."""


class SessionMismatchError(MTProtoFramingError):
    """Raised when a decrypted message's session_id does not match the expected session."""


class ReplayDetectedError(MTProtoFramingError):
    """Raised when a message is detected as a replay or duplicate."""
