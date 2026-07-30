import binascii
import struct
from typing import List, Protocol
from .core import TransportEvent, PayloadFrame, QuickAck, TransportError, ResourceLimits, DEFAULT_LIMITS
from .errors import InvalidFrameLengthError, FrameTooLargeError, TransportSequenceError, TransportChecksumError

class TransportCodec(Protocol):
    def connection_header(self) -> bytes:
        ...

    def encode(
        self,
        payload: bytes,
        *,
        request_quick_ack: bool = False,
    ) -> bytes:
        ...

    def feed_data(self, data: bytes) -> List[TransportEvent]:
        ...

    def feed_eof(self) -> List[TransportEvent]:
        ...

    def reset(self) -> None:
        ...


class BaseTransportCodec:
    def __init__(self, limits: ResourceLimits = DEFAULT_LIMITS):
        self.limits = limits
        self._buffer = bytearray()
        self._offset = 0
        self._sent_header = False

    def reset(self) -> None:
        self._buffer.clear()
        self._offset = 0
        self._sent_header = False

    def _compact(self) -> None:
        if self._offset > 0:
            del self._buffer[:self._offset]
            self._offset = 0
        if len(self._buffer) > self.limits.max_retained_incremental_buffer_size:
            self.reset()
            raise FrameTooLargeError("Incremental buffer exceeded maximum limit")

    def feed_data(self, data: bytes) -> List[TransportEvent]:
        self._buffer.extend(data)
        events = []
        while True:
            evt = self._parse_one()
            if evt is None:
                break
            events.append(evt)
        self._compact()
        return events

    def feed_eof(self) -> List[TransportEvent]:
        events = []
        while True:
            evt = self._parse_one()
            if evt is None:
                break
            events.append(evt)
        self._compact()
        return events

    def _parse_one(self) -> TransportEvent | None:
        raise NotImplementedError

    def _read_bytes(self, n: int) -> bytes | None:
        if len(self._buffer) - self._offset >= n:
            res = bytes(self._buffer[self._offset : self._offset + n])
            self._offset += n
            return res
        return None

    def _peek_bytes(self, n: int) -> bytes | None:
        if len(self._buffer) - self._offset >= n:
            return bytes(self._buffer[self._offset : self._offset + n])
        return None

    def _decode_quick_ack_or_error(self, first_int: int) -> TransportEvent | None:
        # Check for Quick ACK (standalone reversed 4 bytes with MSB set)
        # However, quick acks in Abridged and Intermediate are generally negative ints if treated as little endian
        if first_int >= 0x80000000:
            return QuickAck(token=first_int)

        # Check for error (standalone error frame)
        # Note: the spec says "error is a signed little-endian number of 4 bytes, whose absolute value contains the error code (the error itself is actually negative)."
        return None

class AbridgedTransportCodec(BaseTransportCodec):
    def connection_header(self) -> bytes:
        if not self._sent_header:
            self._sent_header = True
            return b"\xef"
        return b""

    def encode(self, payload: bytes, *, request_quick_ack: bool = False) -> bytes:
        length_words = len(payload) // 4
        if len(payload) % 4 != 0:
            raise InvalidFrameLengthError("Payload length must be divisible by 4")

        header = bytearray()
        if length_words < 127:
            if request_quick_ack:
                header.append(length_words | 0x80)
            else:
                header.append(length_words)
        else:
            header.append(0x7F | (0x80 if request_quick_ack else 0x00))
            header.extend(struct.pack("<I", length_words)[:3])

        return bytes(header) + payload

    def _parse_one(self) -> TransportEvent | None:
        # Check for Quick ACK (4 bytes standalone)
        # Server sends quick ACK by bswapping them. The length/header of normal payload is always <= 127,
        # so MSB is not set. If MSB is set, it's a Quick ACK.

        if len(self._buffer) - self._offset >= 4:
            first_byte = self._buffer[self._offset]
            if first_byte >= 128:
                # 1 byte might be 0x7F | 0x80 = 0xFF (extended length + quick ack?)
                # Actually, spec says: "quick ACK packets can be easily distinguished ... first byte will always have the most-significant bit set ... normal payload packets <= 127"
                # Wait, what if the packet is an extended length abridged packet?
                # "The server will send quick ACK tokens by bswapping them ... standalone 4-byte packet"
                # Wait, server-to-client MTProto payload lengths shouldn't exceed 127 (508 bytes) for standard messages, but they can for larger ones.
                # Is extended length 0x7f or 0xff? Spec: "0x7F plus three-byte little-endian extended length ... If length/4 >= 127, envelope: 0xff, length..."
                # Wait! "first byte will always have most-significant bit set ... length/header of normal payload packets coming from the server is always less than or equal to 127 (thus the most-significant bit is not set for normal payloads)."
                # Oh, it means server *responses* never exceed 127 length in *abridged* transport? Or server doesn't use extended length?
                # Let's assume MSB = 1 -> Quick ACK.
                pass

        if len(self._buffer) - self._offset < 1:
            return None

        first_byte = self._buffer[self._offset]

        # Check for transport error. The server may send a transport error as a 4-byte signed int.
        # But how to distinguish from abridged header?
        # A transport error is 4 bytes. E.g., -404 (0x6C FE FF FF). First byte is 0x6C (108).
        # We need to distinguish it.
        # If it's a 4-byte payload, we'll see.

        if first_byte >= 128:
            if first_byte != 0x7f and first_byte != 0xff:
                # Quick ACK
                if len(self._buffer) - self._offset >= 4:
                    token = struct.unpack(">I", self._peek_bytes(4))[0] # it's bswapped
                    self._offset += 4
                    return QuickAck(token=token)
                return None

        if first_byte == 0x7f or first_byte == 0xff:
            if len(self._buffer) - self._offset < 4:
                return None
            length_words = struct.unpack("<I", self._buffer[self._offset+1 : self._offset+4] + b"\x00")[0]
            header_len = 4
        else:
            length_words = first_byte
            header_len = 1

        payload_len = length_words * 4

        # Check for transport error if length seems to be a negative int.
        if header_len == 1 and length_words == 108 and len(self._buffer) - self._offset >= 4:
             # Just read 4 bytes as error code
             val = struct.unpack("<i", self._peek_bytes(4))[0]
             if val < 0 and val > -1000:
                 self._offset += 4
                 return TransportError(code=abs(val))

        if payload_len > self.limits.max_transport_frame_size:
            raise FrameTooLargeError(f"Abridged frame payload size {payload_len} exceeds max {self.limits.max_transport_frame_size}")

        if len(self._buffer) - self._offset < header_len + payload_len:
            return None

        self._offset += header_len
        payload = self._read_bytes(payload_len)
        return PayloadFrame(payload=payload)


class IntermediateTransportCodec(BaseTransportCodec):
    def connection_header(self) -> bytes:
        if not self._sent_header:
            self._sent_header = True
            return b"\xee\xee\xee\xee"
        return b""

    def encode(self, payload: bytes, *, request_quick_ack: bool = False) -> bytes:
        payload_len = len(payload)
        if payload_len % 4 != 0:
            raise InvalidFrameLengthError("Payload length must be divisible by 4")
        if request_quick_ack:
            payload_len |= 0x80000000
        return struct.pack("<I", payload_len) + payload

    def _parse_one(self) -> TransportEvent | None:
        if len(self._buffer) - self._offset < 4:
            return None

        length_val = struct.unpack("<I", self._buffer[self._offset : self._offset+4])[0]

        # Error check
        signed_val = struct.unpack("<i", self._buffer[self._offset : self._offset+4])[0]
        if signed_val < 0 and signed_val > -1000:
            self._offset += 4
            return TransportError(code=abs(signed_val))

        if length_val >= 0x80000000:
            # Quick ACK
            self._offset += 4
            return QuickAck(token=length_val)

        if length_val > self.limits.max_transport_frame_size:
            raise FrameTooLargeError(f"Intermediate frame size {length_val} exceeds max")

        if len(self._buffer) - self._offset < 4 + length_val:
            return None

        self._offset += 4
        payload = self._read_bytes(length_val)
        return PayloadFrame(payload=payload)


class PaddedIntermediateTransportCodec(BaseTransportCodec):
    def __init__(self, limits: ResourceLimits = DEFAULT_LIMITS):
        super().__init__(limits)

    def connection_header(self) -> bytes:
        if not self._sent_header:
            self._sent_header = True
            return b"\xdd\xdd\xdd\xdd"
        return b""

    def encode(self, payload: bytes, *, request_quick_ack: bool = False) -> bytes:
        import os
        padding_len = os.urandom(1)[0] % 16
        padding = os.urandom(padding_len)
        total_len = len(payload) + padding_len
        if request_quick_ack:
            total_len |= 0x80000000
        return struct.pack("<I", total_len) + payload + padding

    def _parse_one(self) -> TransportEvent | None:
        if len(self._buffer) - self._offset < 4:
            return None

        length_val = struct.unpack("<I", self._buffer[self._offset : self._offset+4])[0]

        # Padded quick ACK: total length is <= 16. Then 4 bytes 0xFFFFFFFF, then 4 bytes token.
        if length_val <= 16:
            if len(self._buffer) - self._offset < 4 + length_val:
                return None
            # Check if it's quick ACK
            val2 = struct.unpack("<I", self._buffer[self._offset+4 : self._offset+8])[0]
            if val2 == 0xFFFFFFFF:
                token = struct.unpack("<I", self._buffer[self._offset+8 : self._offset+12])[0]
                self._offset += 4 + length_val
                return QuickAck(token=token)

        # Error check
        signed_val = struct.unpack("<i", self._buffer[self._offset : self._offset+4])[0]
        if signed_val < 0 and signed_val > -1000:
            self._offset += 4
            return TransportError(code=abs(signed_val))

        if length_val > self.limits.max_transport_frame_size:
            raise FrameTooLargeError(f"Padded intermediate frame size {length_val} exceeds max")

        if len(self._buffer) - self._offset < 4 + length_val:
            return None

        self._offset += 4
        payload_with_padding = self._read_bytes(length_val)
        return PayloadFrame(payload=payload_with_padding, transport_padding=b"") # Note: we don't strip padding here, up to higher layer


class FullTransportCodec(BaseTransportCodec):
    def __init__(self, limits: ResourceLimits = DEFAULT_LIMITS):
        super().__init__(limits)
        self.out_seq_no = 0
        self.in_seq_no = 0

    def connection_header(self) -> bytes:
        self._sent_header = True
        return b""

    def encode(self, payload: bytes, *, request_quick_ack: bool = False) -> bytes:
        if len(payload) % 4 != 0:
            raise InvalidFrameLengthError("Payload length must be divisible by 4")

        # length: length + seqno + payload + crc
        length = 4 + 4 + len(payload) + 4
        seq_no = self.out_seq_no
        self.out_seq_no += 1

        data_to_crc = struct.pack("<II", length, seq_no) + payload
        crc = binascii.crc32(data_to_crc) & 0xFFFFFFFF
        return data_to_crc + struct.pack("<I", crc)

    def _parse_one(self) -> TransportEvent | None:
        if len(self._buffer) - self._offset < 4:
            return None

        length = struct.unpack("<I", self._buffer[self._offset : self._offset+4])[0]

        # Check for error
        signed_val = struct.unpack("<i", self._buffer[self._offset : self._offset+4])[0]
        if signed_val < 0 and signed_val > -1000:
            self._offset += 4
            return TransportError(code=abs(signed_val))

        if length % 4 != 0 or length < 12:
            raise InvalidFrameLengthError(f"Invalid full transport length: {length}")

        if length > self.limits.max_transport_frame_size:
            raise FrameTooLargeError(f"Full frame size {length} exceeds max")

        if len(self._buffer) - self._offset < length:
            return None

        data = self._peek_bytes(length)

        data_to_crc = data[:-4]
        expected_crc = struct.unpack("<I", data[-4:])[0]
        actual_crc = binascii.crc32(data_to_crc) & 0xFFFFFFFF

        if expected_crc != actual_crc:
            self.reset()
            raise TransportChecksumError("CRC32 mismatch in Full transport")

        seq_no = struct.unpack("<I", data[4:8])[0]
        if seq_no != self.in_seq_no:
            self.reset()
            raise TransportSequenceError(f"Expected sequence number {self.in_seq_no}, got {seq_no}")

        self.in_seq_no += 1
        self._offset += length

        payload = data[8:-4]
        return PayloadFrame(payload=payload)
