# MTProto 2.0 Framing Architecture

The MTProto 2.0 implementation in `crypto_standalone` provides a secure, zero-dependency, pure-Python implementation of the framing and cryptographic envelope layers of the Telegram MTProto protocol.

## Supported Transports

All four standard MTProto TCP transports are supported:

- **Abridged**: The lightest protocol. Envelope includes 1-byte marker `0xef` and short/extended lengths.
- **Intermediate**: 4-byte lengths. Envelope includes 4-byte marker `0xeeeeeeee`.
- **Padded-Intermediate**: Padded version to bypass ISP blocks. Envelope includes marker `0xdddddddd` and random padding of 0-15 bytes.
- **Full**: Includes sequence numbers and CRC32 checksums.

Quick ACKs are supported across all transports. The codecs implement incremental, strict parsers suitable for real TCP streams without allocating unbounded buffers.

## Cryptographic Messages

The module implements the MTProto 2.0 message envelope:

- **MTProto 2.0 Key Derivation**: Derives the 256-bit AES key and IV from the authorization key and message key.
- **AES-IGE**: Uses the existing pure-Python AES-256 implementation with Infinite Garble Extension (IGE).
- **Validation**: Enforces mandatory, strictly ordered validation gates (bounds, auth_key resolution, AES decryption, msg_key verification, internal field validation, and msg_id checks) to prevent padding or lengths from serving as side-channel oracles.

### Security Limitations

Because this library is written entirely in Python, it cannot guarantee complete side-channel immunity at the interpreter level:
- There is no hardware-level constant-time execution guarantee (though constant-time comparisons like `compare_digest` are used where applicable).
- Memory cannot be securely zeroized out of Python's garbage collector.
- Immutable strings may leave remnants of plaintext, keys, and message contents in memory.

## Usage Example

```python
from crypto_standalone.mtproto import AbridgedTransportCodec, PayloadFrame

codec = AbridgedTransportCodec()
header = codec.connection_header()
# send header to socket

encrypted_payload = b"..."
wire_packet = codec.encode(encrypted_payload)
# send wire_packet to socket

events = codec.feed_data(received_chunk)
for event in events:
    if isinstance(event, PayloadFrame):
        print("Received payload of length", len(event.payload))
```
