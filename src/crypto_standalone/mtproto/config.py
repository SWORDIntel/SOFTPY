from dataclasses import dataclass

@dataclass(frozen=True)
class MTProtoLimits:
    max_transport_frame_size: int = 16 * 1024 * 1024
    max_encrypted_payload_size: int = 16 * 1024 * 1024
    max_unencrypted_payload_size: int = 4 * 1024 * 1024
    max_decrypted_plaintext_size: int = 16 * 1024 * 1024
    max_container_size: int = 16 * 1024 * 1024
    max_container_messages: int = 1024
    max_buffered_bytes: int = 32 * 1024 * 1024
    max_pending_frame_size: int = 16 * 1024 * 1024
    max_replay_entries: int = 4096

    def __post_init__(self) -> None:
        if self.max_transport_frame_size <= 0:
            raise ValueError("max_transport_frame_size must be positive")
        if self.max_encrypted_payload_size <= 0:
            raise ValueError("max_encrypted_payload_size must be positive")
        if self.max_unencrypted_payload_size <= 0:
            raise ValueError("max_unencrypted_payload_size must be positive")
        if self.max_decrypted_plaintext_size <= 0:
            raise ValueError("max_decrypted_plaintext_size must be positive")
        if self.max_container_size <= 0:
            raise ValueError("max_container_size must be positive")
        if self.max_container_messages <= 0:
            raise ValueError("max_container_messages must be positive")
        if self.max_buffered_bytes <= 0:
            raise ValueError("max_buffered_bytes must be positive")
        if self.max_pending_frame_size <= 0:
            raise ValueError("max_pending_frame_size must be positive")
        if self.max_replay_entries <= 0:
            raise ValueError("max_replay_entries must be positive")
