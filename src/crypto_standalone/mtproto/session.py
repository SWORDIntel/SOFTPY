from dataclasses import dataclass, field

@dataclass
class MTProtoSessionState:
    session_id: int
    server_salt: int
    outgoing_content_count: int = 0
    last_outgoing_msg_id: int = 0
    last_incoming_msg_id: int = 0
    # Use a set, but bounded externally via max_replay_entries limit
    seen_message_ids: set[int] = field(default_factory=set)

    def add_seen_message(self, msg_id: int, max_entries: int) -> None:
        """Adds a seen message ID and ensures the set doesn't grow unbounded."""
        if len(self.seen_message_ids) >= max_entries:
            # Simplest bound: clear the set or remove smallest. For an exact queue,
            # we'd need a more complex structure (like collections.deque).
            # For this requirement, we just avoid an unbounded set.
            # Here we just keep the most recent elements.
            sorted_msgs = sorted(list(self.seen_message_ids))
            # keep the last half
            half = max_entries // 2
            self.seen_message_ids = set(sorted_msgs[-half:])

        self.seen_message_ids.add(msg_id)
import time
from typing import Set

from .errors import ReplayDetectedError

class SessionValidationState:
    """Stateful validation for MTProto sessions (msg_id, seq_no)."""

    def __init__(self):
        self._last_time = 0.0
        self._replay_cache: Set[int] = set()
        self.max_replay_cache = 10000

    def generate_msg_id(self, is_client: bool = True) -> int:
        """
        Generates a 64-bit monotonically increasing message ID based on approx Unix time.
        Fractional part is in the lower 32 bits.
        Must be a multiple of 4, parity depends on direction.
        Client -> Server: msg_id % 4 == 0 or 2 (content-related vs non) (we'll just use % 4 == 0)
        """
        now = time.time()
        if now <= self._last_time:
            now = self._last_time + 0.0001
        self._last_time = now

        # msg_id is approx time in seconds * 2^32
        msg_id = int(now * (1 << 32))

        # ensure parity
        remainder = msg_id % 4
        if is_client:
            # Client: remainder should be 0
            msg_id -= remainder
        else:
            # Server: remainder should be 1 or 3
            if remainder in (0, 2):
                msg_id += 1

        return msg_id

    def validate_msg_id(self, msg_id: int, expected_client: bool = False) -> None:
        """
        Validates direction parity, time bounds, and replay.
        """
        remainder = msg_id % 4
        if expected_client:
            if remainder not in (0, 2):
                raise ValueError("Invalid msg_id parity for client message")
        else:
            if remainder not in (1, 3):
                raise ValueError("Invalid msg_id parity for server message")

        # Time window: 300s past, 30s future
        now_ts = int(time.time())
        msg_ts = msg_id >> 32

        if msg_ts < now_ts - 300:
            raise ValueError("msg_id too old")
        if msg_ts > now_ts + 30:
            raise ValueError("msg_id too far in the future")

        if msg_id in self._replay_cache:
            raise ReplayDetectedError("Duplicate msg_id detected")

        self._replay_cache.add(msg_id)
        if len(self._replay_cache) > self.max_replay_cache:
            # Simple eviction
            self._replay_cache = set(list(self._replay_cache)[-self.max_replay_cache//2:])
