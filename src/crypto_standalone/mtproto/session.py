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
