from dataclasses import dataclass

@dataclass
class FullTransportState:
    outgoing_sequence: int = 0
    expected_incoming_sequence: int | None = None
