"""Best-effort memory zeroing utilities. Python GC limitations documented."""

from __future__ import annotations

from typing import Any


def secure_zero(data: bytearray) -> None:
    """
    Overwrite bytearray with zeros. Best-effort only.
    
    Limitations:
    - Python interns short strings/bytes
    - CPython caches small integers (-5 to 256)
    - Immutable bytes objects cannot be zeroed
    - GC may leave copies in memory
    - No guarantee against swap/hibernation
    
    Use this for bytearrays holding sensitive data like keys.
    """
    if not isinstance(data, bytearray):
        raise TypeError("can only zero bytearray (mutable)")
    for i in range(len(data)):
        data[i] = 0


class SecureBytes:
    """
    Context manager for sensitive byte data. Auto-zeros on exit.
    
    Example:
        with SecureBytes(32) as key:
            key[:] = os.urandom(32)
            # use key
        # key is zeroed here
    """
    
    def __init__(self, size: int) -> None:
        self._data = bytearray(size)
    
    def __enter__(self) -> bytearray:
        return self._data
    
    def __exit__(self, *args: Any) -> None:
        secure_zero(self._data)
    
    def __len__(self) -> int:
        return len(self._data)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison (re-export from hashes for convenience).
    
    Note: Pure Python is NOT truly constant-time due to:
    - Variable-time integer operations
    - Branch prediction
    - Cache timing
    
    This is best-effort. For adversarial timing scenarios, use native crypto.
    """
    try:
        from ..hashing.sha2 import compare_digest
    except ImportError:
        try:
            from hashes import compare_digest
        except ImportError:
            from sha2 import compare_digest
    return compare_digest(a, b)
