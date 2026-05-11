"""Backward-compatible legacy cipher import surface."""

from .tea import TEA
from .redpike import RedPike
from .avemaria import AveMariaCipher

__all__ = ["TEA", "RedPike", "AveMariaCipher"]
