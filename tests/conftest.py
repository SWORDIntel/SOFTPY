"""Pytest configuration and shared fixtures."""

import os
import sys

# Ensure the src package is prioritized over any local crypto_standalone/ directory
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
src_dir = os.path.normpath(src_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
