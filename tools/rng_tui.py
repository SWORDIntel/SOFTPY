#!/usr/bin/env python3
"""RNG Validation TUI — swap os.urandom ↔ DigitalURandom and run tests.

Usage:
    python tools/rng_tui.py
"""

from __future__ import annotations

import os
import sys
import importlib
import subprocess
import time
import textwrap

# ---------------------------------------------------------------------------
# Make the project importable when run from repo root
# ---------------------------------------------------------------------------
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_REPO, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# ---------------------------------------------------------------------------
# RNG backends
# ---------------------------------------------------------------------------

def _backend_os_urandom(n: int) -> bytes:
    return os.urandom(n)

def _backend_digital_urandom(n: int) -> bytes:
    from crypto_standalone.utils.digital_entropy import DigitalURandom
    if not hasattr(_backend_digital_urandom, "_rng"):
        _backend_digital_urandom._rng = DigitalURandom(strict_hardware=False)
    return _backend_digital_urandom._rng.urandom(n)

BACKENDS = {
    "1": ("os.urandom  (system CSPRNG)", _backend_os_urandom),
    "2": ("DigitalURandom (pure-Python)", _backend_digital_urandom),
}

# ---------------------------------------------------------------------------
# Monkey-patch helper
# ---------------------------------------------------------------------------

_original_os_urandom = os.urandom
_original_random_bytes = None

def patch_rng(backend_fn):
    """Monkey-patch os.urandom and crypto_standalone.utils.random to use *backend_fn*."""
    os.urandom = backend_fn
    # Also patch the module-level convenience so existing imports pick it up
    try:
        import crypto_standalone.utils.random as _rmod
        global _original_random_bytes
        _original_random_bytes = _rmod.random_bytes
        _rmod._get_rng = lambda: type("R", (), {"urandom": lambda self, n: backend_fn(n)})()
        # Rebind module-level functions through CSPRNG which now uses the patch
        _rmod._default_csprng = _rmod.CSPRNG()
        _rmod.random_bytes = _rmod._default_csprng.random_bytes
        _rmod.random_below = _rmod._default_csprng.random_below
        _rmod.random_bits = _rmod._default_csprng.random_bits
    except ImportError:
        pass

def unpatch_rng():
    """Restore original os.urandom."""
    os.urandom = _original_os_urandom
    try:
        import crypto_standalone.utils.random as _rmod
        importlib.reload(_rmod)
    except ImportError:
        pass

# ---------------------------------------------------------------------------
# Quick in-process sanity checks
# ---------------------------------------------------------------------------

def quick_check(backend_fn, n=32) -> dict:
    """Run a few fast checks against the chosen backend."""
    results = {}
    t0 = time.perf_counter()
    a = backend_fn(n)
    t1 = time.perf_counter()
    b = backend_fn(n)
    t2 = time.perf_counter()

    results["len_ok"] = len(a) == n and len(b) == n
    results["not_equal"] = a != b
    results["not_zero"] = a != b"\x00" * n and b != b"\x00" * n
    results["diversity"] = len(set(a)) >= 4 and len(set(b)) >= 4
    results["latency_ms"] = ((t1 - t0) * 1000, (t2 - t1) * 1000)
    results["sample"] = a.hex()[:32]
    return results

# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

TEST_SUITES = {
    "1": ("Unit tests (fast)", ["tests/unit/", "-x", "-q"]),
    "2": ("Adversarial / Wycheproof", ["tests/adversarial/", "-x", "-q"]),
    "3": ("All tests", ["tests/", "-x", "-q"]),
    "4": ("Self-test only", ["-c", "from crypto_standalone import self_test; self_test(); print('self_test PASSED')"]),
}

# ---------------------------------------------------------------------------
# TUI drawing helpers
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def header(title):
    w = 60
    print(f"{BOLD}{CYAN}{'=' * w}{RESET}")
    print(f"{BOLD}{CYAN}  {title:^{w - 4}}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * w}{RESET}")
    print()

def menu(options, prompt="Choice"):
    for key, (label, _) in options.items():
        print(f"  {BOLD}[{key}]{RESET}  {label}")
    print()
    while True:
        c = input(f"{YELLOW}{prompt}> {RESET}").strip()
        if c in options:
            return c
        print(f"  {RED}Invalid choice{RESET}")

def print_results(r: dict):
    for k, v in r.items():
        if k == "latency_ms":
            print(f"  {k:20s}  {v[0]:.2f} ms / {v[1]:.2f} ms")
        elif k == "sample":
            print(f"  {k:20s}  {v}...")
        else:
            icon = f"{GREEN}✓{RESET}" if v else f"{RED}✗{RESET}"
            print(f"  {k:20s}  {icon}")

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    current_backend = "1"
    current_fn = BACKENDS["1"][1]

    while True:
        clear()
        header("RNG Validation Suite")
        bname = BACKENDS[current_backend][0]
        print(f"  {BOLD}Active RNG:{RESET}  {bname}")
        print()

        print(f"  {BOLD}── RNG Backend ──{RESET}")
        for k, (label, _) in BACKENDS.items():
            marker = f"{GREEN} ◀{RESET}" if k == current_backend else ""
            print(f"  [{k}]  {label}{marker}")

        print()
        print(f"  {BOLD}── Quick Check ──{RESET}")
        print(f"  [q]  Run 32-byte sanity check")
        print(f"  [Q]  Run 1 KiB throughput check")
        print()
        print(f"  {BOLD}── Test Suites ──{RESET}")
        for k, (label, _) in TEST_SUITES.items():
            print(f"  [{k}]  {label}")
        print()
        print(f"  {BOLD}── Other ──{RESET}")
        print(f"  [p]  Patch os.urandom with active backend")
        print(f"  [u]  Un-patch (restore os.urandom)")
        print(f"  [x]  Exit")
        print()

        c = input(f"{YELLOW}Choice> {RESET}").strip().lower()

        # --- Backend switch ---
        if c in BACKENDS:
            current_backend = c
            current_fn = BACKENDS[c][1]
            continue

        # --- Quick check ---
        if c == "q":
            print(f"\n{DIM}Running sanity check...{RESET}")
            r = quick_check(current_fn, 32)
            print_results(r)
            input(f"\n{DIM}Press Enter...{RESET}")
            continue

        if c == "q_big" or c == "Q":
            print(f"\n{DIM}Running 1 KiB throughput check...{RESET}")
            t0 = time.perf_counter()
            data = current_fn(1024)
            t1 = time.perf_counter()
            print(f"  1024 bytes in {(t1-t0)*1000:.2f} ms")
            print(f"  sample: {data.hex()[:64]}...")
            input(f"\n{DIM}Press Enter...{RESET}")
            continue

        # --- Test suites ---
        if c in TEST_SUITES:
            label, cmd_parts = TEST_SUITES[c]
            print(f"\n{BOLD}Running: {label}{RESET}")
            print(f"{DIM}RNG backend: {BACKENDS[current_backend][0]}{RESET}\n")

            # Patch before running
            patch_rng(current_fn)

            if cmd_parts[0] == "-c":
                # Inline python command
                run_cmd = [sys.executable] + cmd_parts
            else:
                run_cmd = [sys.executable, "-m", "pytest"] + cmd_parts

            result = subprocess.run(run_cmd, cwd=_REPO)
            unpatch_rng()

            status = f"{GREEN}PASSED{RESET}" if result.returncode == 0 else f"{RED}FAILED{RESET}"
            print(f"\n{BOLD}Result: {status}{RESET}")
            input(f"\n{DIM}Press Enter...{RESET}")
            continue

        # --- Patch / unpatch ---
        if c == "p":
            patch_rng(current_fn)
            print(f"\n{GREEN}os.urandom patched with {BACKENDS[current_backend][0]}{RESET}")
            input(f"\n{DIM}Press Enter...{RESET}")
            continue

        if c == "u":
            unpatch_rng()
            print(f"\n{GREEN}os.urandom restored to system default{RESET}")
            input(f"\n{DIM}Press Enter...{RESET}")
            continue

        if c == "x":
            unpatch_rng()
            print(f"\n{DIM}Bye.{RESET}")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        unpatch_rng()
        print()
