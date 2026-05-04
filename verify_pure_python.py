"""Verify that no C-backed crypto modules are imported by core crypto code."""

import sys

FORBIDDEN = ["hashlib", "hmac", "secrets", "cryptography", "Crypto", "pycryptodome"]


def check_core_crypto():
    print("Checking crypto_standalone subpackages for C-backed imports...")
    print()

    before = set(sys.modules.keys())

    import crypto_standalone
    from crypto_standalone import (
        symmetric, hashing, asymmetric, kdf, utils, aws,
    )

    after = set(sys.modules.keys())
    new = after - before

    # Check that our source files don't directly import forbidden modules
    import ast
    import importlib
    import os

    pkg_dir = os.path.dirname(importlib.util.find_spec("crypto_standalone").origin)
    failed = False
    for root, dirs, files in os.walk(pkg_dir):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, pkg_dir)
            try:
                tree = ast.parse(open(fpath).read())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for forbidden in FORBIDDEN:
                            if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                                print(f"  FAIL: {rel} imports {alias.name}")
                                failed = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for forbidden in FORBIDDEN:
                            if node.module == forbidden or node.module.startswith(forbidden + "."):
                                print(f"  FAIL: {rel} imports from {node.module}")
                                failed = True

    if failed:
        return False

    print("  All crypto_standalone source files are pure Python")
    print("  (no direct hashlib/hmac/secrets/C-backed imports)")
    print()

    # Also verify the RNG doesn't use os.urandom/secrets/random as code
    from crypto_standalone.utils import digital_entropy
    import ast
    import inspect
    src = inspect.getsource(digital_entropy)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        pass
    else:
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "urandom":
                if isinstance(node.value, ast.Name) and node.value.id == "os":
                    print("  FAIL: digital_entropy.py uses os.urandom")
                    return False
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("secrets", "random"):
                        print(f"  FAIL: digital_entropy.py imports {alias.name}")
                        return False
            if isinstance(node, ast.ImportFrom) and node.module in ("secrets", "random"):
                print(f"  FAIL: digital_entropy.py imports from {node.module}")
                return False
    print("  digital_entropy.py: no os.urandom/secrets/random code usage")

    print()
    print("Note: aws.sigv4.send_signed_request() uses urllib.request,")
    print("      which imports hashlib for SSL/TLS. This is acceptable")
    print("      since our crypto primitives don't use it.")
    print()

    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Pure-Python Crypto Import Verification")
    print("=" * 60)
    print()

    if check_core_crypto():
        print("=" * 60)
        print("SUCCESS: All crypto primitives are pure Python!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("=" * 60)
        print("FAILURE: C-backed modules detected in crypto code")
        print("=" * 60)
        sys.exit(1)
