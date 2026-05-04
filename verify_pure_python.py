"""Verify that no C-backed crypto modules are imported by core crypto code."""

import sys

FORBIDDEN = ["hashlib", "hmac", "secrets", "cryptography", "Crypto", "pycryptodome"]

def check_core_crypto():
    print("Checking core crypto modules (hashes, aes256, pure_rsa)...")
    print()
    
    before = set(sys.modules.keys())
    
    import hashes
    import aes256
    import pure_rsa
    
    after = set(sys.modules.keys())
    new = after - before
    
    for module_name in new:
        for forbidden in FORBIDDEN:
            if forbidden in module_name:
                print(f"❌ FAIL: Core crypto loaded {forbidden}: {module_name}")
                return False
    
    print("✓ Core crypto modules are pure Python (no hashlib/hmac/secrets)")
    print()
    
    print("Note: aws_sigv4.send_signed_request() uses urllib.request,")
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
        print("✓ SUCCESS: All crypto primitives are pure Python!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("=" * 60)
        print("❌ FAILURE: C-backed modules detected in crypto code")
        print("=" * 60)
        sys.exit(1)
