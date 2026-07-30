import time
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crypto_standalone.symmetric.aes_ige import aes_ige_encrypt, aes_ige_decrypt

def benchmark_ige():
    payload_size = 1024 * 1024  # 1MB
    payload = os.urandom(payload_size)
    key = os.urandom(32)
    iv = os.urandom(32)

    start = time.perf_counter()
    ct = aes_ige_encrypt(payload, key, iv)
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    dec = aes_ige_decrypt(ct, key, iv)
    dec_time = time.perf_counter() - start

    assert dec == payload

    print(f"AES-256-IGE Encryption (1MB): {enc_time:.4f} seconds ({payload_size / enc_time / 1024 / 1024:.2f} MB/s)")
    print(f"AES-256-IGE Decryption (1MB): {dec_time:.4f} seconds ({payload_size / dec_time / 1024 / 1024:.2f} MB/s)")

if __name__ == "__main__":
    benchmark_ige()
