"""Pure-Python digital entropy collector and urandom replacement.

No os.urandom. No secrets. No random. No hashlib. No hmac. No ctypes.
No subprocess. No third-party packages.

Uses only Python-level access to:
  - TPM 2.0 device files, if present
  - /dev/hwrng, if present
  - high-resolution timing jitter
  - thread scheduler jitter
  - allocator / GC timing
  - Linux proc/sysfs state
  - optional network timing over plain sockets

All entropy is conditioned through the project's own pure-Python
sha256() and expanded through HMAC_DRBG_SHA256 (NIST SP 800-90A).
"""

from __future__ import annotations

import time
import threading
import sys
import gc

from ..hashing.sha2 import sha256, hmac_sha256
from .drbg import HMAC_DRBG_SHA256


_MASK64 = (1 << 64) - 1
_BITCOUNT = tuple(bin(i).count("1") for i in range(256))


def _u16(x):
    return (x & 0xFFFF).to_bytes(2, "big")


def _u32(x):
    return (x & 0xFFFFFFFF).to_bytes(4, "big")


def _u64(x):
    return (x & _MASK64).to_bytes(8, "big")


def _safe_bytes(x):
    if isinstance(x, bytes):
        return x
    return str(x).encode("utf-8", "replace")


def _xorshift64(x):
    x &= _MASK64
    x ^= (x << 13) & _MASK64
    x ^= x >> 7
    x ^= (x << 17) & _MASK64
    return x & _MASK64


def _frame(label, data):
    label = _safe_bytes(label)
    data = bytes(data)
    return _u16(len(label)) + label + _u64(len(data)) + data


def _pack_bits(bits):
    out = bytearray()
    acc = 0
    used = 0

    for bit in bits:
        acc = ((acc << 1) | (bit & 1)) & 0xFF
        used += 1

        if used == 8:
            out.append(acc)
            acc = 0
            used = 0

    if used:
        out.append((acc << (8 - used)) & 0xFF)

    return bytes(out)


def _von_neumann_lsb(words):
    """Extract debiased bits from the LSBs of timing-derived words.

    01 -> 0
    10 -> 1
    00, 11 -> discarded

    This is not a proof of entropy. It is a conservative conditioner
    for a noisy timing stream.
    """
    bits = []

    i = 0
    while i + 1 < len(words):
        a = words[i] & 1
        b = words[i + 1] & 1

        if a != b:
            bits.append(1 if a == 1 and b == 0 else 0)

        i += 2

    return _pack_bits(bits)


def _basic_noise_health(data):
    """Cheap sanity check only.

    This is not NIST SP 800-90B validation.
    It just detects obviously dead sources:
      - all zero / all one-ish streams
      - extreme bit imbalance
      - long repeated byte runs
    """
    data = bytes(data)

    if len(data) < 16:
        return False

    total = len(data) * 8
    ones = sum(_BITCOUNT[b] for b in data)

    if ones < total // 8:
        return False

    if ones > total - (total // 8):
        return False

    longest = 1
    run = 1
    prev = data[0]

    for b in data[1:]:
        if b == prev:
            run += 1
            if run > longest:
                longest = run
        else:
            prev = b
            run = 1

    if longest > max(32, len(data) // 4):
        return False

    return True


def _tpm2_getrandom_from_device(device_path, n):
    """Minimal TPM 2.0 TPM2_GetRandom implementation.

    Command format:
      tag           TPM_ST_NO_SESSIONS = 0x8001
      commandSize   12
      commandCode   TPM2_CC_GetRandom = 0x0000017B
      bytesRequested UINT16

    Response:
      tag
      responseSize
      responseCode
      TPM2B_DIGEST:
        size UINT16
        buffer bytes
    """
    out = bytearray()

    try:
        f = open(device_path, "r+b", buffering=0)
    except Exception:
        return b""

    try:
        while len(out) < n:
            want = min(64, n - len(out))

            cmd = (
                b"\x80\x01"
                + _u32(12)
                + _u32(0x0000017B)
                + _u16(want)
            )

            try:
                f.write(cmd)
                rsp = f.read(4096)
            except Exception:
                break

            if len(rsp) < 12:
                break

            response_size = int.from_bytes(rsp[2:6], "big")
            response_code = int.from_bytes(rsp[6:10], "big")

            if response_code != 0:
                break

            if response_size > len(rsp):
                break

            digest_size = int.from_bytes(rsp[10:12], "big")

            if digest_size <= 0:
                break

            if len(rsp) < 12 + digest_size:
                break

            out.extend(rsp[12:12 + digest_size])

    finally:
        try:
            f.close()
        except Exception:
            pass

    return bytes(out[:n])


class DigitalEntropyCollector:
    """Aggressive digital entropy collector.

    Important:
      This collector does not claim every source is secret.
      It mixes everything through pure-Python SHA-256.
      Security comes from at least one source being unpredictable
      to the attacker.
    """

    def __init__(self):
        self.pool = sha256(b"DIGITAL-ENTROPY-COLLECTOR-v2")
        self.events = []
        self.hardware_bytes = 0

    def mix(self, label, data):
        data = bytes(data)

        if not data:
            return

        t = time.perf_counter_ns()

        material = (
            b"POOL-MIX-v2|"
            + self.pool
            + _frame(b"label", _safe_bytes(label))
            + _frame(b"time", _u64(t))
            + _frame(b"data", data)
        )

        self.pool = sha256(material)
        self.events.append((_safe_bytes(label).decode("utf-8", "replace"), len(data)))

    def collect_runtime_state(self):
        payload = (
            _frame(b"sys.version", _safe_bytes(sys.version))
            + _frame(b"sys.platform", _safe_bytes(sys.platform))
            + _frame(b"id.self", _u64(id(self)))
            + _frame(b"id.object", _u64(id(object())))
            + _frame(b"perf_counter_ns", _u64(time.perf_counter_ns()))
            + _frame(b"time_ns", _u64(time.time_ns()))
        )

        self.mix(b"runtime-state", payload)

    def collect_tpm2(self, byte_count=64):
        total = 0

        for dev in ("/dev/tpmrm0", "/dev/tpm0"):
            t0 = time.perf_counter_ns()
            data = _tpm2_getrandom_from_device(dev, byte_count)
            t1 = time.perf_counter_ns()

            if data:
                self.hardware_bytes += len(data)
                total += len(data)
                self.mix(
                    b"tpm2-getrandom:" + _safe_bytes(dev),
                    _u64(t0) + _u64(t1) + data,
                )
                break

        return total

    def collect_hwrng(self, byte_count=64):
        total = 0

        for path in ("/dev/hwrng", "/dev/hw_random"):
            t0 = time.perf_counter_ns()

            try:
                with open(path, "rb", buffering=0) as f:
                    data = f.read(byte_count)
            except Exception:
                data = b""

            t1 = time.perf_counter_ns()

            if data:
                self.hardware_bytes += len(data)
                total += len(data)
                self.mix(
                    b"hwrng:" + _safe_bytes(path),
                    _u64(t0) + _u64(t1) + data,
                )
                break

        return total

    def collect_timer_jitter(self, samples=8192):
        raw = bytearray()
        words = []

        prev = time.perf_counter_ns()
        last_delta = 0
        x = prev ^ id(raw) ^ id(words)

        for i in range(samples):
            spin = 1 + (x & 31)

            for _ in range(spin):
                x = _xorshift64(x + i + prev)

            now = time.perf_counter_ns()
            delta = (now - prev) & _MASK64
            delta2 = (delta - last_delta) & _MASK64

            raw.extend(_u64(now))
            raw.extend(_u64(delta))
            raw.extend(_u64(delta2))
            raw.extend(_u64(x))

            words.append(delta2)

            prev = now
            last_delta = delta

        vn = _von_neumann_lsb(words)

        self.mix(b"timer-jitter-raw", bytes(raw))

        if _basic_noise_health(vn):
            self.mix(b"timer-jitter-vn-pass", vn)
        else:
            self.mix(b"timer-jitter-vn-weak", vn)

    def collect_thread_jitter(self, rounds=4096, workers=4):
        workers = max(1, int(workers))
        counters = [0] * workers
        stop = [False]

        def worker(k):
            x = (
                time.perf_counter_ns()
                ^ id(counters)
                ^ ((k + 1) * 0x9E3779B97F4A7C15)
            ) & _MASK64

            while not stop[0]:
                x = _xorshift64(x + time.perf_counter_ns() + k)
                counters[k] = x

        threads = []

        for k in range(workers):
            t = threading.Thread(target=worker, args=(k,), daemon=True)
            threads.append(t)
            t.start()

        raw = bytearray()
        prev = time.perf_counter_ns()

        for i in range(rounds):
            if (i & 15) == 0:
                time.sleep(0)

            now = time.perf_counter_ns()
            raw.extend(_u64(now - prev))
            raw.extend(_u64(now))

            for c in counters:
                raw.extend(_u64(c))

            prev = now

        stop[0] = True

        for t in threads:
            try:
                t.join(0.05)
            except Exception:
                pass

        self.mix(b"thread-scheduler-jitter", bytes(raw))

    def collect_allocator_jitter(self, samples=1024):
        raw = bytearray()

        for i in range(samples):
            t0 = time.perf_counter_ns()

            count = 1 + ((t0 ^ i) & 15)
            objs = [
                bytearray(1 + ((t0 >> (j % 16)) & 31))
                for j in range(count)
            ]

            raw.extend(_u64(t0))
            raw.extend(_u64(id(objs)))

            for obj in objs[:8]:
                raw.extend(_u64(id(obj)))

            if (i & 31) == 0:
                gc.collect()

            t1 = time.perf_counter_ns()
            raw.extend(_u64(t1))
            raw.extend(_u64(t1 - t0))

            del objs

        self.mix(b"allocator-gc-jitter", bytes(raw))

    def collect_linux_state(self, limit=4096):
        paths = [
            "/proc/interrupts",
            "/proc/stat",
            "/proc/schedstat",
            "/proc/softirqs",
            "/proc/loadavg",
            "/proc/uptime",
            "/proc/meminfo",
            "/proc/net/dev",
            "/proc/self/stat",
            "/proc/self/status",
            "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        ]

        for i in range(16):
            paths.append("/sys/class/thermal/thermal_zone%d/temp" % i)
            paths.append("/sys/class/hwmon/hwmon%d/temp1_input" % i)
            paths.append("/sys/class/hwmon/hwmon%d/fan1_input" % i)

        for path in paths:
            t0 = time.perf_counter_ns()

            try:
                with open(path, "rb") as f:
                    data = f.read(limit)
            except Exception as e:
                data = _safe_bytes(e.__class__.__name__)

            t1 = time.perf_counter_ns()

            self.mix(
                b"linux-state:" + _safe_bytes(path),
                _u64(t0) + _u64(t1) + data[:limit],
            )

    def collect_network_timing(self, hosts=None, timeout=1.0):
        """Optional. Uses plain sockets only, no ssl module.

        Network data is not trusted as secret.
        It is mixed only as supplemental timing/state.
        """
        if hosts is None:
            hosts = (
                "example.com",
                "iana.org",
                "python.org",
                "cloudflare.com",
            )

        try:
            import socket
        except Exception:
            self.mix(b"network-unavailable", b"socket import failed")
            return

        for host in hosts:
            t0 = time.perf_counter_ns()

            try:
                s = socket.create_connection((host, 80), timeout=timeout)
                t1 = time.perf_counter_ns()

                s.settimeout(timeout)
                req = (
                    b"HEAD / HTTP/1.0\r\nHost: "
                    + host.encode("ascii", "ignore")
                    + b"\r\n\r\n"
                )

                s.sendall(req)
                data = s.recv(1024)
                t2 = time.perf_counter_ns()

                try:
                    s.close()
                except Exception:
                    pass

                self.mix(
                    b"network-timing:" + _safe_bytes(host),
                    _u64(t0) + _u64(t1) + _u64(t2) + data,
                )

            except Exception as e:
                t1 = time.perf_counter_ns()
                self.mix(
                    b"network-fail:" + _safe_bytes(host),
                    _u64(t0) + _u64(t1) + _safe_bytes(e.__class__.__name__),
                )

    def extract_seed(self, label=b"DRBG-SEED"):
        """Final extraction to 32 bytes.

        This does not magically create entropy.
        It compresses all collected material into a fixed seed.
        """
        return sha256(
            b"FINAL-EXTRACT-v2|"
            + self.pool
            + _frame(b"label", _safe_bytes(label))
            + _frame(b"time", _u64(time.perf_counter_ns()))
            + _frame(b"id", _u64(id(object())))
        )

    def report(self):
        return {
            "hardware_bytes": self.hardware_bytes,
            "events": list(self.events),
        }


def _fast_additional_input(samples=128):
    """Cheap per-call jitter mixed into DRBG additional_input.

    This is supplemental. It is not treated as a guaranteed entropy source.
    """
    raw = bytearray()
    prev = time.perf_counter_ns()
    x = prev ^ id(raw)

    for i in range(samples):
        x = _xorshift64(x + i + prev)
        now = time.perf_counter_ns()
        raw.extend(_u64(now))
        raw.extend(_u64(now - prev))
        raw.extend(_u64(x))
        prev = now

    return sha256(b"FAST-ADDITIONAL-INPUT-v2|" + bytes(raw))


_DEFAULT_ENTROPY_CONFIG = {
    "timer_samples": 8192,
    "thread_rounds": 4096,
    "thread_workers": 4,
    "alloc_samples": 1024,
    "hw_byte_count": 64,
    "skip_linux_state": False,
    "skip_timer_jitter": False,
    "skip_thread_jitter": False,
    "skip_allocator_jitter": False,
}


class DigitalURandom:
    """urandom-like object backed by pure-Python entropy collection and HMAC-DRBG.

    Usage:
        rng = DigitalURandom()                     # full security
        key = rng.urandom(32)

        rng = DigitalURandom(entropy_config={      # fast init
        ...     "timer_samples": 2048,
        ...     "thread_rounds": 1024,
        ... })
    """

    def __init__(self, strict_hardware=False, use_network=False,
                 entropy_config=None):
        cfg = dict(_DEFAULT_ENTROPY_CONFIG)
        if entropy_config:
            cfg.update(entropy_config)

        collector = DigitalEntropyCollector()

        collector.collect_runtime_state()

        # Best hardware paths first.
        collector.collect_tpm2(cfg["hw_byte_count"])
        collector.collect_hwrng(cfg["hw_byte_count"])

        # Software/hardware-timing supplemental sources.
        if not cfg["skip_linux_state"]:
            collector.collect_linux_state()
        if not cfg["skip_timer_jitter"]:
            collector.collect_timer_jitter(samples=cfg["timer_samples"])
        if not cfg["skip_thread_jitter"]:
            collector.collect_thread_jitter(
                rounds=cfg["thread_rounds"],
                workers=cfg["thread_workers"],
            )
        if not cfg["skip_allocator_jitter"]:
            collector.collect_allocator_jitter(samples=cfg["alloc_samples"])

        if use_network:
            collector.collect_network_timing()

        if strict_hardware and collector.hardware_bytes < 32:
            raise RuntimeError(
                "strict_hardware=True requires at least 32 bytes from "
                "TPM2_GetRandom or /dev/hwrng"
            )

        seed = collector.extract_seed(b"DIGITAL-URANDOM-INIT-v2")

        self._drbg = HMAC_DRBG_SHA256(
            entropy_input=seed,
            personalization=b"DIGITAL-URANDOM-PURE-PYTHON-v2",
        )

        self._lock = threading.Lock()
        self._generated = 0
        self._collector_report = collector.report()

    @property
    def report(self):
        return dict(self._collector_report)

    def urandom(self, n):
        if not isinstance(n, int) or n < 0:
            raise ValueError("n must be a non-negative integer")

        additional = _fast_additional_input()

        with self._lock:
            out = self._drbg.random_bytes(
                n,
                additional_input=additional,
            )

        self._generated += n
        return out

    def hex(self, n):
        return self.urandom(n).hex()


def self_test():
    """Quick self-test of the pure-Python DRBG and entropy pipeline.

    Verifies:
      - HMAC_DRBG_SHA256 produces correct-length output
      - Two successive calls produce different bytes
      - Output is not all-zero
      - DigitalURandom (best-effort mode) produces usable output
    """
    # --- DRBG KAT (known-answer test with fixed seed) ---
    seed = sha256(b"self-test-seed")
    drbg = HMAC_DRBG_SHA256(
        entropy_input=seed,
        personalization=b"SELF-TEST",
    )

    a = drbg.random_bytes(32)
    b = drbg.random_bytes(32)

    assert len(a) == 32, f"DRBG output length: expected 32, got {len(a)}"
    assert len(b) == 32, f"DRBG output length: expected 32, got {len(b)}"
    assert a != b, "DRBG produced identical consecutive outputs"
    assert a != b"\x00" * 32, "DRBG produced all-zero output"
    assert b != b"\x00" * 32, "DRBG produced all-zero output"

    # --- Deterministic KAT: same seed must produce same first output ---
    drbg2 = HMAC_DRBG_SHA256(
        entropy_input=seed,
        personalization=b"SELF-TEST",
    )
    a2 = drbg2.random_bytes(32)
    assert a == a2, "DRBG deterministic KAT failed — same seed gave different output"

    # --- DigitalURandom best-effort mode ---
    rng = DigitalURandom(strict_hardware=False)
    x = rng.urandom(32)
    y = rng.urandom(32)

    assert len(x) == 32, f"DigitalURandom output length: expected 32, got {len(x)}"
    assert len(y) == 32, f"DigitalURandom output length: expected 32, got {len(y)}"
    assert x != y, "DigitalURandom produced identical consecutive outputs"
    assert x != b"\x00" * 32, "DigitalURandom produced all-zero output"

    return True
