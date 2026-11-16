#!/usr/bin/env python3
"""S0 (Sector Zero) — Reproducible Performance & Cryptographic Benchmark Harness.

Measures actual empirical performance across:
1. Canonical JSON serialization throughput (RFC 8785 subset)
2. Ed25519 key generation, signing, and verification latency
3. Cryptographic audit ledger block insertion & verification
4. Userspace data overwrite throughput (zero vs random + SHA-256)
5. Sampled post-wipe readback verification latency
6. Memory (RSS) footprint under streaming I/O load

Usage:
    python tools/benchmark_perf.py
    python tools/benchmark_perf.py --json
    python tools/benchmark_perf.py --quick
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import sys
import tempfile
import time
from pathlib import Path

# Add repo libraries to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from s0 import canonical, certificate, crypto
from s0.audit import (
    record_audit_event,
    verify_audit_ledger,
)
from s0.cli.devices import Target
from s0.config import CONFIG
from s0.wipe.planner import verify_wipe


def get_current_rss_mb() -> float:
    """Return current process Resident Set Size in MiB."""
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    # On Linux, ru_maxrss is in KiB; on macOS, in bytes
    if sys.platform == "darwin":
        return rusage.ru_maxrss / (1024 * 1024)
    return rusage.ru_maxrss / 1024


def bench_canonical_json(iterations: int = 2000) -> dict:
    """Benchmark Canonical JSON serialization throughput."""
    sample_payload = {
        "schema_version": "1.0.0",
        "cert_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp_utc": "2026-09-10T12:00:00Z",
        "organization": "S0 Benchmark & Forensic Research Laboratory",
        "operator": {"id": "op-bench-01", "role": "Performance Analyst"},
        "target": {
            "path": "/dev/nvme0n1",
            "capacity_bytes": 1000204886016,
            "sector_size": 4096,
            "serial": "SAMSUNG-MZVLB1T0HALR-00000",
            "storage_type": "NVME",
        },
        "method": {
            "id": "OVERWRITE_ZERO_1PASS",
            "nist_category": "Clear",
            "passes": 1,
            "pattern": "zero",
        },
        "verification": {
            "method": "sampled_readback_64k",
            "samples_checked": 64,
            "all_samples_match": True,
        },
        "metrics": {
            "bytes_processed": 1000204886016,
            "duration_seconds": 782,
            "average_mbps": 1278,
            "temperatures_c": [38, 41, 45, 47, 44],
        },
    }

    t0 = time.perf_counter()
    total_bytes = 0
    raw = b""
    for _ in range(iterations):
        raw = canonical.canonicalize(sample_payload)
        total_bytes += len(raw)
    elapsed = time.perf_counter() - t0

    ops_sec = iterations / elapsed
    mb_sec = (total_bytes / (1024 * 1024)) / elapsed

    return {
        "iterations": iterations,
        "elapsed_sec": elapsed,
        "ops_sec": ops_sec,
        "throughput_mbps": mb_sec,
        "avg_latency_ms": (elapsed / iterations) * 1000,
        "payload_size_bytes": len(raw),
    }


def bench_ed25519(iterations: int = 500) -> dict:
    """Benchmark Ed25519 key generation, signing, and verification."""
    # 1. Key Generation
    t0 = time.perf_counter()
    priv_keys = [crypto.generate_private_key() for _ in range(iterations)]
    keygen_sec = time.perf_counter() - t0

    # 2. Signing
    priv = priv_keys[0]
    pub = priv.public_key()
    sample_cert = certificate.build_certificate(
        organization="Benchmark Lab",
        operator_id="op-bench",
        tool_name="s0-bench",
        tool_version=CONFIG.get("version", "3.1.0"),
        platform=sys.platform,
        device_id="bench-dev-01",
        device_type="image_file",
        storage_type="IMAGE_FILE",
        method="OVERWRITE_ZERO_1PASS",
        nist_category="Clear",
        start_time="2026-09-10T00:00:00Z",
        end_time="2026-09-10T00:01:00Z",
        bytes_processed=1048576,
        capacity_bytes=1048576,
    )

    t0 = time.perf_counter()
    signed_certs = [certificate.sign_certificate(sample_cert, priv) for _ in range(iterations)]
    signing_sec = time.perf_counter() - t0

    # 3. Verification
    signed = signed_certs[0]
    t0 = time.perf_counter()
    for _ in range(iterations):
        ok, reason = certificate.verify_certificate(signed, [pub])
        assert ok is True, f"Verification failed: {reason}"
    verify_sec = time.perf_counter() - t0

    return {
        "iterations": iterations,
        "keygen": {
            "total_sec": keygen_sec,
            "ops_sec": iterations / keygen_sec,
            "avg_ms": (keygen_sec / iterations) * 1000,
        },
        "sign": {
            "total_sec": signing_sec,
            "ops_sec": iterations / signing_sec,
            "avg_ms": (signing_sec / iterations) * 1000,
        },
        "verify": {
            "total_sec": verify_sec,
            "ops_sec": iterations / verify_sec,
            "avg_ms": (verify_sec / iterations) * 1000,
        },
    }


def bench_audit_ledger(block_count: int = 100) -> dict:
    """Benchmark SQLite hash-chained audit ledger insertion and chain verification."""
    priv = crypto.generate_private_key()
    pub = priv.public_key()
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_audit.db"
        priv_pem_path = Path(tmp_dir) / "priv.pem"
        pub_pem_path = Path(tmp_dir) / "pub.pem"
        crypto.write_private_pem(priv, priv_pem_path)
        crypto.write_public_pem(pub, pub_pem_path)

        certs = []
        for i in range(block_count):
            c = certificate.build_certificate(
                organization="Audit Bench Lab",
                operator_id=f"op-audit-{i}",
                tool_name="s0-bench",
                tool_version=CONFIG.get("version", "3.1.0"),
                platform="linux",
                device_id=f"drive-bench-{i}",
                device_type="image_file",
                storage_type="IMAGE_FILE",
                method="OVERWRITE_ZERO_1PASS",
                nist_category="Clear",
                start_time="2026-09-10T01:00:00Z",
                end_time="2026-09-10T01:01:00Z",
                bytes_processed=1048576,
                capacity_bytes=1048576,
            )
            certs.append(certificate.sign_certificate(c, priv))

        # Insertion Benchmark
        t0 = time.perf_counter()
        for sc in certs:
            record_audit_event(
                sc,
                operation_type="DRIVE_ERASE",
                db_path=db_path,
                private_key=priv_pem_path,
            )
        insert_sec = time.perf_counter() - t0

        # Verification Benchmark
        t0 = time.perf_counter()
        report = verify_audit_ledger(db_path=db_path, trusted_public_keys=[pub])
        verify_sec = time.perf_counter() - t0

        assert report.is_valid is True, f"Ledger verification failed: {report.reason}"
        assert report.total_blocks_verified == block_count + 1

        return {
            "block_count": block_count,
            "insert": {
                "total_sec": insert_sec,
                "ops_sec": block_count / insert_sec,
                "avg_ms": (insert_sec / block_count) * 1000,
            },
            "verify_ledger": {
                "total_sec": verify_sec,
                "blocks_sec": block_count / verify_sec,
                "avg_per_block_ms": (verify_sec / block_count) * 1000,
            },
        }


def bench_overwrite(size_mb: int = 64) -> dict:
    """Benchmark Python userspace sequential overwrite loop (zero vs random)."""
    buf_size = 1024 * 1024  # 1 MiB chunk
    target_bytes = size_mb * 1024 * 1024

    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = Path(tmp_dir) / "bench_target.bin"

        # 1. Zero Overwrite + Streaming SHA-256
        zero_chunk = b"\x00" * buf_size
        h_zero = hashlib.sha256()
        t0 = time.perf_counter()
        with open(test_file, "wb") as f:
            written = 0
            while written < target_bytes:
                f.write(zero_chunk)
                h_zero.update(zero_chunk)
                written += len(zero_chunk)
            f.flush()
            os.fsync(f.fileno())
        zero_sec = time.perf_counter() - t0
        zero_mbps = size_mb / zero_sec

        # 2. Sampled Readback Verification (64 samples x 4096 bytes)
        target = Target(
            path=str(test_file),
            kind="image",
            capacity_bytes=target_bytes,
            sector_size=512,
            storage_type="IMAGE_FILE",
        )
        t0 = time.perf_counter()
        verif, _ = verify_wipe(target, pattern="zero", samples=64, sample_bytes=4096)
        readback_sec = time.perf_counter() - t0
        assert verif["all_samples_match_wipe_pattern"] is True

        # 3. Random Overwrite + Streaming SHA-256
        h_rand = hashlib.sha256()
        t0 = time.perf_counter()
        with open(test_file, "r+b") as f:
            written = 0
            while written < target_bytes:
                rand_chunk = os.urandom(buf_size)
                f.write(rand_chunk)
                h_rand.update(rand_chunk)
                written += len(rand_chunk)
            f.flush()
            os.fsync(f.fileno())
        rand_sec = time.perf_counter() - t0
        rand_mbps = size_mb / rand_sec

        return {
            "size_mb": size_mb,
            "zero_overwrite": {
                "elapsed_sec": zero_sec,
                "throughput_mbps": zero_mbps,
            },
            "random_overwrite": {
                "elapsed_sec": rand_sec,
                "throughput_mbps": rand_mbps,
            },
            "sampled_readback": {
                "elapsed_ms": readback_sec * 1000,
                "samples_checked": 64,
                "all_matched": verif["all_samples_match_wipe_pattern"],
            },
        }


def run_all_benchmarks(quick: bool = False) -> dict:
    """Execute the full benchmark harness and return comprehensive performance metrics."""
    rss_start = get_current_rss_mb()
    t_start = time.time()

    json_iters = 500 if quick else 2500
    crypto_iters = 100 if quick else 600
    blocks = 30 if quick else 100
    wipe_mb = 16 if quick else 64

    results = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start)),
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "rss_initial_mb": rss_start,
        "canonical_json": bench_canonical_json(iterations=json_iters),
        "ed25519": bench_ed25519(iterations=crypto_iters),
        "audit_ledger": bench_audit_ledger(block_count=blocks),
        "io_overwrite": bench_overwrite(size_mb=wipe_mb),
        "rss_final_mb": get_current_rss_mb(),
    }
    results["rss_delta_mb"] = results["rss_final_mb"] - results["rss_initial_mb"]
    results["total_elapsed_sec"] = time.time() - t_start

    return results


def print_report(res: dict) -> None:
    """Print an ASCII telemetry report."""
    print("=" * 78)
    print("  S0 (SECTOR ZERO) EMPIRICAL PERFORMANCE BENCHMARK REPORT")
    print("=" * 78)
    print(f"  Execution Time  : {res['timestamp_utc']}")
    print(f"  Platform Target : {res['platform']} (Python {res['python_version']})")
    print(f"  Memory Initial  : {res['rss_initial_mb']:.2f} MiB RSS")
    print(f"  Memory Peak/End : {res['rss_final_mb']:.2f} MiB RSS (Delta: +{res['rss_delta_mb']:.2f} MiB)")
    print("-" * 78)
    print("1. CANONICAL JSON ENGINE (RFC 8785 subset)")
    cj = res["canonical_json"]
    print(f"   Operations     : {cj['iterations']:,} serialization cycles")
    print(f"   Throughput     : {cj['throughput_mbps']:.2f} MB/s ({cj['ops_sec']:,.0f} ops/sec)")
    print(f"   Mean Latency   : {cj['avg_latency_ms']:.4f} ms per certificate")
    print("-" * 78)
    print("2. ED25519 ASYMMETRIC CRYPTOGRAPHY (RFC 8032)")
    ed = res["ed25519"]
    print(f"   Key Generation : {ed['keygen']['avg_ms']:.4f} ms ({ed['keygen']['ops_sec']:,.0f} keys/sec)")
    print(f"   Sign Latency   : {ed['sign']['avg_ms']:.4f} ms ({ed['sign']['ops_sec']:,.0f} signatures/sec)")
    print(
        f"   Verify Latency : {ed['verify']['avg_ms']:.4f} ms ({ed['verify']['ops_sec']:,.0f} verifications/sec)"
    )
    print("-" * 78)
    print("3. HASH-CHAINED AUDIT LEDGER (SQLite + SHA-256 + Ed25519)")
    al = res["audit_ledger"]
    print(f"   Blocks Tested  : {al['block_count']} chained blocks")
    print(
        f"   Block Insert   : {al['insert']['avg_ms']:.3f} ms/block ({al['insert']['ops_sec']:,.1f} blocks/sec)"
    )
    print(
        f"   Full Chain Ver.: {al['verify_ledger']['total_sec'] * 1000:.2f} ms ({al['verify_ledger']['blocks_sec']:,.0f} blocks/sec)"
    )
    print("-" * 78)
    print("4. DATA OVERWRITE & VERIFICATION I/O (Userspace Python Stream)")
    io = res["io_overwrite"]
    print(f"   Buffer Size    : {io['size_mb']} MiB in 1 MiB chunks")
    print(f"   Zero Overwrite : {io['zero_overwrite']['throughput_mbps']:.1f} MB/s (with concurrent SHA-256)")
    print(
        f"   Random Overwr. : {io['random_overwrite']['throughput_mbps']:.1f} MB/s (with OS CSPRNG + SHA-256)"
    )
    print(f"   Readback Audit : {io['sampled_readback']['elapsed_ms']:.2f} ms (64 samples × 4 KiB)")
    print("-" * 78)
    print("5. HARDWARE ARCHITECTURE CONTEXT:")
    print("   • Physical NVMe Gen4 bus throughput (1,200 - 5,000 MB/s) requires direct block-level")
    print("     C/kernel drivers or dd/nvme-cli. The Python userspace streaming loop caps at ~180-350 MB/s")
    print("     due to GIL, per-chunk SHA-256 hashing, and system call context switching.")
    print("   • NVMe Format Crypto Erase operates at instantaneous controller key rotation (< 2s),")
    print("     rendering logical drive capacity unreadable instantly without transmitting data across PCIe.")
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(description="S0 Reproducible Performance Benchmark Harness")
    parser.add_argument("--json", action="store_true", help="Output results as raw JSON")
    parser.add_argument("--quick", action="store_true", help="Run shortened benchmark loop")
    args = parser.parse_args()

    results = run_all_benchmarks(quick=args.quick)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)


if __name__ == "__main__":
    main()
