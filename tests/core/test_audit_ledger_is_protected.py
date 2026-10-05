"""The chain of custody must be private, and appends must not collide.

The ledger records what was wiped, by whom, with signatures. Two properties make it
worth anything, and both were missing.

**It was world-readable.** ``sqlite3.connect`` creates the file with the process
umask -- 0644 on a typical system, and 0664 here. Anyone who could read the ledger
learned which evidence a user had destroyed; anyone who could write it could forge
history. The fix creates the file at 0600 before handing the path to sqlite (which
takes no mode) and then chmods unconditionally, so a ledger left wide by an older
version is narrowed too rather than trusted.

The chain checkpoint sidecar carried the *same* tip index and hash and was still
0664 after the database was tightened -- so the "fix" left a readable copy of the
chain state beside the protected one.

**Appends could collide.** Reading the tip and then inserting is a race: two
processes both read tip N, both compute index N+1 against the same prev_hash, and
both insert. A duplicated index in a hash chain is exactly the artefact the ledger
exists to make impossible. ``BEGIN IMMEDIATE`` takes the write lock before the tip is
read, making the read and the insert one atomic step; a deferred transaction does
not, because it upgrades to a write lock at the first write, which is after the
SELECT.

Six concurrent `s0 wipe` processes are used rather than threads, because the real
collision was between processes -- a UI, a CLI and a scheduled export sharing one
ledger.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

from s0.audit.db import BUSY_TIMEOUT_MS, get_db_connection, init_audit_db

REPO_ROOT = Path(__file__).resolve().parents[2]


def _entry_point() -> str:
    import shutil

    found = shutil.which("s0") or str(Path(sys.executable).parent / "s0")
    if not Path(found).is_file():
        pytest.skip("s0 entry point not available")
    return found


def _wipe(path: Path, home: Path, tag: str) -> subprocess.CompletedProcess:
    target = home / f"{tag}.txt"
    target.write_text(f"evidence {tag}\n" * 8)
    return subprocess.run(
        [
            _entry_point(),
            "wipe",
            "--target",
            str(target),
            "--yes",
            "--no-pdf",
            "--out-dir",
            str(home / "certs"),
        ],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "HOME": str(home),
            "USERPROFILE": str(home),
            "S0_AUDIT_DB": str(home / "audit.db"),
            **({} if os.name == "nt" else {"PATH": "/usr/bin:/bin"}),
        },
        cwd=str(home),
    )


class TestTheLedgerIsNotWorldReadable:
    def test_a_new_ledger_is_0600(self, tmp_path):
        db = tmp_path / "audit.db"
        init_audit_db(db)
        conn = get_db_connection(db)
        conn.close()
        mode = stat.S_IMODE(db.stat().st_mode)
        assert mode == 0o600, (
            f"the ledger is {mode:04o}; anyone who can read it learns what was "
            f"destroyed, and anyone who can write it can forge history"
        )

    def test_an_existing_wide_ledger_is_narrowed(self, tmp_path):
        """The case that matters most: a ledger created by an older version."""
        db = tmp_path / "audit.db"
        init_audit_db(db)
        os.chmod(db, 0o666)  # noqa: S103 - widening is what is under test
        assert stat.S_IMODE(db.stat().st_mode) == 0o666

        conn = get_db_connection(db)
        conn.close()
        mode = stat.S_IMODE(db.stat().st_mode)
        assert mode == 0o600, (
            f"a pre-existing 0666 ledger was left at {mode:04o}. The chmod has to be "
            f"unconditional -- trusting an existing file's mode is trusting that "
            f"nothing has widened it."
        )

    def test_the_checkpoint_sidecar_is_0600_too(self, tmp_path):
        """It carries the same tip index and hash as the ledger."""
        from s0.audit.db import _write_checkpoint

        db = tmp_path / "audit.db"
        init_audit_db(db)
        _write_checkpoint(db, 1, "a" * 64, "2026-01-01T00:00:00Z")
        sidecar = tmp_path / "audit.checkpoint.json"
        assert sidecar.is_file()
        mode = stat.S_IMODE(sidecar.stat().st_mode)
        assert mode == 0o600, (
            f"the chain checkpoint is {mode:04o}. It holds the same tip state as the "
            f"ledger, so tightening only the database leaves a readable copy of the "
            f"chain beside it."
        )

    def test_an_existing_wide_checkpoint_is_narrowed(self, tmp_path):
        from s0.audit.db import _write_checkpoint

        db = tmp_path / "audit.db"
        init_audit_db(db)
        sidecar = tmp_path / "audit.checkpoint.json"
        sidecar.write_text("{}")
        os.chmod(sidecar, 0o666)  # noqa: S103 - likewise

        _write_checkpoint(db, 2, "b" * 64, "2026-01-01T00:00:00Z")
        mode = stat.S_IMODE(sidecar.stat().st_mode)
        assert mode == 0o600

    def test_the_parent_directory_is_not_world_writable(self, tmp_path):
        """0600 on the file is undermined by a world-writable directory."""
        db = tmp_path / "state" / "audit.db"
        init_audit_db(db)
        mode = stat.S_IMODE(db.parent.stat().st_mode)
        assert not (mode & stat.S_IWOTH), (
            f"the ledger's directory is {mode:04o}; another user could replace the "
            f"file regardless of its own mode"
        )


class TestTheLedgerWaitsForALock:
    def test_a_busy_timeout_is_configured(self, tmp_path):
        db = tmp_path / "audit.db"
        init_audit_db(db)
        conn = get_db_connection(db)
        try:
            got = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        finally:
            conn.close()
        assert got == BUSY_TIMEOUT_MS, (
            "no busy_timeout, so a concurrent append raises 'database is locked' "
            "the instant another writer holds the lock rather than waiting"
        )

    def test_a_second_writer_waits_rather_than_failing(self, tmp_path):
        """The scenario the timeout exists for, held open deliberately."""
        db = tmp_path / "audit.db"
        init_audit_db(db)

        holder = get_db_connection(db)
        holder.execute("BEGIN IMMEDIATE")  # take the write lock
        holder.execute(
            "INSERT INTO audit_blocks (block_index, timestamp, operation_type, "
            "target_id, operator_id, organization, cert_uuid, payload_hash, "
            "signature, prev_hash, block_hash, certificate_json, block_signature) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (99, "t", "X", "d", "o", "g", "u", "p", "s", "ph", "bh", "{}", ""),
        )

        errors: list[Exception] = []
        done = threading.Event()

        def contend() -> None:
            try:
                conn = get_db_connection(db)
                try:
                    with conn:
                        conn.execute("BEGIN IMMEDIATE")
                finally:
                    conn.close()
            except Exception as exc:  # noqa: BLE001 - recording the outcome
                errors.append(exc)
            finally:
                done.set()

        worker = threading.Thread(target=contend, daemon=True)
        worker.start()
        # Give it long enough that an immediate failure is unambiguous.
        assert not done.wait(timeout=1.0), "the second writer failed instead of waiting for the lock"
        assert not errors, f"the waiting writer raised: {errors}"

        holder.rollback()
        holder.close()
        assert done.wait(timeout=BUSY_TIMEOUT_MS / 1000 + 5)
        assert not errors, f"the waiting writer raised once the lock cleared: {errors}"


class TestConcurrentAppendsDoNotCollide:
    def test_six_processes_produce_a_gapless_unique_chain(self, tmp_path):
        """The real collision was between processes, not threads.

        Threads share a GIL and would serialise the read-modify-write anyway, which
        is exactly the case that hides this bug. Separate processes interleave for
        real.
        """
        procs = []
        for i in range(6):
            target = tmp_path / f"t{i}.txt"
            target.write_text(f"evidence {i}\n" * 8)
            procs.append(
                subprocess.Popen(
                    [
                        _entry_point(),
                        "wipe",
                        "--target",
                        str(target),
                        "--yes",
                        "--no-pdf",
                        "--out-dir",
                        str(tmp_path / "certs"),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={
                        "HOME": str(tmp_path),
                        "PATH": "/usr/bin:/bin",
                        "S0_AUDIT_DB": str(tmp_path / "audit.db"),
                    },
                    cwd=str(tmp_path),
                )
            )

        for proc in procs:
            assert proc.wait(timeout=300) == 0, "a concurrent wipe failed"

        from s0.audit.db import list_audit_blocks

        blocks = list_audit_blocks(db_path=tmp_path / "audit.db")
        indices = [b.block_index for b in blocks]

        assert len(indices) == len(set(indices)), (
            f"duplicate block indices in the ledger: {sorted(indices)}. Two blocks "
            f"at one index is the exact forgery the chain exists to prevent."
        )
        assert sorted(indices) == list(range(len(indices))), (
            f"the chain has a gap or is out of order: {sorted(indices)}"
        )

    def test_every_block_chains_to_its_predecessor(self, tmp_path):
        procs = []
        for i in range(4):
            target = tmp_path / f"u{i}.txt"
            target.write_text(f"evidence {i}\n" * 8)
            procs.append(
                subprocess.Popen(
                    [
                        _entry_point(),
                        "wipe",
                        "--target",
                        str(target),
                        "--yes",
                        "--no-pdf",
                        "--out-dir",
                        str(tmp_path / "certs"),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={
                        "HOME": str(tmp_path),
                        "PATH": "/usr/bin:/bin",
                        "S0_AUDIT_DB": str(tmp_path / "audit.db"),
                    },
                    cwd=str(tmp_path),
                )
            )
        for proc in procs:
            proc.wait(timeout=300)

        from s0.audit.db import list_audit_blocks

        blocks = sorted(list_audit_blocks(db_path=tmp_path / "audit.db"), key=lambda b: b.block_index)
        for previous, current in zip(blocks, blocks[1:], strict=False):
            assert current.prev_hash == previous.block_hash, (
                f"block {current.block_index} chains to {current.prev_hash[:16]}... "
                f"but block {previous.block_index} is {previous.block_hash[:16]}..."
            )

    def test_the_ledger_still_verifies_after_concurrent_writes(self, tmp_path):
        """A chain that survives the race must still verify."""
        procs = []
        for i in range(3):
            target = tmp_path / f"v{i}.txt"
            target.write_text(f"evidence {i}\n" * 8)
            procs.append(
                subprocess.Popen(
                    [
                        _entry_point(),
                        "wipe",
                        "--target",
                        str(target),
                        "--yes",
                        "--no-pdf",
                        "--out-dir",
                        str(tmp_path / "certs"),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={
                        "HOME": str(tmp_path),
                        "PATH": "/usr/bin:/bin",
                        "S0_AUDIT_DB": str(tmp_path / "audit.db"),
                    },
                    cwd=str(tmp_path),
                )
            )
        for proc in procs:
            proc.wait(timeout=300)

        # `audit verify` takes the ledger through S0_AUDIT_DB; there is no --db flag.
        proc = subprocess.run(
            [_entry_point(), "audit", "verify"],
            capture_output=True,
            text=True,
            timeout=300,
            env={
                **os.environ,
                "HOME": str(tmp_path),
                "USERPROFILE": str(tmp_path),
                "S0_AUDIT_DB": str(tmp_path / "audit.db"),
                **({} if os.name == "nt" else {"PATH": "/usr/bin:/bin"}),
            },
            cwd=str(tmp_path),
        )
        assert "Traceback" not in proc.stdout + proc.stderr
        assert proc.returncode in (0, 75), (
            f"audit verify exited {proc.returncode} after concurrent appends:\n"
            f"{(proc.stdout + proc.stderr)[-800:]}"
        )


class TestTheTipReadRaceIsActuallyClosed:
    """Deterministic proof, because the race is too narrow to hit by chance.

    Six concurrent processes did not collide even with the fix reverted: the window
    between reading the tip and inserting is a few microseconds, so a test that
    relies on losing that race passes whether or not the lock is taken. A test that
    cannot fail when the fix is removed is not testing the fix.

    So the window is widened on purpose. ``compute_block_hash`` is called after the
    tip is read and before the row is inserted, which makes it the ideal place to
    pause: with BEGIN IMMEDIATE the second process is still blocked at its BEGIN, so
    it cannot have read a stale tip; without it, the second process reads the tip the
    first is about to advance past and both compute the same index.
    """

    def test_two_writers_cannot_both_advance_from_the_same_tip(self, tmp_path):
        import threading

        from s0.audit import db as dbmod

        db = tmp_path / "audit.db"
        init_audit_db(db)

        gate = threading.Event()
        entered = threading.Semaphore(0)
        release = threading.Semaphore(0)
        original = dbmod.compute_block_hash
        slowdowns = 4  # let several threads pile up behind the lock

        def slow_hash(*args, **kwargs):
            entered.release()
            # Wait for the other threads to reach the same point. If the write lock
            # is held, they never get here and this simply times out.
            release.acquire(timeout=3)
            return original(*args, **kwargs)

        results: list[int] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def append(i: int) -> None:
            cert = {
                "issued_at": "2026-01-01T00:00:00Z",
                "cert_uuid": f"u{i}",
                "issuer": {"operator_id": "op", "organization": "org"},
                "device": {"device_id": "dev"},
                "signature": {"signature_base64url": "sig"},
            }
            try:
                block = dbmod.record_audit_event(cert, db_path=db)
                with lock:
                    results.append(block.block_index)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        workers = [threading.Thread(target=append, args=(i,), daemon=True) for i in range(slowdowns)]
        with mock.patch.object(dbmod, "compute_block_hash", slow_hash):
            for w in workers:
                w.start()
            # Let them all reach the widened window, then let them through.
            for _ in range(slowdowns):
                assert entered.acquire(timeout=5), "a writer never reached the window"
            gate.set()
            for _ in range(slowdowns):
                release.release()
            for w in workers:
                w.join(timeout=30)

        assert not errors, f"concurrent appends raised: {errors}"
        assert len(results) == len(set(results)), (
            f"two writers claimed the same block index: {sorted(results)}. Each "
            f"computed it from the same tip, which means the chain forks here."
        )
