"""Two commands that destroy things, and neither asked first.

**`live flash` wrote over a mounted filesystem.** `_unmount_partitions` ran
`umount -f` with `check=False` and then returned `True` unconditionally on Linux. When
the unmount failed -- a busy filesystem, which is the normal state of a USB stick someone
is still using -- the caller was told it had succeeded and the ISO was written over live
data, reporting "Successfully flashed". `wipe` and `clone` both refuse a mounted target;
`live flash` did not, and `--force --yes` made it reachable.

The fix asks the kernel rather than `umount`: `/proc/mounts` is read after the attempt,
and the write is refused if anything under the device or one of its partitions is still
mounted. `--force` does not override it, because there is no reading of "overwrite a
mounted filesystem" that is what the operator meant.

**`keygen` silently replaced an existing private key.** Running it twice in one directory
wrote a new key, exit 0, no warning, no backup. The tool calls that key the root of trust
for every certificate the authority will ever issue, so every certificate already signed
with it stopped being attributable to anything on that machine, and nothing said so.

**`keygen --name` was an unchecked path.** `--name ../escape` wrote
`escape_private.pem` one level above `--out-dir`, because `out_dir / "../x"` normalises
upwards; `--name /abs/path` discarded `--out-dir` entirely, because joining an absolute
path replaces the left side. So a name could create, or overwrite, a `*_private.pem`
somewhere the operator never named.

The unmount half needs root to exercise end to end, so those tests assert the predicate
directly against the machine's real mounts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))


def _entry() -> str:
    found = Path(sys.executable).parent / "s0"
    if found.is_file():
        return str(found)
    which = shutil.which("s0")
    if not which:
        pytest.skip("s0 entry point not available")
    return which


def _synthetic_mounts(tmp_path: Path, lines: list[str]) -> Path:
    """Write a fake /proc/mounts and point `_still_mounted` at it.

    The unmount logic used to be tested against whatever block devices the machine
    happened to have mounted. That is the thing the test suite is not allowed to do:
    it issued a real `umount -f` against a real device, and relied on running
    unprivileged to make that fail safely. A test that is only safe because of the
    permissions it happens to run with is one CI root container away from being a test
    that unmounts the build machine's disk.

    Every case below is now a fixture: the device nodes are ordinary empty files in
    tmp_path and the mount table is a string we control.
    """
    mounts = tmp_path / "proc-mounts"
    mounts.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return mounts


class TestLiveFlashRefusesAMountedTarget:
    """Every case here is a fixture -- no real block device is read or unmounted."""

    @pytest.fixture(autouse=True)
    def _no_real_devices(self, tmp_path, monkeypatch):
        """Fail loudly if anything in this class reaches a real device node."""
        from s0.live import live_manager

        mounts = _synthetic_mounts(
            tmp_path,
            [
                "/dev/fakesda1 / ext4 rw,relatime 0 0",
                "/dev/fakesda2 /data xfs rw,relatime 0 0",
                "tmpfs /run tmpfs rw,nosuid 0 0",
            ],
        )
        monkeypatch.setattr(live_manager, "MOUNTS_PATH", str(mounts))

        def _no_subprocess(*a, **k):
            raise AssertionError(f"a test issued a real command: {a!r}")

        monkeypatch.setattr(live_manager.subprocess, "run", _no_subprocess)

    def test_it_finds_a_mounted_device(self):
        from s0.live.live_manager import _still_mounted

        holders = _still_mounted("/dev/fakesda1")
        assert holders, "a device in the mount table must be reported as mounted"
        assert all("/" in h or "(" in h for h in holders)

    def test_a_partition_of_a_mounted_device_counts_as_mounted(self):
        """`/dev/sda1` is a partition of `/dev/sda`; asking about either must work.

        Getting this wrong in the permissive direction is how a whole-disk flash slips
        past a check that only looks at the device node itself.
        """
        from s0.live.live_manager import _still_mounted

        assert _still_mounted("/dev/fakesda"), "/dev/fakesda should be reported as mounted"
        assert _still_mounted("/dev/fakesda1"), "/dev/fakesda1 is mounted directly"
        assert _still_mounted("/dev/fakesda2"), "/dev/fakesda2 is mounted directly"

    def test_the_whole_disk_lists_every_partition_mount_point(self):
        from s0.live.live_manager import _still_mounted

        holders = _still_mounted("/dev/fakesda")
        assert any("/data" in h for h in holders), f"expected /data among {holders}"
        assert any("ext4" in h or "/" in h for h in holders)

    def test_a_device_with_nothing_mounted_is_clean(self):
        from s0.live.live_manager import _still_mounted

        assert _still_mounted("/dev/definitely-not-a-real-device-xyz") == []

    def test_a_non_device_mount_is_not_attributed_to_it(self):
        """tmpfs has no device node; it must not make an unrelated device look busy."""
        from s0.live.live_manager import _still_mounted

        assert _still_mounted("/dev/run") == []

    def test_a_failed_unmount_reports_failure(self, tmp_path, monkeypatch):
        """The reported defect: unmount failed and the function said it had succeeded.

        `umount -f` on a busy filesystem can return zero in some configurations and
        non-zero in others, so the old code that trusted its exit status -- and used
        `check=False` so nobody was even looking -- was wrong in whichever direction the
        kernel happened to pick. The answer now comes from re-reading the mount table.
        """
        from s0.live import live_manager
        from s0.live.live_manager import _unmount_partitions

        monkeypatch.setattr(sys, "platform", "linux")
        calls: list[list[str]] = []

        def _fake_run(cmd, *a, **k):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, b"", b"target is busy")

        monkeypatch.setattr(live_manager.subprocess, "run", _fake_run)

        assert _unmount_partitions("/dev/fakesda") is False, (
            "_unmount_partitions reported success while the device is still mounted; "
            "the caller would then write the ISO over live data"
        )
        assert calls, "it never even attempted the unmount"

    def test_a_successful_unmount_reports_success(self, tmp_path, monkeypatch):
        """The other direction: a device genuinely absent from the table is clean."""
        from s0.live import live_manager
        from s0.live.live_manager import _unmount_partitions

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            live_manager,
            "MOUNTS_PATH",
            str(_synthetic_mounts(tmp_path, ["tmpfs /run tmpfs rw 0 0"])),
        )
        monkeypatch.setattr(
            live_manager.subprocess,
            "run",
            lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, b"", b""),
        )

        assert _unmount_partitions("/dev/fakesda") is True

    def test_a_missing_mount_table_is_not_read_as_success(self, tmp_path, monkeypatch):
        """If we cannot tell whether it is mounted, we must not say "go ahead"."""
        from s0.live import live_manager
        from s0.live.live_manager import _unmount_partitions

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(live_manager, "MOUNTS_PATH", str(tmp_path / "absent"))
        monkeypatch.setattr(
            live_manager.subprocess,
            "run",
            lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, b"", b""),
        )

        # With no mount table the safest reading is "cannot confirm it is safe".
        assert _unmount_partitions("/dev/fakesda") is False

    def test_the_caller_refuses_rather_than_proceeding(self):
        """Reading the code: the return value must gate the write, not be ignored."""
        source = (REPO_ROOT / "src" / "s0" / "live" / "live_manager.py").read_text(encoding="utf-8")
        assert "if not _unmount_partitions(" in source, (
            "cmd_live_flash no longer checks whether the unmount succeeded"
        )
        idx_call = source.index("if not _unmount_partitions(")
        idx_write = source.index("Writing {iso_path.name} to {write_target}", idx_call)
        assert idx_call < idx_write, "the unmount check must come before the write"
        assert source.count("_unmount_partitions(matched_device") == 1, (
            "the unmount result is being called in more than one place; one of them may be ignoring it"
        )


class TestKeygenWillNotReplaceAKey:
    def test_a_second_keygen_refuses_and_leaves_the_key_alone(self, tmp_path):
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        first = subprocess.run(
            [entry, "keygen"], capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=300
        )
        assert first.returncode == 0, first.stderr[-400:]
        key = tmp_path / "operator_key_private.pem"
        before = key.read_bytes()

        second = subprocess.run(
            [entry, "keygen"], capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=300
        )
        assert second.returncode != 0, (
            "a second keygen exited 0 and silently replaced the private key; every "
            "certificate already signed with it is now unattributable"
        )
        assert key.read_bytes() == before, "the existing private key was modified"
        assert "refusing to overwrite" in second.stderr, second.stderr[-300:]

    def test_force_replaces_it_and_says_so(self, tmp_path):
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        subprocess.run(
            [entry, "keygen"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
            check=True,
        )
        key = tmp_path / "operator_key_private.pem"
        before = key.read_bytes()
        forced = subprocess.run(
            [entry, "keygen", "--force"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
        )
        assert forced.returncode == 0, forced.stderr[-400:]
        assert key.read_bytes() != before, "--force did not replace the key"
        combined = forced.stdout + forced.stderr
        assert "replacing" in combined.lower(), "--force replaced the key without saying so"

    def test_the_new_key_is_still_usable(self, tmp_path):
        """A refusal must not leave the existing pair broken."""
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        subprocess.run(
            [entry, "keygen"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
            check=True,
        )
        subprocess.run(
            [entry, "keygen"], capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=300
        )
        from s0.crypto import load_private_pem, load_public_pem, public_key_fingerprint

        priv = load_private_pem(tmp_path / "operator_key_private.pem")
        pub = load_public_pem(tmp_path / "operator_key_public.pem")
        assert public_key_fingerprint(priv.public_key()) == public_key_fingerprint(pub)


class TestKeygenNameIsAFilename:
    @pytest.mark.parametrize(
        "name",
        [
            "../escape",
            "..",
            ".",
            "",
            "/tmp/abs",
            "a/b",
            "sub\\win",
            "-leading",
            ".hidden",
            "with\nnewline",
            "with\x1b[31m",
        ],
        ids=[
            "parent",
            "dotdot",
            "dot",
            "empty",
            "absolute",
            "slash",
            "backslash",
            "leading-dash",
            "leading-dot",
            "newline",
            "escape",
        ],
    )
    def test_a_name_that_is_a_path_is_refused(self, tmp_path, name):
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        proc = subprocess.run(
            [entry, "keygen", "--out-dir", str(tmp_path / "out"), "--name", name],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
        )
        assert proc.returncode != 0, f"--name {name!r} was accepted"
        # Two layers refuse these. argparse rejects a leading dash (it reads the value
        # as another flag) and an embedded NUL (argv cannot carry one) before any s0
        # code runs; the rest are caught by the filename check. Either refusal is
        # correct -- what matters is that nothing is written.
        assert (
            "invalid --name" in proc.stderr
            or "usage:" in proc.stderr
            or "expected one argument" in proc.stderr
        ), proc.stderr[-300:]
        assert not list(tmp_path.glob("*.pem")), f"--name {name!r} wrote a keypair anyway"

    def test_nothing_is_written_outside_the_output_directory(self, tmp_path):
        """The reported impact: `*_private.pem` created, or overwritten, elsewhere."""
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        out = tmp_path / "out"
        out.mkdir()
        # A pre-existing private key one level up, which `--name ../escape` would hit.
        victim = tmp_path / "escape_private.pem"
        victim.write_text("PRECIOUS")

        subprocess.run(
            [entry, "keygen", "--out-dir", str(out), "--name", "../escape"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
        )
        assert victim.read_text() == "PRECIOUS", "keygen overwrote a private key outside --out-dir"
        assert sorted(p.name for p in tmp_path.glob("*.pem")) == ["escape_private.pem"]

    @pytest.mark.parametrize("name", ["operator_key", "lab-2024", "Lab_Key", "k"])
    def test_ordinary_names_still_work(self, tmp_path, name):
        entry = _entry()
        env = {**os.environ, "HOME": str(tmp_path)}
        proc = subprocess.run(
            [entry, "keygen", "--out-dir", str(tmp_path / "out"), "--name", name],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
            timeout=300,
        )
        assert proc.returncode == 0, f"--name {name!r} was refused: {proc.stderr[-300:]}"
        assert (tmp_path / "out" / f"{name}_private.pem").is_file()
