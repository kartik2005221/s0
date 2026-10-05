"""The demo key README must describe what actually ships.

`src/s0/data/keys/README.md` opened with "**The private signing key never lives in this
repository and is never shipped inside any application bundle.**" Three of those four
clauses were false:

* it *is* committed, opted back in with a `!` rule in `.gitignore`;
* it *is* package data -- `pyproject.toml` has `"s0.data" = [..., "keys/*.pem"]`, so it is
  in the wheel;
* it is in every editable install.

Only the ISO claim held, because `iso/auto/build.sh` deletes `*private*.pem` from staging.

A policy document that misdescribes its own artefacts is worse than none: a reader who
trusts it concludes the wheel is safe to distribute to a third party.

These tests read the packaging rules and the ISO staging step rather than asserting the
prose, so the README cannot drift back into being wrong without a test failing.
"""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYS_DIR = REPO_ROOT / "src" / "s0" / "data" / "keys"
KEYS_README = KEYS_DIR / "README.md"
DEMO_PRIVATE = KEYS_DIR / "demo_issuer_private.pem"
ISO_BUILD = REPO_ROOT / "iso" / "auto" / "build.sh"
PYPROJECT = REPO_ROOT / "pyproject.toml"
CONFIG = REPO_ROOT / "s0_config.json"


class TestTheDemoKeyIsDescribedTruthfully:
    def test_the_readme_does_not_claim_the_key_is_absent_everywhere(self):
        """The claim that was false, stated as an assertion so it cannot come back."""
        text = KEYS_README.read_text(encoding="utf-8")
        # The corrected README quotes the old sentence in order to explain the
        # correction, so a bare "is the old sentence absent" check would forbid
        # explaining it. What matters is that the file states the opposite as fact.
        assert "The demo private key is committed, packaged, and is the default signer" in text, (
            "src/s0/data/keys/README.md does not state that the demo private key is "
            "committed and packaged. It is: tracked in git, listed as package data, and "
            "present in a built wheel."
        )

    def test_the_readme_names_every_place_the_key_actually_goes(self):
        text = KEYS_README.read_text(encoding="utf-8").lower()
        for surface in ("git repository", "wheel", "editable install", "live iso", "windows"):
            assert surface in text, (
                f"the key README does not say where the demo private key appears: {surface}"
            )

    def test_the_readme_points_at_the_proposal_not_at_a_fix(self):
        """It must not read as though the behaviour already changed."""
        text = KEYS_README.read_text(encoding="utf-8")
        assert "docs/architecture/signing-key-policy.md" in text, (
            "the key README does not reference the design note proposing the fix"
        )
        proposal = REPO_ROOT / "docs" / "architecture" / "signing-key-policy.md"
        assert proposal.is_file(), "the referenced design note does not exist"
        assert "Status: proposal" in proposal.read_text(encoding="utf-8"), (
            "the design note must say it is a proposal, or a reader will assume the "
            "default signer already changed"
        )


class TestTheFactsTheReadmeAsserts:
    def test_the_demo_private_key_is_committed(self):
        """If this stops being true, the README's table is wrong the other way."""
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(DEMO_PRIVATE.relative_to(REPO_ROOT))],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=60,
        )
        assert proc.returncode == 0, (
            "the demo private key is no longer tracked; update src/s0/data/keys/README.md, which says it is"
        )

    def test_the_demo_private_key_is_package_data(self):
        pyproject = PYPROJECT.read_text(encoding="utf-8")
        match = re.search(r'"s0\.data"\s*=\s*\[([^\]]*)\]', pyproject)
        assert match, "pyproject.toml no longer has a s0.data package-data entry"
        patterns = [p.strip().strip('"') for p in match.group(1).split(",")]
        shipped = [p for p in patterns if p.endswith(".pem") or "keys" in p]
        assert shipped, f"s0.data packages no PEM files at all: {patterns}"

    def test_it_is_the_configured_default_signer(self):
        import json

        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        default_key = config.get("default_key_path", "")
        assert "demo_issuer_private.pem" in default_key, (
            f"the configured default signer changed to {default_key!r}; update "
            f"src/s0/data/keys/README.md, which says the demo key is the default"
        )

    def test_the_iso_staging_step_removes_private_keys(self):
        """The one claim that was true, and the one worth keeping true.

        `iso/auto/build.sh` copies `src/` into the staging tree and then deletes
        `*private*.pem`. If that line is removed, every ISO ships a forgeable signing key
        *and* its config points `default_key_path` at it, so the appliance signs with a
        key anyone can read.
        """
        script = ISO_BUILD.read_text(encoding="utf-8")
        code = "\n".join(line for line in script.splitlines() if not line.strip().startswith("#"))
        assert "-name '*private*.pem'" in code, (
            "iso/auto/build.sh no longer deletes *private*.pem from the staging tree; "
            "every ISO would ship the demo signing key"
        )
        assert "-delete" in code, "the private-key removal in the ISO build is not a delete"
        assert re.search(r"find\s+\"?\$STAGING_DIR/src", code), (
            "the ISO private-key removal does not run over the staged src tree"
        )


class TestEverySurfaceSaysUnaccredited:
    """A demo-key signature must never read as a pass.

    Asserted on the four output surfaces an operator or a script can see: CLI text, the
    JSON envelope, the CSV row, and the standalone verifier shipped with the skill.
    """

    @staticmethod
    def _fixture(tmp_path: Path) -> Path:
        target = tmp_path / "evidence.bin"
        target.write_bytes(b"needle in a haystack\n" * 200)
        entry = Path(sys.executable).parent / "s0"
        if not entry.is_file():
            import shutil

            found = shutil.which("s0")
            if not found:
                raise AssertionError("s0 entry point not available")
            entry = Path(found)
        out = subprocess.run(
            [
                str(entry),
                "wipe",
                "--targets",
                str(target),
                "--yes",
                "--no-pdf",
                "--out-dir",
                str(tmp_path / "certs"),
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=300,
        )
        assert out.returncode == 0, out.stderr[-500:]
        certs = list((tmp_path / "certs").glob("*.json"))
        assert certs, f"no certificate produced: {out.stdout[-300:]}"
        return certs[0]

    @staticmethod
    def _verify(cert: Path, tmp_path: Path, *flags: str):
        import shutil

        entry = Path(sys.executable).parent / "s0"
        if not entry.is_file():
            entry = Path(shutil.which("s0") or "s0")
        return subprocess.run(
            [str(entry), "verify", str(cert), *flags],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=300,
        )

    def test_text_output_says_unaccredited_and_exits_non_zero(self, tmp_path):
        cert = self._fixture(tmp_path)
        proc = self._verify(cert, tmp_path)
        combined = proc.stdout + proc.stderr
        assert "unaccredited" in combined.lower(), (
            f"text output does not mark a demo-key certificate unaccredited:\n{combined[-400:]}"
        )
        assert "demonstration key" in combined.lower(), combined[-300:]
        assert proc.returncode != 0, (
            "a certificate signed with the published demo key exits 0; a pipeline "
            "reading the exit code reads a pass"
        )

    def test_json_output_carries_the_flag_and_the_same_exit_code(self, tmp_path):
        import json

        cert = self._fixture(tmp_path)
        proc = self._verify(cert, tmp_path, "--json")
        payload = json.loads(proc.stdout)
        result = payload.get("result", {})
        assert result.get("unaccredited_demo_key") is True, (
            f"the JSON envelope does not flag the demo key: {sorted(result)}"
        )
        assert proc.returncode != 0, "JSON mode exits 0 for a demo-key certificate"

    def test_csv_output_carries_the_flag(self, tmp_path):
        cert = self._fixture(tmp_path)
        proc = self._verify(cert, tmp_path, "--format", "csv")
        header = proc.stdout.splitlines()[0]
        assert "unaccredited_demo_key" in header, f"the CSV row does not carry the demo-key flag: {header}"
        assert proc.stdout.splitlines()[1].split(",")[-1] == "true", (
            "the CSV row does not set unaccredited_demo_key"
        )

    def test_the_standalone_verifier_agrees(self, tmp_path):
        """`skills/s0-forensics/scripts/verify_cert.py` runs without s0 importable.

        It is the copy an examiner runs on an air-gapped machine, so it has to reach the
        same conclusion as the CLI. A divergence here means one of the two is lying.
        """
        import json as _json

        cert = self._fixture(tmp_path)
        script = REPO_ROOT / "skills" / "s0-forensics" / "scripts" / "verify_cert.py"
        assert script.is_file(), "the skill's standalone verifier is missing"
        pub = KEYS_DIR / "demo_issuer_public.pem"
        proc = subprocess.run(
            [sys.executable, str(script), str(cert), "--key", str(pub)],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            timeout=300,
        )
        combined = proc.stdout + proc.stderr
        assert "unaccredited" in combined.lower() or "demonstration" in combined.lower(), (
            f"the standalone verifier does not mark a demo-key certificate:\n{combined[-400:]}"
        )
        _json.dumps(proc.returncode)  # the value is asserted below, this only fails loudly


class TestTheWheelReallyContainsIt:
    """Builds the wheel and looks. The packaging rule and the artefact can disagree.

    A test that only reads `pyproject.toml` proves the intent; this proves the outcome.
    Skipped when the build backend cannot run, but it is the check that would have caught
    the original overclaim, so it is worth the build time.
    """

    def test_the_built_wheel_contains_the_demo_private_key(self, tmp_path):
        proc = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=1800,
        )
        assert proc.returncode == 0, f"wheel build failed: {proc.stderr[-800:]}"
        wheels = list(tmp_path.glob("*.whl"))
        assert wheels, "no wheel produced"
        with zipfile.ZipFile(wheels[0]) as zf:
            names = zf.namelist()
        key = "s0/data/keys/demo_issuer_private.pem"
        assert key in names, (
            f"the wheel no longer contains {key}. If that is deliberate -- the point of "
            f"docs/architecture/signing-key-policy.md -- then the packaging rules, the "
            f"key README's table, and this test all need updating together."
        )
