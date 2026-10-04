"""The skill's generated references must match the tool they describe.

The carving reference used to carry a hand-written table of "10 magic-byte
signatures" while the tool had 62 across 51 extensions. A duplicated table
drifts, and the drift is invisible because the reference reads perfectly well.

Generating it from the live source fixes the cause; this test stops it coming
back.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GENERATOR = REPO / "tools" / "gen_carving_reference.py"
REFERENCE = REPO / "skills" / "s0-forensics" / "references" / "carving-signatures.md"


def test_the_carving_reference_is_in_sync():
    r = subprocess.run([sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, (
        f"{REFERENCE.name} is out of date with the signature table.\n"
        f"run: python tools/gen_carving_reference.py\n{r.stdout}{r.stderr}"
    )


def test_the_reference_does_not_understate_the_tool():
    """The specific regression: the reference claimed 10 signatures."""
    from s0.carve.signatures import SIGNATURES

    text = REFERENCE.read_text(encoding="utf-8")
    assert f"{len(SIGNATURES)} signatures" in text, (
        "the reference's headline signature count does not match the table"
    )


def test_every_extension_in_the_table_appears_in_the_reference():
    from s0.carve.signatures import SIGNATURES

    text = REFERENCE.read_text(encoding="utf-8")
    missing = sorted({s.extension.lower() for s in SIGNATURES if f"`{s.extension.lower()}`" not in text})
    assert not missing, f"extensions absent from the reference: {missing}"


def test_the_unresolved_extensions_are_named():
    """An agent must be able to see which formats have no derived length."""
    from s0.carve import boundary
    from s0.carve.signatures import SIGNATURES

    text = REFERENCE.read_text(encoding="utf-8")
    section = text.split("Extensions without a structural boundary rule")[-1]
    unresolved = sorted(
        {s.extension.lower() for s in SIGNATURES if not boundary.has_boundary_rule(s.extension.lower())}
    )
    for ext in unresolved:
        assert f"`{ext}`" in section, f"{ext} has no boundary rule but is not listed"


def test_the_skill_states_the_sampling_bound_rather_than_the_sample_count():
    """The 64-block claim was arithmetically inadequate and an agent would
    have relayed it as sufficient."""
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "residual_fraction_upper_bound_ppm" in skill
    assert "4.5%" in skill, "the bound for 64 samples should be stated"
    assert "64 post-wipe verification blocks with 0 non-zero hits" not in skill, (
        "the sample count is still presented as the evidence"
    )


def test_the_skill_cites_the_current_nist_revision():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "Rev. 2" in skill
    assert "Rev. 1" not in skill and "Rev.1" not in skill


def test_the_skill_documents_the_new_capabilities():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    for term in (
        "--hash-set",
        "--bodyfile",
        "--gaps-bodyfile",
        "--session",
        "Matroska",
        "mfhd",
        "Cluster.Timestamp",
    ):
        assert term in skill, f"{term} is not documented in the skill"


def test_the_skill_warns_that_refusals_are_correct():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "Refusals Are Correct" in skill
    assert "Do Not Work Around" in skill or "do not" in skill.lower()


# --------------------------------------------------------------------------- #
# The published docs (GitBook renders docs/ verbatim) must not drift either.
#
# The first pass of this test only read SKILL.md, so it passed while
# docs/compliance/nist-compliance.md still said "Revision 1" in a file whose own
# heading said Rev. 2, and docs/guides/cli-reference.md still carried the exact
# "full Clear sanitization" overclaim that had been removed from the skill. A
# guard that reads one file proves nothing about the other twenty-eight.
# --------------------------------------------------------------------------- #

DOC_ROOTS = (REPO / "docs", REPO / "skills")


def _markdown_docs() -> list[Path]:
    out: list[Path] = []
    for root in DOC_ROOTS:
        if root.is_dir():
            out.extend(p for p in root.rglob("*.md") if "__pycache__" not in p.parts)
    out.append(REPO / "README.md")
    return out


def test_every_published_doc_cites_the_current_nist_revision():
    """Rev. 1 references are stale except where the text is *about* Rev. 1.

    A historical comparison ("Rev. 1 withdrew...") is legitimate; a page
    asserting Rev. 1 is the current standard is not.
    """
    offenders: list[str] = []
    for path in _markdown_docs():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "Rev. 1" not in line and "Revision 1" not in line:
                continue
            # Allowed only when the sentence is explicitly historical.
            historical = any(
                token in line
                for token in (
                    "withdrew",
                    "withdrawn",
                    "replaced",
                    "superseded",
                    "used to",
                    "previously",
                    "older",
                    "Rev. 1's",
                    "moved from",
                    "revised to",
                    "was",
                )
            )
            if not historical:
                offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line.strip()[:90]}")
    assert not offenders, "These docs still cite NIST SP 800-88 Rev. 1 as current:\n  " + "\n  ".join(
        offenders
    )


def test_no_doc_makes_a_whole_media_erasure_guarantee():
    """The overclaim that was removed from the skill must not reappear anywhere.

    s0 verifies by sampling. A zero readback proves the sampled blocks were
    zeroed; it does not prove the medium is blank, and saying "fully sufficient
    to achieve Clear sanitization" on the strength of a sample is the specific
    overstatement that makes a report indefensible.
    """
    banned = (
        "fully sufficient to achieve clear",
        "is clear sanitization",
        "full clear sanitization",
        "guarantees the medium is blank",
        "proves the entire drive is erased",
    )
    offenders: list[str] = []
    for path in _markdown_docs():
        text = path.read_text(encoding="utf-8").lower()
        for phrase in banned:
            if phrase in text:
                lineno = next((i for i, line in enumerate(text.splitlines(), 1) if phrase in line), 0)
                offenders.append(f"{path.relative_to(REPO)}:{lineno}: ...{phrase}...")
    assert not offenders, (
        "Whole-media erasure guarantees found; state the sampling bound instead:\n  " + "\n  ".join(offenders)
    )


def test_docs_changelog_records_the_current_version():
    """The GitBook changelog page must reach at least the current version.

    It is a separate page from the root CHANGELOG.md, so it drifts silently. The
    released versions are all present; what goes missing is the unreleased work.
    """
    changelog = (REPO / "docs" / "project" / "changelog.md").read_text(encoding="utf-8")
    version = json.loads((REPO / "s0_config.json").read_text(encoding="utf-8"))["version"]
    assert f"[{version}]" in changelog or "[Unreleased]" in changelog, (
        f"docs/project/changelog.md does not mention {version} and has no "
        f"Unreleased section, so it predates current work."
    )


def test_help_screens_state_the_sampling_bound():
    """`--verify-samples` must say what sampling does and does not establish.

    A user reading "number of readback samples to verify (default: 64)" would
    reasonably conclude the medium was verified. It was not.
    """
    main = (REPO / "src" / "s0" / "cli" / "main.py").read_text(encoding="utf-8")
    assert "45,730" in main, (
        "--verify-samples help must state the residual bound (≈45,730 ppm at 95% "
        "confidence for the default 64 blocks), not just the sample count."
    )
    assert "number of readback samples to verify (default: 64)" not in main, (
        "the old --verify-samples help implied full verification; it should describe the bound instead."
    )


def test_certificate_spec_documents_the_attestation_fields():
    """The certificate spec is the verifier's contract; it must match the schema.

    It documented a verification block with four fields while `cert_schema.json`
    requires five more, so anyone implementing a verifier from the spec would have
    produced one that rejected every current certificate.
    """
    spec = (REPO / "docs" / "architecture" / "certificate-spec.md").read_text(encoding="utf-8")
    schema = json.loads((REPO / "src" / "s0" / "data" / "cert_schema.json").read_text(encoding="utf-8"))
    verification = schema["properties"]["result"]["properties"]["verification"]
    missing = [name for name in verification["properties"] if name not in spec]
    assert not missing, (
        "docs/architecture/certificate-spec.md omits schema fields, so a verifier "
        f"built from it would reject valid certificates: {missing}"
    )


def test_user_guide_format_table_is_generated_not_handwritten():
    """The carving guide must not carry a second, hand-kept format list.

    It used to: 16 hand-written rows against 62 live signatures, which silently
    omitted mp4, mkv, rar, bz2, xz, zst, lz4, aiff, mid, tiff, jp2, class and rtf
    from the page a user reads to find out what s0 can carve.
    """
    guide = (REPO / "docs" / "guides" / "forensic-carving.md").read_text(encoding="utf-8")
    assert "<!-- BEGIN GENERATED FORMAT TABLE -->" in guide, (
        "the format table must be generated by tools/gen_carving_reference.py so it "
        "cannot drift from the live signature registry"
    )
    rows = [line for line in guide.splitlines() if line.startswith("| `")]
    assert len(rows) >= 50, (
        f"the guide lists only {len(rows)} formats; the registry has far more. "
        "Re-run tools/gen_carving_reference.py."
    )
