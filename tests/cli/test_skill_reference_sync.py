"""The skill's generated references must match the tool they describe.

The carving reference used to carry a hand-written table of "10 magic-byte
signatures" while the tool had 62 across 51 extensions. A duplicated table
drifts, and the drift is invisible because the reference reads perfectly well.

Generating it from the live source fixes the cause; this test stops it coming
back.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GENERATOR = REPO / "tools" / "gen_carving_reference.py"
REFERENCE = REPO / "skills" / "s0-forensics" / "references" / "carving-signatures.md"


def test_the_carving_reference_is_in_sync():
    r = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, (
        f"{REFERENCE.name} is out of date with the signature table.\n"
        f"run: python tools/gen_carving_reference.py\n{r.stdout}{r.stderr}")


def test_the_reference_does_not_understate_the_tool():
    """The specific regression: the reference claimed 10 signatures."""
    from s0.carve.signatures import SIGNATURES
    text = REFERENCE.read_text(encoding="utf-8")
    assert f"{len(SIGNATURES)} signatures" in text, (
        "the reference's headline signature count does not match the table")


def test_every_extension_in_the_table_appears_in_the_reference():
    from s0.carve.signatures import SIGNATURES
    text = REFERENCE.read_text(encoding="utf-8")
    missing = sorted({s.extension.lower() for s in SIGNATURES
                      if f"`{s.extension.lower()}`" not in text})
    assert not missing, f"extensions absent from the reference: {missing}"


def test_the_unresolved_extensions_are_named():
    """An agent must be able to see which formats have no derived length."""
    from s0.carve import boundary
    from s0.carve.signatures import SIGNATURES
    text = REFERENCE.read_text(encoding="utf-8")
    section = text.split("Extensions without a structural boundary rule")[-1]
    unresolved = sorted({s.extension.lower() for s in SIGNATURES
                         if not boundary.has_boundary_rule(s.extension.lower())})
    for ext in unresolved:
        assert f"`{ext}`" in section, f"{ext} has no boundary rule but is not listed"


def test_the_skill_states_the_sampling_bound_rather_than_the_sample_count():
    """The 64-block claim was arithmetically inadequate and an agent would
    have relayed it as sufficient."""
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "residual_fraction_upper_bound_ppm" in skill
    assert "4.5%" in skill, "the bound for 64 samples should be stated"
    assert "64 post-wipe verification blocks with 0 non-zero hits" not in skill, \
        "the sample count is still presented as the evidence"


def test_the_skill_cites_the_current_nist_revision():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "Rev. 2" in skill
    assert "Rev. 1" not in skill and "Rev.1" not in skill


def test_the_skill_documents_the_new_capabilities():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    for term in ("--hash-set", "--bodyfile", "--gaps-bodyfile", "--session",
                 "Matroska", "mfhd", "Cluster.Timestamp"):
        assert term in skill, f"{term} is not documented in the skill"


def test_the_skill_warns_that_refusals_are_correct():
    skill = (REPO / "skills" / "s0-forensics" / "SKILL.md").read_text(encoding="utf-8")
    assert "Refusals Are Correct" in skill
    assert "Do Not Work Around" in skill or "do not" in skill.lower()
