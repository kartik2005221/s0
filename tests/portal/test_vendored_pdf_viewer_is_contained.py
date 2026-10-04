"""The vendored PDF viewer must not be able to execute script from a document.

The portal renders a certificate PDF so its embedded QR code can be decoded
offline. It serves pdf.js 3.11.174, which is inside the range affected by
CVE-2024-4367: a crafted font achieves arbitrary JavaScript execution through the
font evaluator, which reaches `eval`.

That is worse here than it would be in most deployments, because `/portal` is
served from the **same origin as the dashboard's destructive API**. Script execution
inside the PDF viewer is therefore script execution able to reach
`/api/erase-files`. The mitigation that exists -- neither CSP permits
`'unsafe-eval'` -- only holds in browsers that enforce CSP, and it is a single
missing keyword away from not holding at all.

Upgrading pdf.js is the real fix and is deliberately not done here: it is a
hash-pinned vendoring step, and swapping the file out from under the manifest would
break the pinning that makes re-vendoring auditable. So the eval path is removed at
the only call site with `isEvalSupported: false`, which makes the advisory's
mechanism unavailable on this version. A font that genuinely needs the evaluator now
fails to render instead of running, which is the right trade for a certificate
viewer.

These tests pin both halves: the flag stays set, and the affected version is
recorded as affected rather than quietly left looking fine.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PORTAL_JS = REPO_ROOT / "site" / "verify" / "js" / "portal.js"
MANIFEST = REPO_ROOT / "site" / "verify" / "vendor" / "manifest.json"
PDF_MIN = REPO_ROOT / "site" / "verify" / "vendor" / "pdf.min.js"


class TestTheEvalPathIsClosed:
    def test_every_getdocument_call_disables_eval(self):
        source = PORTAL_JS.read_text(encoding="utf-8")
        calls = list(re.finditer(r"getDocument\s*\(\s*\{", source))
        assert calls, "no getDocument call found; the check below would be vacuous"

        for match in calls:
            # Take the object literal that follows, up to its closing brace.
            depth = 0
            end = match.end()
            for i in range(match.end() - 1, min(len(source), match.end() + 2000)):
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            block = source[match.start():end]
            assert "isEvalSupported" in block, (
                "a getDocument call does not set isEvalSupported. Without it pdf.js "
                "may use eval to interpret fonts, which is the mechanism "
                "CVE-2024-4367 uses to execute script from a crafted document.")
            assert re.search(r"isEvalSupported\s*:\s*false", block), (
                "isEvalSupported is present but not false; the eval path is still "
                "available.")

    def test_the_flag_is_documented_where_it_is_set(self):
        source = PORTAL_JS.read_text(encoding="utf-8")
        index = source.index("isEvalSupported")
        preceding = source[max(0, index - 900):index]
        assert "CVE-2024-4367" in preceding, (
            "the mitigation is set without saying what it mitigates, so the next "
            "person to tidy this file has no idea it is load-bearing")


class TestTheAffectedVersionIsRecorded:
    def test_the_manifest_names_the_advisory(self):
        manifest = json.loads(MANIFEST.read_text())
        entry = next(f for f in manifest["files"] if f["path"] == "vendor/pdf.min.js")
        advisories = entry.get("known_advisories")
        assert advisories, (
            f"pdf.js {entry['version']} carries no recorded advisory. If it has been "
            f"upgraded, say so here rather than deleting the field -- an absent "
            f"field reads as 'checked, nothing found'.")
        ids = {a["id"] for a in advisories}
        assert "CVE-2024-4367" in ids, (
            f"the recorded advisories are {ids}; CVE-2024-4367 is the one that "
            f"applies to this file")

    def test_the_advisory_states_its_mitigation_and_residual_risk(self):
        manifest = json.loads(MANIFEST.read_text())
        entry = next(f for f in manifest["files"] if f["path"] == "vendor/pdf.min.js")
        advisory = next(a for a in entry["known_advisories"] if a["id"] == "CVE-2024-4367")
        for field in ("affects", "impact", "mitigation", "risk_if_mitigation_removed"):
            assert advisory.get(field), f"the advisory omits {field!r}"
        assert "isEvalSupported" in advisory["mitigation"], (
            "the recorded mitigation does not name the mechanism, so a reader "
            "cannot tell whether it still holds")

    def test_the_recorded_version_matches_the_vendored_file(self):
        """The manifest's version claim must be about the file that actually ships."""
        manifest = json.loads(MANIFEST.read_text())
        entry = next(f for f in manifest["files"] if f["path"] == "vendor/pdf.min.js")
        text = PDF_MIN.read_text(encoding="utf-8", errors="ignore")
        found = re.search(r'version["\':=\s]{1,4}([0-9]+\.[0-9]+\.[0-9]+)', text)
        assert found, "could not determine the vendored pdf.js version"
        assert found.group(1) == entry["version"], (
            f"the manifest says pdf.js {entry['version']} but the file says "
            f"{found.group(1)}. One of them is lying, and the advisory status "
            f"depends on which.")


class TestTheVendorPinningStillHolds:
    """Re-vendoring is hash-pinned; the mitigation must not have disturbed it."""

    def test_the_pdf_hash_still_matches_the_manifest(self):
        import hashlib

        manifest = json.loads(MANIFEST.read_text())
        entry = next(f for f in manifest["files"] if f["path"] == "vendor/pdf.min.js")
        digest = hashlib.sha256(PDF_MIN.read_bytes()).hexdigest()
        assert digest == entry["sha256"], (
            "vendor/pdf.min.js does not match its recorded sha256. Re-vendoring "
            "must go through the manifest so the change is auditable.")

    def test_no_unpinned_script_tags_were_introduced(self):
        """The mitigation must not have added a remote script."""
        source = PORTAL_JS.read_text(encoding="utf-8")
        for match in re.finditer(r"<script[^>]*src=[\"']([^\"']+)[\"']", source):
            url = match.group(1)
            assert url.startswith(("vendor/", "./", "/verify/vendor/")), (
                f"portal.js loads a script from {url!r}. The PDF viewer must not "
                f"gain a remote dependency, least of all while carrying a known "
                f"advisory that depends on what code is reachable.")
