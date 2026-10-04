"""Workflow dependencies must be immutable, and the pins must be real.

A GitHub Action pinned to a tag is not pinned. `uses: actions/checkout@v4` runs
whatever `v4` points at today, and whoever controls that repository can move it --
including to code that does something else entirely. This workflow runs on every
push and, in `release.yml`, holds `contents: write`.

So every action is pinned to a 40-character commit SHA, with the human-readable
version kept in a trailing comment. The comment matters: an unexplained SHA is
unreviewable, and a pin nobody can interpret does not get updated.

Two things are asserted. That no reference is mutable, and that each pinned SHA is
actually 40 hex characters -- which catches the common failure of pasting a tag into
the position a SHA is expected.

These tests do not contact GitHub. A test that needed the network would be skipped
in exactly the environment where a bad pin hurts most. The SHAs were verified against
the API when they were written; what is enforced here is the *shape*, so nobody adds
`@latest` back.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))

#: Anything that resolves to "whatever is newest" at run time.
MUTABLE = re.compile(r"@(?:master|main|latest|v\d+\.\d+\.\d+|v\d+|HEAD)\s*$")

USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)\s*(?:#\s*(.*))?$")

SHA = re.compile(r"^[0-9a-f]{40}$")


def _references() -> list[tuple[Path, int, str, str]]:
    out = []
    for path in WORKFLOWS:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if match:
                out.append((path, lineno, match.group(1), match.group(2) or ""))
    return out


class TestEveryReferenceIsImmutable:
    def test_the_corpus_is_not_empty(self):
        """Guard the guard: no references found would pass everything below."""
        refs = _references()
        assert len(refs) >= 8, (
            f"only {len(refs)} action references found; the regex probably stopped "
            f"matching the file format, which would make this file vacuous")

    def test_no_reference_is_a_mutable_ref(self):
        offenders = [f"{p.relative_to(REPO_ROOT)}:{n}: {ref}"
                     for p, n, ref, _c in _references() if MUTABLE.search(ref)]
        assert not offenders, (
            f"these action references are mutable: {offenders}. A tag or branch can "
            f"be moved to new code by whoever controls the repository, and this "
            f"workflow runs with write permissions on release.")

    def test_no_docker_image_reference_remains(self):
        """`docker://image:tag` is mutable too, and easy to reintroduce."""
        offenders = [f"{p.relative_to(REPO_ROOT)}:{n}: {ref}"
                     for p, n, ref, _c in _references() if ref.startswith("docker://")]
        assert not offenders, (
            f"these reference a mutable container image: {offenders}. Pin to a digest "
            f"(image@sha256:...) or use a SHA-pinned action.")

    @pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
    def test_every_sha_is_a_full_commit_hash(self, path):
        offenders = []
        for lineno, ref, _comment in ((n, r, c) for p, n, r, c in _references()
                                      if p == path):
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if "@" not in ref:
                offenders.append(f"{path.name}:{lineno}: {ref} has no ref at all")
                continue
            sha = ref.rsplit("@", 1)[1]
            if not SHA.match(sha):
                offenders.append(
                    f"{path.name}:{lineno}: {ref} is not a 40-character commit SHA")
        assert not offenders, offenders


class TestThePinsRemainReviewable:
    def test_every_pin_records_the_version_it_corresponds_to(self):
        """An unexplained SHA cannot be reviewed, so it does not get updated."""
        offenders = []
        for path, lineno, ref, comment in _references():
            if ref.startswith("docker://") or "@" not in ref:
                continue
            sha = ref.rsplit("@", 1)[1]
            if SHA.match(sha) and not comment.strip():
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {ref}")
        assert not offenders, (
            f"these pins have no trailing version comment: {offenders}. A bare SHA "
            f"is unreviewable and will not be maintained.")

    def test_the_same_action_is_always_pinned_to_the_same_sha(self):
        """Two refs to one action at different SHAs means a partial, unexplained bump."""
        by_action: dict[str, set[str]] = {}
        for _p, _n, ref, _c in _references():
            if "@" not in ref:
                continue
            name, sha = ref.rsplit("@", 1)
            if SHA.match(sha):
                by_action.setdefault(name, set()).add(sha)

        split = {name: sorted(shas) for name, shas in by_action.items() if len(shas) > 1}
        assert not split, (
            f"these actions are pinned to more than one SHA, so a bump was applied "
            f"in some places and not others: {split}")

    def test_pins_are_actually_pinned_not_freshly_added_as_tags(self):
        """Catches a plausible-looking ref that is a tag in SHA position."""
        for path, lineno, ref, _c in _references():
            if "@" not in ref or ref.startswith("docker://"):
                continue
            sha = ref.rsplit("@", 1)[1]
            assert not re.fullmatch(r"v[\w.]+", sha), (
                f"{path.relative_to(REPO_ROOT)}:{lineno}: {ref} looks like a version "
                f"tag, not a commit")


class TestDependabotKeepsThemCurrent:
    def test_a_dependabot_config_exists_for_github_actions(self):
        """A pin that nothing updates becomes a vulnerability with a long shelf life."""
        config = REPO_ROOT / ".github" / "dependabot.yml"
        assert config.is_file(), (
            "dependabot.yml is missing, so the SHA pins will never be refreshed. "
            "Pinning without an updater trades a mutable-ref risk for a stale-action "
            "risk.")
        text = config.read_text()
        # For the github-actions ecosystem the directory is the repository root, not
        # /.github/workflows -- dependabot reads the workflow files itself. The value
        # may be quoted or bare in the YAML, so match either.
        assert re.search(r'package-ecosystem:\s*["\']?github-actions["\']?\s*\n'
                         r'\s*directory:\s*["\']?/["\']?', text), (
            "dependabot is not configured for github-actions against the repository "
            "root, so none of these SHA pins will ever be refreshed")
