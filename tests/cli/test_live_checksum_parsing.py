"""A checksum file must be parsed as a checksum file.

Every way this went wrong ended the same way: a **correct** download was deleted.

**The dedicated `.sha256` asset was read with `text.split()[0]`** -- the first
whitespace-separated token of the whole body. When a request is rate-limited or
redirected, the body is an HTML error page, so the "expected hash" became
`<!DOCTYPE` and every subsequent run reported a checksum mismatch and removed the
ISO it had just downloaded correctly.

**`SHA256SUMS.txt` was scanned for the first line merely *containing* the ISO name.**
With several artefacts in one file, a substring match hits the wrong line. A release
containing `s0-live-amd64.iso.sha256` alongside `s0-live-amd64.iso` matches the
checksum-of-the-checksum first, and that file's hash is then used to condemn the ISO.

**Nothing checked the result was a hash at all.**

So the format is parsed as the format it is: one line per artefact, `<64 hex>  <name>`,
with exact basename matching and a shape check on the digest. Anything unparseable
returns None, which the caller already treats as "no checksum available" -- so the
failure mode is "I could not verify this", which is honest, rather than "this is
wrong", which is not.

This is integrity, not authenticity. The digests come from the same GitHub release
as the ISO, so a compromised release can supply a matching pair. That is a separate
problem and it is not solved by a better parser.
"""

from __future__ import annotations

import pytest

from s0.live.live_manager import _parse_sha256_document, _parse_sha256_sums

ISO = "s0-live-amd64.iso"
GOOD = "a" * 64


class TestTheDedicatedChecksumAsset:
    def test_a_bare_digest_is_accepted(self):
        assert _parse_sha256_document(GOOD, ISO) == GOOD

    def test_a_bare_digest_with_whitespace_is_accepted(self):
        assert _parse_sha256_document(f"  {GOOD}\n", ISO) == GOOD

    def test_a_sha256sum_line_is_accepted(self):
        assert _parse_sha256_document(f"{GOOD}  {ISO}", ISO) == GOOD

    def test_the_binary_mode_star_form_is_accepted(self):
        """`sha256sum -b` writes `<hash> *<name>`; both forms are real."""
        assert _parse_sha256_document(f"{GOOD} *{ISO}", ISO) == GOOD

    def test_a_dot_slash_prefix_is_tolerated(self):
        assert _parse_sha256_document(f"{GOOD}  ./{ISO}", ISO) == GOOD

    @pytest.mark.parametrize(
        "body",
        [
            "<!DOCTYPE html><html><body>rate limit exceeded</body></html>",
            "Not Found",
            "",
            "   \n\n",
            "404: Not Found",
            '{"error": "too many requests"}',
        ],
    )
    def test_an_error_page_yields_no_hash(self, body):
        """The reported defect: the first token became the expected hash."""
        assert _parse_sha256_document(body, ISO) is None, (
            f"an error page produced a hash from {body!r}. The caller then reported "
            f"a mismatch and deleted a correctly downloaded ISO."
        )

    def test_a_truncated_digest_is_rejected(self):
        assert _parse_sha256_document(GOOD[:63], ISO) is None

    def test_a_non_hex_digest_is_rejected(self):
        assert _parse_sha256_document("z" * 64, ISO) is None

    @pytest.mark.parametrize(
        "junk", ["garbage", "sha256:abc", "<hash>", "0x1234", "e3b0c44298fc1c149afbf4c8996fb924"]
    )
    def test_a_matching_name_with_a_junk_digest_is_rejected(self, junk):
        """The name matches but the digest does not.

        The only case where the shape check is load-bearing rather than masked by
        the name comparison: everything else is rejected earlier for having the
        wrong filename. Accepting the line here would condemn every future download
        with a mismatch against a value that was never a hash.
        """
        assert _parse_sha256_document(f"{junk}  {ISO}", ISO) is None
        assert _parse_sha256_sums(f"{junk}  {ISO}", ISO) is None

    def test_a_valid_line_after_a_junk_one_is_still_found(self):
        """A junk entry must not stop the scan."""
        sums = f"garbage  {ISO}\n{GOOD}  {ISO}\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_uppercase_hex_is_normalised(self):
        assert _parse_sha256_document("A" * 64, ISO) == GOOD


class TestTheSumsFileMatchesExactly:
    def test_the_right_line_is_found(self):
        sums = f"{GOOD}  {ISO}\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_a_checksum_of_the_checksum_does_not_win(self):
        """The reported defect, constructed exactly.

        `iso_name in line` matches `s0-live-amd64.iso.sha256` before
        `s0-live-amd64.iso`, because the former contains the latter as a substring.
        The wrong digest is then used to condemn a correct download.
        """
        other = "b" * 64
        sums = "\n".join(
            [
                f"{other}  {ISO}.sha256",  # decoy, listed FIRST
                f"{GOOD}  {ISO}",
                f"{'c' * 64}  {ISO}.zsync",  # another decoy
            ]
        )
        assert _parse_sha256_sums(sums, ISO) == GOOD, "a substring match picked another artefact's digest"

    def test_a_prefix_sharing_name_does_not_match(self):
        other = "d" * 64
        sums = f"{other}  {ISO}-signed.iso\n{GOOD}  {ISO}\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_absent_from_the_file_means_no_hash_not_a_wrong_one(self):
        """Fail closed as 'unverified', which is honest."""
        assert _parse_sha256_sums(f"{'e' * 64}  completely-other.iso", ISO) is None

    def test_an_empty_sums_file_yields_nothing(self):
        assert _parse_sha256_sums("", ISO) is None

    def test_a_realistic_multi_artefact_release_resolves(self):
        sums = "\n".join(
            [
                "# sha256sums for the release",
                f"{'1' * 64}  s0_2.4.4_amd64.iso",
                f"{'2' * 64}  s0-live-amd64.iso.zsync",
                f"{GOOD}  {ISO}",
                f"{'3' * 64}  SHA256SUMS.txt",
            ]
        )
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_comments_and_blank_lines_are_skipped(self):
        sums = f"# a comment\n\n   \n{GOOD}  {ISO}\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_crlf_line_endings_are_handled(self):
        """A file written on Windows is the normal case, not an edge case."""
        sums = f"# sums\r\n{GOOD}  {ISO}\r\n{'b' * 64}  other.iso\r\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD

    def test_a_sums_line_with_only_one_field_is_skipped(self):
        """`<hash>` alone carries no filename, so it cannot be attributed."""
        sums = f"{'b' * 64}\n{GOOD}  {ISO}\n"
        assert _parse_sha256_sums(sums, ISO) == GOOD


class TestWhatThisDoesNotClaim:
    def test_the_docstring_states_that_this_is_integrity_not_authenticity(self):
        """A better parser does not make a compromised release detectable.

        The digests come from the same host as the artefact, so anyone who can
        replace the ISO can replace the checksum. Saying so here is the point: the
        temptation is to read "verified" as "authentic".
        """
        import inspect

        doc = inspect.getdoc(_parse_sha256_document) or ""
        assert "authentic" in doc.lower(), (
            "the parser's docstring does not distinguish integrity from "
            "authenticity, so a caller may read 'verified' as 'trustworthy'"
        )
