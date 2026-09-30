"""Known-file hash sets, for suppressing files the examiner already has.

Why this exists
---------------
A carve of a large volume returns a great deal that an examiner has already seen:
operating-system files, the applications already installed, the media library
that was there before the incident. Forcing the operator to delete those by hand
is how a report ends up with 4,000 findings and nobody reads any of them.

NSRL-style hash sets have done this job for a decade. What they have not done is
describe *why* something was suppressed, and they are usually in a different
format from what an examiner has to hand.

Design notes
------------
* One hash per payload is enough to decide; several are accepted so an operator
  can hand over whatever list they have.
* Only the algorithms actually present in the set are computed. Hashing a 4 GiB
  candidate with SHA-512 to check a SHA-256 list would be pure waste.
* A match is a *suppression*, not a deletion. The candidate is carved and
  validated exactly as it would have been without a hash set, so its byte range
  and confidence are real; it is then withheld from the output rather than
  written and then removed. Withheld bytes are not counted as recovered, because
  "recovered" has to mean "present in the output" for the manifest to be worth
  anything. What is recorded is the algorithm, the size, and the source of the
  hash set, and each suppression is listed in the rejection summary and counted
  in the recovery index. An examiner can always see what was held back and why;
  a tool that silently drops findings is a tool whose report cannot be trusted.
* Malformed lines are counted and reported rather than ignored, because a hash
  list that silently loaded 40% of its lines is worse than one that refused.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "SuppressionError",
    "SuppressionSet",
    "load_hash_set",
    "load_file_hashes",
    "ALGORITHMS",
]

#: Digest name -> hex length. Used to tell which algorithm a bare line is.
ALGORITHMS: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
}

_HEX = re.compile(r"^[0-9a-fA-F]+$")

#: NSRL and most commercial lists put the algorithm first, then a quoted name and
#: metadata:  SHA-256,"file.txt",1234,2019-01-01T00:00:00
_NSRL_FIELD = re.compile(r"^\s*([A-Za-z0-9-]+)\s*,")


class SuppressionError(ValueError):
    """A hash set that could not be used as given."""


@dataclass
class SuppressionSet:
    """A loaded set of known digests, grouped by algorithm."""

    #: algorithm -> set of lowercase hex digests
    digests: dict[str, set] = field(default_factory=dict)
    source: str = ""
    lines_read: int = 0
    lines_parsed: int = 0
    lines_skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return sum(len(v) for v in self.digests.values())

    @property
    def algorithms(self) -> list[str]:
        return sorted(self.digests)

    def _skip(self, reason: str) -> None:
        self.lines_skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def add_digest(self, algo: str, hexdigest: str) -> bool:
        algo = algo.lower().replace("-", "")
        if algo not in ALGORITHMS:
            self._skip(f"unknown algorithm {algo!r}")
            return False
        if len(hexdigest) != ALGORITHMS[algo]:
            self._skip(f"{algo} digest of the wrong length")
            return False
        self.digests.setdefault(algo, set()).add(hexdigest.lower())
        self.lines_parsed += 1
        return True

    def add_line(self, line: str) -> bool:
        """Parse one line, in any of the shapes these lists come in.

        Accepts a bare digest, ``<algo>,...`` (NSRL and friends), ``<algo> <hex>``
        and ``<hex> <filename>`` as written by ``sha256sum`` and ``md5sum``.
        """
        raw = line.strip()
        if not raw or raw.startswith(("#", ";", "//")):
            return False
        self.lines_read += 1

        # NSRL: algorithm first, then a quoted name and metadata.
        m = _NSRL_FIELD.match(raw)
        if m and m.group(1).lower().replace("-", "") in ALGORITHMS:
            rest = raw[m.end():]
            # The digest is the first quoted field after the algorithm, or the
            # first whitespace-separated token.
            quoted = re.search(r'"([0-9a-fA-F]{32,128})"', rest)
            if quoted:
                return self.add_digest(m.group(1), quoted.group(1))
            token = rest.strip().split(",")[0].strip()
            if _HEX.match(token):
                return self.add_digest(m.group(1), token)
            self._skip("NSRL row with no digest field")
            return False

        # Bare digest, or digest followed by a filename.
        token = raw.split()[0] if raw.split() else raw
        if "," in token and _HEX.match(token.split(",")[0] or "x"):
            token = token.split(",")[0]
        if _HEX.match(token):
            for algo, width in ALGORITHMS.items():
                if len(token) == width:
                    return self.add_digest(algo, token)
            self._skip(f"digest of unrecognised length {len(token)}")
            return False

        self._skip("unparseable line")
        return False

    def match(self, data: bytes) -> str | None:
        """Return the algorithm whose digest of ``data`` is in the set, or None.

        Only the algorithms actually present are computed.
        """
        for algo in self.digests:
            digest = hashlib.new(algo, data).hexdigest()
            if digest in self.digests[algo]:
                return algo
        return None

    def describe(self) -> str:
        parts = [f"{len(self)} digest(s) across {', '.join(self.algorithms)}"]
        if self.source:
            parts.insert(0, self.source)
        if self.lines_skipped:
            worst = sorted(self.skip_reasons.items(), key=lambda kv: -kv[1])[:3]
            parts.append(f"{self.lines_skipped} line(s) skipped ("
                         + ", ".join(f"{n} {why}" for why, n in worst) + ")")
        return "; ".join(parts)


def _normalise_algorithms(algorithms: Iterable[str] | None) -> list[str]:
    """Canonical algorithm names, de-duplicated in first-seen order.

    "SHA-256", "sha256" and "Sha_256" all mean the same algorithm, and a caller
    who writes them inconsistently should not silently get an empty hash set.
    """
    if not algorithms:
        return []
    out: list[str] = []
    for a in algorithms:
        name = a.strip().lower().replace("-", "").replace("_", "")
        if name and name not in out:
            out.append(name)
    return out


def load_file_hashes(path: Path, algorithms: Sequence[str] | None = None,
                     chunk_size: int = 1 << 20) -> SuppressionSet:
    """Hash every file under ``path`` and suppress on those digests.

    The common case where the examiner has no hash list but does have the
    original media or a reference copy: hashing the reference is strictly better
    than deleting findings by eye.

    Files are streamed rather than read whole, because the reference copy is
    usually a multi-gigabyte image and holding one in memory is how a hash step
    becomes the reason the run dies.
    """
    path = Path(path)
    if not path.is_dir():
        raise SuppressionError(f"{path} is not a directory")
    algos = _normalise_algorithms(algorithms) or ["sha256"]
    out = SuppressionSet(source=f"{path} (hashed in place)")
    files = sorted(p for p in path.rglob("*") if p.is_file())
    if not files:
        raise SuppressionError(f"{path} contains no files to hash")
    for p in files:
        try:
            digests = _hash_file(p, algos, chunk_size)
        except OSError as exc:
            out._skip(f"unreadable: {exc.strerror}")
            continue
        for algo, digest in digests.items():
            out.add_digest(algo, digest)
    if not len(out):
        raise SuppressionError(f"no readable files under {path}")
    return out


def _hash_file(path: Path, algorithms: Sequence[str],
               chunk_size: int = 1 << 20) -> dict[str, str]:
    """Digest ``path`` with every named algorithm in a single pass over the file."""
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            for h in hashers.values():
                h.update(block)
    return {algo: h.hexdigest() for algo, h in hashers.items()}


def load_hash_set(path: Path, algorithms: Iterable[str] | None = None) -> SuppressionSet:
    """Load a hash set from a list file, or hash a directory in place.

    ``algorithms`` optionally restricts which algorithms are kept, for when a
    list mixes SHA-256 rows with MD5 rows and only one is trustworthy.
    """
    path = Path(path)
    if path.is_dir():
        return load_file_hashes(path, algorithms=algorithms)
    if not path.is_file():
        raise SuppressionError(f"{path} does not exist")

    wanted = set(_normalise_algorithms(algorithms)) or None
    out = SuppressionSet(source=str(path))
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            out.add_line(line)
    if wanted:
        for algo in list(out.digests):
            if algo not in wanted:
                out._skip(f"dropped {algo} rows")
                del out.digests[algo]
    if not len(out):
        raise SuppressionError(
            f"{path} yielded no usable digests "
            f"({out.lines_skipped} line(s) skipped)")
    return out
