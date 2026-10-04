"""Carve sessions: resume a long run instead of starting it again.

Why
---
A full carve of a large image takes hours. When it is interrupted -- the
operator needs the machine, the disk controller drops, the process is killed by
a scheduler -- the only options today are to start over or to work out by hand
which files were already written. Both are bad. Starting over re-does hours of
work; working it out by hand means trusting a directory listing, and s0 names
its output by offset precisely so that a human can do that arithmetic.

What a session records
----------------------
The target's identity (path, size, and a digest of the first and last megabyte
so a *different* image cannot be mistaken for this one), the policy that was in
force, and every extent already recovered.

What it deliberately does not record
------------------------------------
A claim that a skipped extent is still there. A session says what was found
last time, not what is true now, and a session file can be edited. So a resumed
run reports the previous results as previous, and the bytes on the medium are
re-read rather than assumed: the skip is on the *output*, never on the evidence.
If a file named in the session is missing from the output directory, that is
reported rather than silently treated as done.

Format
------
JSON, one versioned document, with a `s0_carve_session` marker and a format
version. Unknown keys are ignored on read so a newer session can still be used
by an older binary for the fields it understands, and a wrong marker or a
future major version is refused rather than misread.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

#: Bumped when the meaning of an existing field changes. A reader that does not
#: recognise the major version refuses the file rather than guessing.
SESSION_FORMAT = "s0_carve_session"
SESSION_VERSION = 1

#: Bytes hashed from each end of the target for its fingerprint.
_FINGERPRINT_BYTES = 1 << 20

#: Additional samples spread through the middle of the image. Hashing the two
#: ends alone is enough to tell two different disks apart, but it will happily
#: accept an image whose middle was rewritten, and a session then suppresses
#: findings on an image nobody has examined. Sampling the middle costs a
#: bounded number of reads whatever the image size, which is the property that
#: matters here -- a terabyte image and a 4 GiB one must cost the same.
_FINGERPRINT_SAMPLES = 64
_FINGERPRINT_SAMPLE_BYTES = 4096


class SessionError(ValueError):
    """The session file is missing, malformed, or not about this target."""


@dataclass
class SessionEntry:
    """One extent already recovered."""

    offset: int
    length: int
    sha256: str
    extension: str = ""
    original_name: str | None = None
    recovered_path: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class CarveSession:
    """State that lets a later run skip work already done."""

    target_path: str
    target_size: int
    fingerprint: str
    entries: list[SessionEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    version: int = SESSION_VERSION

    # -- identity ---------------------------------------------------------- #

    @staticmethod
    def compute_fingerprint(path: Path) -> str:
        """Identify an image by its size, both ends, and a spread of samples.

        Hashing the whole image would be absurd on a multi-terabyte target and
        pointless on a session that is about to be resumed against the same
        disk. So: the size, the first and last megabyte, and 64 evenly spaced
        4 KiB reads through the middle. The read cost is fixed at about
        2.3 MiB whatever the image size.

        What this does not catch: a change confined to the unsampled middle of
        an image larger than 2 MiB. That is a real limit and is stated in the
        resume notes rather than left for the operator to discover.
        """
        size = path.stat().st_size
        h = hashlib.sha256()
        h.update(str(size).encode())
        with open(path, "rb") as fh:
            h.update(fh.read(_FINGERPRINT_BYTES))
            if size > _FINGERPRINT_BYTES:
                fh.seek(max(0, size - _FINGERPRINT_BYTES))
                h.update(fh.read(_FINGERPRINT_BYTES))
            span = max(0, size - 2 * _FINGERPRINT_BYTES)
            if span > _FINGERPRINT_SAMPLES * _FINGERPRINT_SAMPLE_BYTES:
                step = span // _FINGERPRINT_SAMPLES
                for i in range(_FINGERPRINT_SAMPLES):
                    fh.seek(_FINGERPRINT_BYTES + i * step)
                    h.update(fh.read(_FINGERPRINT_SAMPLE_BYTES))
        return h.hexdigest()

    # -- serialisation ----------------------------------------------------- #

    def to_dict(self) -> dict:
        return {
            "format": SESSION_FORMAT,
            "version": self.version,
            "target_path": self.target_path,
            "target_size": self.target_size,
            "fingerprint": self.fingerprint,
            "policy": self.policy,
            "entries": [e.as_dict() for e in self.entries],
            "warnings": self.warnings,
        }

    def write(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        # Written via a temporary file and renamed, so an interrupted write
        # cannot leave a half-written session that claims work is done.
        tmp.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
        return path

    @classmethod
    def read(cls, path: Path) -> CarveSession:
        path = Path(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SessionError(f"cannot read session {path}: {exc}") from exc
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SessionError(f"session {path} is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict) or doc.get("format") != SESSION_FORMAT:
            raise SessionError(f"{path} is not an s0 carve session")
        version = doc.get("version")
        if not isinstance(version, int):
            raise SessionError(f"session {path} has no format version")
        if version > SESSION_VERSION:
            raise SessionError(
                f"session {path} is format version {version}, newer than this "
                f"build understands ({SESSION_VERSION}); refusing rather than "
                f"misreading it"
            )
        entries = []
        for e in doc.get("entries") or []:
            if not isinstance(e, dict):
                continue
            try:
                entries.append(
                    SessionEntry(
                        offset=int(e["offset"]),
                        length=int(e["length"]),
                        sha256=str(e.get("sha256", "")),
                        extension=str(e.get("extension", "")),
                        original_name=e.get("original_name"),
                        recovered_path=e.get("recovered_path"),
                    )
                )
            except (KeyError, TypeError, ValueError):
                # One malformed row must not cost the whole session; the rest of
                # the run is still worth resuming.
                continue
        return cls(
            target_path=str(doc.get("target_path", "")),
            target_size=int(doc.get("target_size", 0) or 0),
            fingerprint=str(doc.get("fingerprint", "")),
            entries=entries,
            warnings=[str(w) for w in (doc.get("warnings") or [])],
            policy=doc.get("policy") or {},
            version=version,
        )

    # -- resume ------------------------------------------------------------ #

    def check_against(self, target: Path) -> None:
        """Refuse to resume onto a different image.

        A session whose fingerprint does not match would suppress findings on a
        volume nobody has examined, and would report them as previously done.
        """
        target = Path(target)
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise SessionError(f"cannot stat target {target}: {exc}") from exc
        if size != self.target_size:
            raise SessionError(
                f"session was taken against a {self.target_size}-byte target but "
                f"{target} is {size} bytes; these are not the same image"
            )
        actual = self.compute_fingerprint(target)
        if actual != self.fingerprint:
            raise SessionError(
                f"session fingerprint does not match {target}; the image has "
                f"changed since the session was written"
            )

    def skipped_offsets(self) -> set:
        """Offsets this session already recovered."""
        return {e.offset for e in self.entries}

    def missing_outputs(self) -> list[SessionEntry]:
        """Entries whose recovered file is no longer on disk.

        A session records what was found, not what still exists. Reporting these
        is the difference between "resumed" and "quietly did less work".
        """
        gone = []
        for e in self.entries:
            if e.recovered_path and not Path(e.recovered_path).exists():
                gone.append(e)
        return gone

    def merge(self, carved_files, *, out_dir: Path) -> CarveSession:
        """Fold this run's results into the session and return the new state."""
        out_dir = Path(out_dir)
        merged = {e.offset: e for e in self.entries}
        for c in carved_files:
            if c.offset in merged:
                continue
            merged[c.offset] = SessionEntry(
                offset=c.offset,
                length=c.size_bytes,
                sha256=c.sha256,
                extension=c.extension,
                original_name=c.original_name,
                recovered_path=(
                    str(Path(c.recovered_path).relative_to(out_dir)) if c.recovered_path else None
                ),
            )
        self.entries = sorted(merged.values(), key=lambda e: e.offset)
        return self


def describe_resume(session: CarveSession, *, out_dir: Path, skipped: int) -> list[str]:
    """Notes for the report about what resuming did and did not carry over."""
    notes = [
        f"resumed from a session recording {len(session.entries)} recovered "
        f"extent(s); {skipped} candidate(s) at known offsets were not re-carved"
    ]
    gone = session.missing_outputs()
    if gone:
        names = ", ".join(f"{e.original_name or e.recovered_path or f'offset {e.offset}'}" for e in gone[:8])
        more = "" if len(gone) <= 8 else f" (+{len(gone) - 8} more)"
        notes.append(
            f"{len(gone)} extent(s) in the session have no file in {out_dir} and "
            f"were re-examined: {names}{more}. A session records what was found, "
            f"not what is still on the medium"
        )
    if session.warnings:
        notes.append(f"session carried {len(session.warnings)} warning(s) from the previous run")
    return notes
