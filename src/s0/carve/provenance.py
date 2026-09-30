"""How far a recovered name or path can be trusted, and what to say about it.

The problem
-----------
A recovery report that prints `Documents/Q3-report.pdf` and one that prints
`Q3-report.pdf` look equally authoritative. They are not. The first implies the
tool reconstructed a directory hierarchy; the second does not, and on most
filesystems the hierarchy is *not recoverable* from a deleted record at all.

Worse, the bare filename case hides a second distinction. exFAT stores a deleted
file's name in a single directory entry with no checksum and no link to a
parent. FAT32 stores a long name as a run of fragments that each carry a
checksum of the 8.3 entry they belong to, so a long name recovered from a
*live* 8.3 entry can be verified and one recovered from a *deleted* one cannot.
Reporting both as "filename" makes a verified name and an unverifiable one
indistinguishable.

What this module does
---------------------
It names the strength of each piece of evidence once, so the engine does not
have to re-derive it per filesystem and cannot accidentally present a weak name
as a strong one. Every constant is a sentence an examiner can be shown, because
a report field that says only `verified: false` leaves the reader to guess how
much to trust it.

What is genuinely unrecoverable
-------------------------------
A deleted directory entry in exFAT or FAT32 records the file's name and its
first cluster. It does not record the directory it lived in -- there is no
parent pointer to read, and the directory that held it may itself be deleted
and its own entry gone. So the path cannot be reconstructed from the volume,
and the honest output is a filename with the absence of a path stated, not a
path assembled from whatever directories happen to still parse.

NTFS is the exception and for a real reason: `$FILE_NAME` is a full path
relative to the volume root, written by the filesystem at creation time, and it
survives in the MFT record of a deleted file. That path is metadata, not
inference, and is labelled as such.
"""

from __future__ import annotations

from dataclasses import dataclass

# How a recovered name was arrived at.
NAME_SOURCE_CHECKSUM = "checksum-verified"
NAME_SOURCE_ADJACENCY = "adjacency-only"
NAME_SOURCE_DIRECTORY_ENTRY = "deleted-directory-entry"
NAME_SOURCE_JOURNAL = "journal-record"
NAME_SOURCE_CARVED = "carved-no-metadata"

#: How a recovered path was arrived at.
PATH_SOURCE_MFT = "ntfs-file-name-attribute"
PATH_SOURCE_UNRECOVERABLE = "not-recoverable"

#: Prose per name source. The text is what an examiner reads, so it says what
#: the evidence *is* rather than only what it is not, and it names the
#: filesystem, because "no checksum" means different things in different ones.
_NAME_SOURCE_TEXT = {
    NAME_SOURCE_CHECKSUM: (
        "long filename bound to its 8.3 entry by the LFN checksum, which "
        "Windows and FAT32 store for exactly this purpose"
    ),
    NAME_SOURCE_ADJACENCY: (
        "long filename reconstructed from fragment order and adjacency only. "
        "The 8.3 entry it belonged to is deleted, so its checksum cannot be "
        "recomputed and the name cannot be verified"
    ),
    NAME_SOURCE_DIRECTORY_ENTRY: (
        "filename read from a deleted directory entry. exFAT stores a deleted "
        "file's name in one entry with no checksum, so there is nothing to "
        "verify it against"
    ),
    NAME_SOURCE_JOURNAL: (
        "name from a filesystem change-journal record. The journal is written "
        "by the filesystem as it happens, so this is a contemporaneous record "
        "rather than a structure that survived deletion"
    ),
    NAME_SOURCE_CARVED: (
        "no filesystem metadata: the name was assigned from the recovered "
        "content's format, not recovered from the volume"
    ),
}

#: Where the prose above is not specific enough, because the mechanism differs.
_NAME_SOURCE_TEXT_BY_FILESYSTEM = {
    ("ntfs", NAME_SOURCE_DIRECTORY_ENTRY): (
        "filename read from the $FILE_NAME attribute of a deleted MFT record. "
        "NTFS keeps the full path there, so the name and the path are both "
        "filesystem metadata rather than inference"
    ),
    ("ext4", NAME_SOURCE_DIRECTORY_ENTRY): (
        "filename read from a deleted inode's directory entry. The entry names "
        "the file but records no parent, so the directory it lived in is not "
        "recoverable from the entry"
    ),
}

_PATH_SOURCE_TEXT = {
    PATH_SOURCE_MFT: (
        "original path from the NTFS $FILE_NAME attribute, which the "
        "filesystem writes in full at creation and leaves in the MFT record "
        "of a deleted file"
    ),
    PATH_SOURCE_UNRECOVERABLE: (
        "original path is not recoverable. A deleted record in this filesystem "
        "holds the name and the first cluster but no parent, and the containing "
        "directory may itself be deleted. No path is reported rather than one "
        "assembled from whatever directories still parse"
    ),
}


def name_source_text(source: str | None, filesystem: str | None = None) -> str:
    """A sentence explaining a name's provenance, for the report."""
    if not source:
        return _NAME_SOURCE_TEXT[NAME_SOURCE_CARVED]
    if filesystem:
        specific = _NAME_SOURCE_TEXT_BY_FILESYSTEM.get(
            (filesystem.lower(), source))
        if specific:
            return specific
    return _NAME_SOURCE_TEXT.get(source, source)


def path_source_text(source: str | None) -> str:
    """A sentence explaining a path's provenance, or its absence."""
    if not source:
        return _PATH_SOURCE_TEXT[PATH_SOURCE_UNRECOVERABLE]
    return _PATH_SOURCE_TEXT.get(source, source)


@dataclass
class NameProvenance:
    """What supports a recovered name and path, in reportable form."""
    name_source: str
    path_source: str | None = None
    path: str | None = None
    filesystem: str | None = None

    @property
    def name_is_verified(self) -> bool:
        """Only a checksum-bound long name is verified.

        Everything else is structurally sound, and none of it is confirmed.
        This distinction is the reason the field exists.
        """
        return self.name_source == NAME_SOURCE_CHECKSUM

    @property
    def path_is_recovered(self) -> bool:
        return bool(self.path) and bool(self.path_source)

    def describe(self) -> str:
        parts = [name_source_text(self.name_source, self.filesystem)]
        if self.path_is_recovered:
            parts.append(f"path from {path_source_text(self.path_source)}")
        else:
            parts.append(path_source_text(PATH_SOURCE_UNRECOVERABLE))
        return "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "name_source": self.name_source,
            "name_is_verified": self.name_is_verified,
            "filesystem": self.filesystem,
            "name_detail": name_source_text(self.name_source, self.filesystem),
            "path": self.path,
            "path_source": self.path_source,
            "path_is_recovered": self.path_is_recovered,
            "path_detail": path_source_text(self.path_source) if self.path_is_recovered
            else path_source_text(PATH_SOURCE_UNRECOVERABLE),
        }


# Per-filesystem defaults. Each entry records what that filesystem can actually
# prove about a deleted file, which is what the report must say.
FILESYSTEM_PROVENANCE = {
    "ntfs": (NAME_SOURCE_DIRECTORY_ENTRY, PATH_SOURCE_MFT),
    "fat32": (NAME_SOURCE_ADJACENCY, PATH_SOURCE_UNRECOVERABLE),
    "exfat": (NAME_SOURCE_DIRECTORY_ENTRY, PATH_SOURCE_UNRECOVERABLE),
    "ext4": (NAME_SOURCE_DIRECTORY_ENTRY, PATH_SOURCE_UNRECOVERABLE),
    "raw": (NAME_SOURCE_CARVED, PATH_SOURCE_UNRECOVERABLE),
}


def for_filesystem(filesystem: str, *, path: str | None = None,
                   name_source: str | None = None) -> NameProvenance:
    """Provenance for a name recovered from `filesystem`."""
    default_name, path_source = FILESYSTEM_PROVENANCE.get(
        (filesystem or "raw").lower(), FILESYSTEM_PROVENANCE["raw"])
    if filesystem and filesystem.lower() == "ntfs":
        path_source = PATH_SOURCE_MFT
    return NameProvenance(
        name_source=name_source or default_name,
        path_source=path_source if path else PATH_SOURCE_UNRECOVERABLE,
        path=path,
        filesystem=(filesystem or "").lower() or None,
    )
