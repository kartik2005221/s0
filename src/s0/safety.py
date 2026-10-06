"""One path guard, shared by the CLI and the web tier.

The web dashboard refused `/etc/passwd` and the root device. The CLI refused
neither. Two interfaces to the same destructive engine, disagreeing about what is
protected, is the worst shape this could take: an operator who found the web tier
safe would reasonably assume the terminal was too.

So the rules live here once, and both callers use them.

Three classes of path are refused:

* **System locations** -- `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`,
  `/boot`, `/proc`, `/sys`, `/dev`, `/root`, `/var`, `/run`. A denylist is the
  wrong shape for a tool whose job is destroying data, but an allowlist is worse
  still: legitimate forensic work targets evidence in `~`, in `/mnt`, in `/media`
  and in `/tmp`, and refusing those by default would make the tool useless. So
  this denies the known-critical prefixes and additionally denies s0's own state,
  which is the case that actually bites.

* **s0's own state** -- `~/.s0`, the audit ledger inside it, the web auth token,
  and the installation tree. This is the finding that mattered: `s0 wipe
  --targets ~/.s0/s0_audit.db --yes` succeeded, destroying the chain-of-custody
  ledger, after which `s0 audit verify` built a fresh empty one and reported it
  valid. Wiping the evidence of what you wiped is the worst available outcome.

* **The user's home directory and `/` themselves** -- not because they are
  categorically wrong, but because erasing a whole home directory is never what
  someone means when they type a path, and the cost of being wrong is total.

`--force` still exists for the cases where the operator genuinely means it, but it
now produces an explicit, recorded warning rather than silence.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Critical system prefixes. Matched after resolution, so `/etc/../etc/passwd`
#: and a symlink into `/etc` are both caught.
SYSTEM_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/var",
    "/run",
    "/srv",
    "/opt",
    # macOS resolved prefixes (symlinks in root resolve to /private/*)
    "/private/etc",
    "/private/var",
    "/System",
    "/Library",
    "/Applications",
    # Windows system prefixes
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
)

#: Paths under system prefixes that are user/temporary space and allowed.
ALLOWED_TEMP_PREFIXES: tuple[str, ...] = (
    "/tmp",  # nosec B108  # noqa: S108
    "/private/tmp",
    "/private/var/tmp",
    "/private/var/folders",
    "/var/tmp",  # nosec B108  # noqa: S108
)


def _resolve(path: str | os.PathLike[str]) -> Path | None:
    try:
        s = os.fspath(path)
        if "\x00" in s or any(ord(c) < 32 for c in s):
            return None
        norm = os.path.normpath(os.path.expanduser(s))
        if ".." in norm.split(os.sep):
            return None
        real = os.path.realpath(norm)
        return Path(real)
    except (OSError, RuntimeError, ValueError):
        return None


def _under(child: Path, parent: Path) -> bool:
    """True when `child` is `parent` or lives inside it.

    Compared on resolved paths as strings rather than with `relative_to`, so a
    sibling like `/etcfoo` is not mistaken for a child of `/etc`.
    """
    c, p = str(child), str(parent)
    if os.name == "nt":
        c, p = c.lower(), p.lower()
        if len(c) >= 2 and c[1] == ":" and (len(p) < 2 or p[1] != ":"):
            c = c[2:]
        p_clean = p.rstrip("/\\")
        return c == p_clean or c.startswith(p_clean + "\\") or c.startswith(p_clean + "/")
    return c == p or c.startswith(p.rstrip("/") + "/")


def s0_state_paths() -> list[Path]:
    """Files and directories that hold s0's own state.

    Resolved rather than guessed: `~/.s0` may be a symlink, and the install tree
    is whatever `resources.repo_root()` says it is.
    """
    out: list[Path] = []
    raw_home_s0 = Path.home() / ".s0"
    out.append(raw_home_s0)
    home_s0 = _resolve(raw_home_s0)
    if home_s0 is not None and home_s0 != raw_home_s0:
        out.append(home_s0)
    try:
        from s0.resources import repo_root

        root = repo_root()
        if root is not None:
            raw_repo_state = root / ".s0"
            out.append(raw_repo_state)
            repo_state = _resolve(raw_repo_state)
            if repo_state is not None and repo_state != raw_repo_state:
                out.append(repo_state)
            resolved = _resolve(root)
            if resolved is not None:
                out.append(resolved)
    except Exception:  # pragma: no cover - resources is always importable
        pass
    return out


def check_path_is_destructive(
    path: str | os.PathLike[str],
    *,
    force: bool = False,
    allow_state: bool = False,
) -> list[str]:
    """Return warnings if *path* is protected. Raises `ProtectedPathError` otherwise.

    Callers that already have a warning channel should raise; the returned list is
    only non-empty when `force=True` overrode something, so it must be shown.
    """
    resolved = _resolve(path)
    if resolved is None:
        raise ProtectedPathError(f"cannot resolve {str(path)!r} to a real path; refusing to act on it")

    warnings: list[str] = []

    # Block devices are handled by the device-tier safety check (mounts, root
    # filesystem, HPA). Refusing `/dev/sda` here would duplicate that logic and
    # lose the better error messages.
    try:
        if resolved.is_block_device():
            return warnings
    except OSError:
        pass

    target = str(resolved)

    is_root = target == "/" or (
        os.name == "nt" and (target in ("\\", "/") or resolved == Path(resolved.anchor))
    )
    if is_root:
        _refuse_or_warn(
            warnings,
            force,
            "Refusing to target the filesystem root '/'.",
            f"proceeding AGAINST THE FILESYSTEM ROOT: {target}",
        )

    resolved_home = _resolve(Path.home())
    if resolved_home is not None and resolved == resolved_home:
        _refuse_or_warn(
            warnings,
            force,
            f"Refusing to target the entire home directory ({target}). Target a specific path inside it.",
            f"proceeding AGAINST THE ENTIRE HOME DIRECTORY: {target}",
        )

    for prefix in SYSTEM_PREFIXES:
        if prefix == "/System" and (
            str(resolved) == "/System/Volumes" or str(resolved).startswith("/System/Volumes/")
        ):
            continue
        if any(_under(resolved, Path(allowed)) for allowed in ALLOWED_TEMP_PREFIXES):
            continue
        if _under(resolved, Path(prefix)):
            _refuse_or_warn(
                warnings,
                force,
                f"Refusing to target system path: {target}",
                f"proceeding AGAINST A SYSTEM PATH: {target}",
            )
            break

    if not allow_state:
        for state in s0_state_paths():
            if _under(resolved, state):
                label = "s0's own state" if state.name == ".s0" else "the s0 installation tree"
                _refuse_or_warn(
                    warnings,
                    force,
                    f"Refusing to target {label}: {target}\n"
                    "       This holds the audit ledger and signing material. Wiping it "
                    "destroys the\n"
                    "       chain of custody for every operation already recorded.",
                    f"proceeding AGAINST {label.upper()}: {target}",
                )
                break

    return warnings


def _refuse_or_warn(warnings: list[str], force: bool, refusal: str, override: str) -> None:
    if not force:
        raise ProtectedPathError(refusal)
    warnings.append(override)


class ProtectedPathError(Exception):
    """Raised when a target path is protected and ``--force`` was not given."""


def is_protected_path(path: str | os.PathLike[str], *, allow_state: bool = False) -> bool:
    """Boolean form for the web tier, which answers with a status code."""
    try:
        check_path_is_destructive(path, force=False, allow_state=allow_state)
    except ProtectedPathError:
        return True
    return False
