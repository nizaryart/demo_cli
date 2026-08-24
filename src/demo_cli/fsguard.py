"""Windows behavioural guard: decide which filesystem operations destroy data.

The Linux syscall guard answers indirection by watching the kernel: `rm`, however
it was written, becomes `unlink()` on a resolved path. Windows has no ptrace, so
the equivalent standing-place is a WinFsp filesystem — user-mode code sitting
below the syscall boundary, where every route (Win32, ntdll, direct syscalls)
has already converged.

This module is the JUDGEMENT half of that: given one filesystem operation, is it
destructive, and which path is about to lose its contents? It deliberately knows
nothing about WinFsp, snapshots, or Windows itself, so it can be tested anywhere
- the same split that let the PowerShell dialect work be developed on Linux.

--------------------------------------------------------------------------
EVERY RULE BELOW COMES FROM AN OBSERVED OPERATION LOG, NOT FROM THE DOCS
--------------------------------------------------------------------------
Captured against winfspy 0.8.4 on Windows 10 (fsprobe/REPORT.md). Three of the
four findings contradicted the obvious design:

1. `rename(replace_if_exists=True)` destroys the destination with NO delete
   signal whatsoever - no can_delete, no cleanup(FspCleanupDelete), nothing.
   This is not exotic: it is what Claude Code's own Write tool does, every
   time, for new files and overwrites alike, via a temp file named
   `<original>.tmp.<pid>.<hex>`. It is also `os.replace()`, `MoveFileEx`, and
   every editor that saves atomically. A guard hooking only the delete signal
   misses the single most common thing an agent does to a file.

2. `overwrite()` is dead code. Despite being the method whose NAME matches
   "this file is about to be overwritten", it was never called once. Real
   overwrites go through `set_file_size(new_size=0)` on an open handle. It is
   hooked here anyway, defensively, but nothing observed reaches it.

3. `can_delete()` is not a reliable signal - PowerShell's `Remove-Item` calls
   it, cmd's `del` skips it entirely. `set_delete()` is documented and never
   called at all. Only `cleanup()` with the delete bit fired on every delete.

4. Windows never tells user-mode code the CreateFile disposition, so there is
   no "was this CREATE_ALWAYS?" to branch on. The driver resolves it and
   signals the outcome by which method it calls.

The noise is also worth stating: `dir` on a one-file directory produced 35
operations, and merely mounting produced ~55. Everything not in the four hooks
below must pass through at zero cost.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Set

# --------------------------------------------------------------------------
# WinFsp cleanup flags.
#
# winfspy does NOT export these - they exist only as literals inside its own
# memfs reference implementation, under a `# TODO: expose FspCleanupDelete &
# friends` comment. Copied here rather than imported, because there is nothing
# to import.
# --------------------------------------------------------------------------
FSP_CLEANUP_DELETE = 0x01
FSP_CLEANUP_SET_ALLOCATION_SIZE = 0x02
FSP_CLEANUP_SET_ARCHIVE_BIT = 0x10
FSP_CLEANUP_SET_LAST_ACCESS_TIME = 0x20
FSP_CLEANUP_SET_LAST_WRITE_TIME = 0x40
FSP_CLEANUP_SET_CHANGE_TIME = 0x80

# What kind of destruction, for the receipt.
DELETE = "delete"
TRUNCATE = "truncate"
REPLACE = "replace"
OVERWRITE = "overwrite"

# --------------------------------------------------------------------------
# What this guard does not watch.
#
# DELIBERATELY SEPARATE from recovery.IGNORED_DIRS, not an accidental copy.
# They answer different questions and the right answers differ:
#
#   recovery.IGNORED_DIRS  "what may a recovery point omit?"
#                          Conservative. Omitting a directory from a snapshot
#                          means `undo` restores an INCOMPLETE tree, which is
#                          the partial-recovery lie FIX #5 exists to prevent.
#
#   this list              "what is not worth a receipt?"
#                          Aggressive. Every operation here is intercepted
#                          live: one `git status` inside the mount walks
#                          hundreds of files under .git, and a build writes
#                          thousands into dist/. Snapshotting regenerable
#                          output would bury the ledger and cost real time.
#
# So this one is longer, and should stay longer. If the two ever need to agree
# on something, that is a decision to make explicitly - not by importing one
# into the other and losing the distinction.
# --------------------------------------------------------------------------
DEFAULT_IGNORE: Set[str] = {
    ".git", "node_modules", "__pycache__", ".demo_cli", ".demo_cli_recovery",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox",
    "dist", "build", ".next", "target",
}

@dataclass(frozen=True)
class Verdict:
    """What one filesystem operation is about to do.

    `target` is the path whose CONTENT dies - which for a rename is the
    DESTINATION, not the file being moved. Getting that backwards would snapshot
    the wrong file and report a recovery we never took.
    """
    destructive: bool
    kind: Optional[str] = None
    target: Optional[str] = None
    reason: str = ""

    @staticmethod
    def passthrough(reason: str = "not destructive") -> "Verdict":
        return Verdict(False, reason=reason)


# --------------------------------------------------------------------------
# Path handling
#
# WinFsp hands out virtual paths rooted at the mount, Windows-style:
#   '\notes.txt'   '\src\app.py'   '\'
# --------------------------------------------------------------------------

def normalize(virtual_path: Optional[str]) -> str:
    """A virtual path as forward-slash-separated, leading slash stripped.

    '\\src\\app.py' -> 'src/app.py'   '\\' -> ''   None -> ''
    """
    if not virtual_path:
        return ""
    return virtual_path.replace("\\", "/").lstrip("/")


def path_parts(virtual_path: Optional[str]) -> list:
    n = normalize(virtual_path)
    return [p for p in n.split("/") if p]


def in_scope(virtual_path: Optional[str],
             ignore: Optional[Iterable[str]] = None) -> bool:
    """False for paths we deliberately do not guard.

    The mount root itself is never a target, and anything under an ignored
    directory is skipped. Unlike the Linux guard there is no project-root check
    here: the mount IS the project root, which is the one genuine simplification
    the WinFsp approach buys.
    """
    parts = path_parts(virtual_path)
    if not parts:
        return False                       # the root itself
    ignored = set(DEFAULT_IGNORE if ignore is None else ignore)
    return not (set(parts) & ignored)


def is_temp_sibling(virtual_path: Optional[str], of: Optional[str]) -> bool:
    """True if `virtual_path` looks like an atomic-save temp file for `of`.

    Claude Code writes `<original>.tmp.<pid>.<hex>` beside the target and
    renames it over. Not used to skip anything - the temp file is harmless and
    its own cleanup carries no delete flag - but it identifies the pattern in
    receipts, so a reader can tell an atomic save from an unrelated delete.
    """
    a, b = normalize(virtual_path), normalize(of)
    return bool(a and b and a != b and a.startswith(b + "."))


# --------------------------------------------------------------------------
# The four hook points
# --------------------------------------------------------------------------

def on_cleanup(file_name: Optional[str], flags: int) -> Verdict:
    """cleanup() fires after nearly every handle closes. Only the delete bit matters.

    Observed non-delete value: 242 (allocation size + archive bit + three
    timestamps), on every ordinary write. Observed delete value: 33
    (FspCleanupDelete | SetLastAccessTime). Testing `flags == FSP_CLEANUP_DELETE`
    instead of masking would therefore miss every real delete.
    """
    if not flags & FSP_CLEANUP_DELETE:
        return Verdict.passthrough("cleanup without the delete flag")
    if not in_scope(file_name):
        return Verdict.passthrough(f"out of scope: {file_name}")
    return Verdict(True, DELETE, normalize(file_name),
                   "cleanup with FspCleanupDelete")


def on_set_file_size(file_name: Optional[str], new_size: int,
                     current_size: int) -> Verdict:
    """Shrinking a file destroys the bytes past the new end.

    This - not overwrite() - is how Set-Content, Clear-Content and Claude
    Code's in-place writes empty a file. Growing a file destroys nothing, so
    only a strict shrink counts.
    """
    if new_size >= current_size:
        return Verdict.passthrough("file grew or stayed the same size")
    if not in_scope(file_name):
        return Verdict.passthrough(f"out of scope: {file_name}")
    return Verdict(True, TRUNCATE, normalize(file_name),
                   f"set_file_size {current_size} -> {new_size}")


def on_rename(old_name: Optional[str], new_name: Optional[str],
              replace_if_exists: bool, dest_exists: bool) -> Verdict:
    """The one with no delete signal - and the most common one in practice.

    The DESTINATION is what dies; the source survives under a new name. Both
    conditions are required: a rename onto a free name destroys nothing, and
    without replace_if_exists Windows refuses the rename rather than clobbering
    (which is exactly why Move-Item -Force deletes the destination separately
    first, and so is caught by on_cleanup instead).
    """
    if not dest_exists:
        return Verdict.passthrough("destination does not exist; nothing clobbered")
    if not replace_if_exists:
        return Verdict.passthrough("rename would fail rather than replace")
    if not in_scope(new_name):
        return Verdict.passthrough(f"out of scope: {new_name}")
    note = ("atomic save" if is_temp_sibling(old_name, new_name)
            else "rename over an existing file")
    return Verdict(True, REPLACE, normalize(new_name),
                   f"{note} ({normalize(old_name)} -> {normalize(new_name)})")


def on_overwrite(file_name: Optional[str], exists: bool) -> Verdict:
    """Never observed firing. Hooked because the API offers it and a different
    Windows build or application might use it - but the absence is recorded so
    nobody later assumes this is the main path. It is not; on_set_file_size is.
    """
    if not exists:
        return Verdict.passthrough("nothing there to overwrite")
    if not in_scope(file_name):
        return Verdict.passthrough(f"out of scope: {file_name}")
    return Verdict(True, OVERWRITE, normalize(file_name), "overwrite()")
