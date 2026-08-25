"""Stage 2: the filesystem guard backed by REAL FILES instead of memory.

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
Stage 1 (fsmount.GuardedFileSystem) holds every file in a Python dict. That
proved interception, snapshotting and undo end to end without also requiring a
correct filesystem - but everything vanishes on unmount, so it is a laboratory
instrument and not something a person can work in.

This module is the other half: a real directory underneath the mount.

    virtual   \\src\\app.py                  what WinFsp and the user see
    backing   C:\\project.real\\src\\app.py   where the bytes actually live

The four destructive hooks and the whole of fsguard.py are UNCHANGED. Only
where the bytes go changes. That is the payoff of having split judgement from
plumbing at the start, and it is now being collected for the second time.

--------------------------------------------------------------------------
WHY IT IS A SEPARATE MODULE FROM fsmount.py
--------------------------------------------------------------------------
Same reason fsguard.py is separate: winfspy exists only on Windows, so
anything living inside a winfspy subclass cannot be tested where the work is
done. Everything here is ordinary Python file I/O against an ordinary
directory, so the correctness suite runs on any platform.

That matters more here than anywhere else in this codebase. Stage 1's worst
failure was losing scratch data. THIS module's worst failure is corrupting
somebody's real files, and a filesystem is not something to write with the
tests on a different machine.

--------------------------------------------------------------------------
THE SECURITY PROPERTY THIS FILE IS RESPONSIBLE FOR
--------------------------------------------------------------------------
Every virtual path must resolve INSIDE the backing directory. A guard that can
be talked into writing to C:\\Windows\\System32 by a path containing '..' is
not a guard, and "the caller would never send that" is not an argument - a
malicious or confused agent is the entire threat model. `resolve()` is the
single door, it rejects traversal structurally rather than by pattern
matching, and nothing else in this module may join paths by hand.
"""
from __future__ import annotations

import errno
import os
import shutil
from dataclasses import dataclass
from typing import List, Optional, Tuple


class PathEscape(Exception):
    """A virtual path tried to leave the backing directory."""


def normalize(virtual: Optional[str]) -> str:
    """A WinFsp virtual path as forward-slash form with no leading separator.

    '\\src\\app.py' -> 'src/app.py'   '\\' -> ''   None -> ''

    Deliberately the same shape as fsguard.normalize, because the two see the
    same strings. They are separate functions because the modules are separate
    layers and importing one into the other for three lines would couple them
    for no gain.
    """
    if not virtual:
        return ""
    return virtual.replace("\\", "/").strip("/")


@dataclass
class Attrs:
    """What the filesystem layer needs to answer get_file_info.

    Deliberately not a stat_result: the mount reports a small, explicit set of
    facts, and passing os.stat objects around would invite reporting host
    details WinFsp never asked for.
    """
    is_dir: bool
    size: int
    ctime: float
    atime: float
    mtime: float
    readonly: bool = False


class Backing:
    """A real directory presented through virtual paths.

    Holds no state beyond its root: every method takes a virtual path and does
    the work immediately. Open file handles are plain OS file descriptors owned
    by the caller, so nothing here has to be reconciled after a crash.
    """

    def __init__(self, root: str, create: bool = False):
        self.root = os.path.abspath(root)
        if create:
            os.makedirs(self.root, exist_ok=True)
        if not os.path.isdir(self.root):
            raise NotADirectoryError(f"backing directory does not exist: {self.root}")

    # ------------------------------------------------------------------
    # The single door
    # ------------------------------------------------------------------

    def resolve(self, virtual: Optional[str]) -> str:
        """Virtual path -> absolute real path, or raise PathEscape.

        Two independent checks, because either alone has a hole:

        1. Reject '..' as a path COMPONENT before joining. Catches the ordinary
           case cheaply and without touching the filesystem.
        2. Verify the joined result is still under the root with commonpath.
           Catches what step 1 cannot: an absolute component ('/etc/passwd',
           'C:\\Windows') that os.path.join would silently make the whole path,
           and anything a future normalisation change lets through.

        Symlinks are deliberately NOT resolved. os.path.realpath here would
        refuse a legitimate symlink inside the project that points elsewhere,
        which is a normal thing for a repository to contain. The containment
        guarantee is over the PATH the caller named, which is what WinFsp asked
        about.
        """
        rel = normalize(virtual)
        if rel:
            parts = rel.split("/")
            if any(p == ".." for p in parts):
                raise PathEscape(f"path traversal refused: {virtual!r}")
            # An absolute or drive-qualified component would make os.path.join
            # discard everything before it.
            if any(os.path.isabs(p) or (len(p) > 1 and p[1] == ":") for p in parts):
                raise PathEscape(f"absolute component refused: {virtual!r}")
        real = os.path.abspath(os.path.join(self.root, *rel.split("/")) if rel else self.root)
        try:
            if os.path.commonpath([real, self.root]) != self.root:
                raise PathEscape(f"escapes the backing directory: {virtual!r}")
        except ValueError:                      # different drives entirely
            raise PathEscape(f"escapes the backing directory: {virtual!r}") from None
        return real

    # ------------------------------------------------------------------
    # Reading the tree
    # ------------------------------------------------------------------

    def exists(self, virtual: Optional[str]) -> bool:
        try:
            return os.path.lexists(self.resolve(virtual))
        except PathEscape:
            return False

    def is_dir(self, virtual: Optional[str]) -> bool:
        try:
            return os.path.isdir(self.resolve(virtual))
        except PathEscape:
            return False

    def attrs(self, virtual: Optional[str]) -> Attrs:
        real = self.resolve(virtual)
        st = os.stat(real)
        is_dir = os.path.isdir(real)
        return Attrs(
            is_dir=is_dir,
            # A directory's on-disk size is meaningless to the caller and
            # differs per filesystem; report 0 so the mount looks the same
            # everywhere.
            size=0 if is_dir else st.st_size,
            ctime=st.st_ctime, atime=st.st_atime, mtime=st.st_mtime,
            readonly=not os.access(real, os.W_OK),
        )

    def listdir(self, virtual: Optional[str]) -> List[str]:
        """Entry names, sorted. Sorted because WinFsp pages through directory
        listings with a marker: an unstable order makes entries appear twice or
        not at all across pages, and that bug only shows up on big
        directories."""
        return sorted(os.listdir(self.resolve(virtual)))

    # ------------------------------------------------------------------
    # Creating
    # ------------------------------------------------------------------

    def make_dir(self, virtual: str) -> str:
        real = self.resolve(virtual)
        os.mkdir(real)
        return real

    def make_file(self, virtual: str) -> str:
        """Create an empty file, refusing to clobber an existing one.

        'x' rather than 'w': a create that silently truncates an existing file
        would destroy data BELOW the level the guard inspects, with no hook
        able to see it happen.
        """
        real = self.resolve(virtual)
        with open(real, "xb"):
            pass
        return real

    # ------------------------------------------------------------------
    # File contents
    # ------------------------------------------------------------------

    def open_fd(self, virtual: str, write: bool = True) -> int:
        """A raw OS file descriptor. Raw rather than a buffered object because
        WinFsp reads and writes at explicit offsets from several threads, and a
        Python file object's internal position is shared state we would then
        have to lock.

        On Windows this goes through CreateFileW rather than os.open, for one
        reason: FILE_SHARE_DELETE. See _open_fd_windows - without it the
        passthrough cannot perform the single most important operation it
        exists to guard.
        """
        real = self.resolve(virtual)
        if os.name == "nt":
            return _open_fd_windows(real, write)
        return os.open(real, os.O_RDWR if write else os.O_RDONLY)

    @staticmethod
    def read_at(fd: int, offset: int, length: int) -> bytes:
        """Read up to `length` bytes at `offset`. Short reads near end-of-file
        are normal and are the caller's to interpret."""
        return os.pread(fd, length, offset) if hasattr(os, "pread") else \
            _read_at_seek(fd, offset, length)

    @staticmethod
    def write_at(fd: int, data: bytes, offset: int) -> int:
        return os.pwrite(fd, data, offset) if hasattr(os, "pwrite") else \
            _write_at_seek(fd, data, offset)

    @staticmethod
    def size_of_fd(fd: int) -> int:
        return os.fstat(fd).st_size

    @staticmethod
    def set_size_fd(fd: int, size: int) -> None:
        os.ftruncate(fd, size)

    def read_all(self, virtual: str) -> bytes:
        """The whole file. Used by the guard to snapshot content that is about
        to be destroyed - the passthrough equivalent of reading FileObj.data
        out of the in-memory filesystem."""
        with open(self.resolve(virtual), "rb") as f:
            return f.read()

    # ------------------------------------------------------------------
    # Destroying and moving
    # ------------------------------------------------------------------

    def remove(self, virtual: str) -> None:
        """Delete a file, or an EMPTY directory.

        Non-empty directories are refused on purpose. Windows deletes a tree
        leaf-first, so every file arrives as its own operation and every one
        gets its own verdict. A recursive delete here would destroy files the
        guard never saw.
        """
        real = self.resolve(virtual)
        if os.path.isdir(real):
            os.rmdir(real)
        else:
            os.unlink(real)

    def rename(self, old_virtual: str, new_virtual: str,
               replace_if_exists: bool = False) -> None:
        """Move within the backing directory.

        os.replace and os.rename differ exactly where it matters: replace
        clobbers the destination, rename refuses. Windows signals which one it
        wants, and getting it backwards either loses a file that should have
        survived or fails an operation that should have worked. The
        DESTINATION's content is what dies here - fsguard.on_rename already
        knows that, and its snapshot has been taken before we are called.
        """
        src, dst = self.resolve(old_virtual), self.resolve(new_virtual)
        if replace_if_exists:
            os.replace(src, dst)
        else:
            if os.path.lexists(dst):
                raise FileExistsError(errno.EEXIST, "destination exists", dst)
            os.rename(src, dst)

    # ------------------------------------------------------------------
    # Whole-tree helpers, for `demo_cli protect`
    # ------------------------------------------------------------------

    @staticmethod
    def relocate(source: str, backing: str) -> None:
        """Move a project aside so its own path can become the mount point.

            C:\\project  ->  C:\\project.real      (this)
            C:\\project  <-  the WinFsp mount      (afterwards)

        A directory mount point is an NTFS reparse point and Windows only sets
        one on an empty or missing directory, so the original path HAS to be
        vacated. os.rename rather than a copy: it is atomic within a volume,
        needs no free space, and cannot half-finish leaving two divergent
        copies of somebody's work.
        """
        source, backing = os.path.abspath(source), os.path.abspath(backing)
        if not os.path.isdir(source):
            raise NotADirectoryError(f"nothing to relocate at {source}")
        if os.path.lexists(backing):
            raise FileExistsError(errno.EEXIST,
                                  "backing path already exists; refusing to merge", backing)
        os.rename(source, backing)


# --------------------------------------------------------------------------
# Positional I/O fallback
#
# os.pread / os.pwrite are absent on Windows, and they are the reason the rest
# of this module can be thread-safe without locking: they take the offset as an
# argument instead of moving a shared file position. Where they do not exist,
# seek-then-read is the only option and the lock below is what keeps two
# threads from interleaving a seek with someone else's read.
# --------------------------------------------------------------------------
import threading

_POSITION_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# Windows: opening a file that can still be renamed and deleted
#
# THE DEFECT THIS FIXES, found on the first live passthrough run (2026-08-25):
#
#     os.replace('temp.txt', 'keep.txt')
#     PermissionError: [WinError 32] The process cannot access the file
#     because it is being used by another process
#
# We were the other process. WinFsp calls rename() while handing us a file
# context that holds OUR OWN descriptor on the source, and Windows refuses to
# rename or delete a file with an open handle unless every handle was opened
# with FILE_SHARE_DELETE. Python's os.open never sets it, and exposes no way
# to ask - so the only route is CreateFileW directly.
#
# This is not an edge case. rename-onto-an-existing-file IS Claude Code's Write
# tool on every save, and the operation with no delete signal is the entire
# reason the Windows guard exists. Without share-delete, the passthrough
# cannot perform the one thing it was built to watch.
#
# POSIX has no equivalent problem: an open file can always be renamed or
# unlinked, so the plain os.open path above is correct there.
# --------------------------------------------------------------------------

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_SHARE_READ_WRITE_DELETE = 0x01 | 0x02 | 0x04
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80


def _open_fd_windows(real: str, write: bool) -> int:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    access = _GENERIC_READ | (_GENERIC_WRITE if write else 0)
    handle = kernel32.CreateFileW(real, access, _SHARE_READ_WRITE_DELETE, None,
                                  _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    # open_osfhandle takes ownership: closing the returned fd closes the
    # handle, so there is exactly one thing to release.
    return msvcrt.open_osfhandle(handle, os.O_BINARY if write
                                 else (os.O_BINARY | os.O_RDONLY))


def _read_at_seek(fd: int, offset: int, length: int) -> bytes:
    with _POSITION_LOCK:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, length)


def _write_at_seek(fd: int, data: bytes, offset: int) -> int:
    with _POSITION_LOCK:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data)
