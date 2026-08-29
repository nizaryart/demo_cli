"""Windows behavioural guard: the WinFsp filesystem that does the intercepting.

`fsguard.py` decides WHAT is destructive. This is the part that stands where it
can see - a user-mode filesystem below the syscall boundary, where the Win32,
ntdll and direct-syscall routes have all converged, so no amount of obfuscation
in the command text can route around it.

WINDOWS ONLY. `winfspy` is imported lazily inside `build_operations`, never at
module scope, so importing this file on Linux is harmless - the same
arrangement `syscall_guard.py` uses for its `ctypes.CDLL("libc.so.6")`.

TWO STAGES LIVE HERE, and they make the SAME DECISIONS. Both drive fsguard.py;
only storage differs.

  build_operations              STAGE 1, in memory. Contents are LOST on
                                unmount. Built first on purpose: it proved
                                interception, snapshotting and undo end to end
                                without also requiring a correct filesystem,
                                whose failure mode is corrupting real files
                                rather than losing scratch ones. Keep it - it
                                is the cheap way to exercise the hooks.
  build_passthrough_operations  STAGE 2, over a real backing directory
                                (fspassthrough.Backing). Files survive
                                unmounting, so this is the one a person can
                                work in.

Recovery points go to the REAL disk in both cases, so they outlive the mount
either way. That Stage 2 needed no change at all to fsguard.py, and only one
line of `_capture`, is the return on having split judgement from plumbing
before writing either.

--------------------------------------------------------------------------
WHY THESE FOUR HOOKS, AND NOT THE OBVIOUS ONES
--------------------------------------------------------------------------
From operation logs captured on Windows 10 / winfspy 0.8.4 (fsprobe/REPORT.md):

  rename(replace_if_exists=True)   destroys the destination with NO delete
                                   signal at all. This is Claude Code's Write
                                   tool, every save. THE most important hook.
  cleanup(flags & FspCleanupDelete) ordinary deletes. The flag must be masked -
                                   real deletes arrive as 33, not 1.
  set_file_size(shrinking)         how Set-Content and Clear-Content empty a
                                   file. NOT overwrite().
  overwrite()                      never once observed. Hooked anyway.

`can_delete()` is skipped by cmd's `del`, and `set_delete()` is never called at
all, so neither is a usable signal.
"""
from __future__ import annotations

import errno
import os
import sys
from typing import Optional

from . import fsguard, recovery
from .config import Config, load_config
from .context import build_context
from .receipts import Receipt, append_receipt


def available() -> bool:
    """True when this machine could actually mount something."""
    if os.name != "nt":
        return False
    try:
        import winfspy  # noqa: F401
        return True
    except Exception:
        return False


def absolute_target(mountpoint: Optional[str], virtual: str) -> str:
    """Turn a mount-relative virtual path into a real filesystem path.

    'src/app.py' -> 'C:\\Users\\pc\\Desktop\\fslab\\guarded\\src\\app.py'

    WHY THIS EXISTS (defect W5, found 2026-08-24 by the last test of the day).
    WinFsp speaks in paths relative to the mount, so a verdict names
    'notes.txt'. Recording that bare string in the ledger is a lie of
    omission: `recovery.restore_entry` does `shutil.copy2(recovery_point,
    target)`, and a relative target resolves against whatever directory
    `demo_cli undo` is run from. Run inside the mount it was correct; run one
    level up - which still finds the recovery index, because .demo_cli lives
    there - undo wrote the file OUTSIDE the mount and reported RESTORED. The
    file the user wanted back was still gone.

    A ledger entry must mean the same thing from every working directory.

    Module-level rather than a method so it can be tested off Windows: the
    class it serves cannot even be constructed without winfspy, which is the
    same reason fsguard.py holds the judgement logic and this file holds only
    the plumbing.
    """
    if not mountpoint:
        return virtual
    return os.path.join(mountpoint, virtual.replace("/", os.sep))


def mountpoint_obstruction(mountpoint: str,
                           workspace_dir: str = ".demo_cli") -> Optional[str]:
    """Why this path cannot be mounted over, or None if it is safe to clear.

    WinFsp creates the mount point itself, so the path must NOT exist first.
    The old check was `if os.path.exists(...): refuse`, which is right for a
    directory holding somebody's work and wrong for the two cases that
    actually occur after a reboot:

      a dangling reparse point   a POINTER to a filesystem that is no longer
                                 running. Removing it removes nothing; the
                                 bytes are in the backing directory.
      an empty leftover          a directory some other demo_cli command
                                 conjured while the guard was down (see
                                 config.ensure_workspace). Nothing of the
                                 user's is inside it.

    Both used to be permanent: the logon task refused, every boot, and the
    only route back was rmdir by hand - which the person would have to know
    was safe. Judgement belongs here, in the module that can be tested off
    Windows, not in the .cmd file the scheduled task runs.

    STRICTLY EMPTY, deliberately. A .demo_cli with anything in it holds
    receipts and recovery points - the evidence the whole tool exists to
    produce - so it is an obstruction like any other. This function's job is
    to separate "nothing would be lost" from "something might be", and when it
    cannot tell, it says so and the mount refuses.
    """
    if not os.path.lexists(mountpoint):
        return None
    if os.path.islink(mountpoint):
        return None                      # a link holds no bytes of its own
    if not os.path.isdir(mountpoint):
        return f"{mountpoint} exists and is a file, not a directory"
    try:
        entries = os.listdir(mountpoint)
    except OSError as e:
        return f"{mountpoint} exists and cannot be read ({e.strerror})"

    others = sorted(e for e in entries if e != workspace_dir)
    if others:
        shown = ", ".join(others[:4]) + (", ..." if len(others) > 4 else "")
        return f"{mountpoint} already exists and contains: {shown}"
    if workspace_dir in entries:
        ws = os.path.join(mountpoint, workspace_dir)
        try:
            if os.listdir(ws):
                return (f"{mountpoint} holds a non-empty {workspace_dir} - "
                        f"receipts or recovery points live there")
        except OSError as e:
            return f"{ws} cannot be read ({e.strerror})"
    return None


def clear_mountpoint(mountpoint: str, workspace_dir: str = ".demo_cli") -> bool:
    """Remove a mount point that mountpoint_obstruction() has cleared.

    Returns True if something was removed. Callers MUST consult
    mountpoint_obstruction first; this deletes without re-judging.

    os.rmdir, never shutil.rmtree. rmdir refuses a directory that is not
    empty, so if the judgement above were ever wrong this fails loudly instead
    of taking a tree with it - the same reason schedule.py's script uses
    `rmdir` and not `rmdir /s`.
    """
    if not os.path.lexists(mountpoint):
        return False
    if os.path.islink(mountpoint):
        # A LINK IS REMOVED DIFFERENTLY ON EACH PLATFORM, and neither call
        # follows it, so the backing directory is untouched either way.
        # POSIX: unlink, even when it points at a directory - rmdir raises
        # NotADirectoryError. Windows: a junction or directory symlink needs
        # rmdir, and unlink raises. Caught by the test on Linux rather than
        # assumed, which is how the four earlier platform-shaped assumptions
        # in this project should have been found.
        try:
            os.unlink(mountpoint)
        except OSError:
            os.rmdir(mountpoint)
        return True
    ws = os.path.join(mountpoint, workspace_dir)
    if os.path.isdir(ws):
        os.rmdir(ws)
    os.rmdir(mountpoint)
    return True


def config_anchor(mountpoint: str, backing: Optional[str] = None) -> str:
    """Which directory the mount's config and ledger are resolved from.

    NOT the current directory, which is what load_config() defaults to.
    Observed three times in two days: the same lab mounted from three
    different shells put its recovery points in three different ledgers, and
    `demo_cli undo` answered "No recovery points found" while the files sat
    intact somewhere else entirely. Twenty minutes went into the second one.

    A mount's scope is the mountpoint, so the ledger has to follow the thing
    being protected rather than the shell that launched the protection - which
    the mount may well outlive, and is exactly what --detach is for.

        backing given   the backing directory. It holds the real files and it
                        always exists.
        otherwise       the mount point's PARENT. The mount point itself
                        cannot be used: WinFsp has not created it yet, and
                        find_project_root would walk from a path that is not
                        there.

    Module level so it can be tested off Windows, like absolute_target.
    """
    if backing:
        return os.path.abspath(backing)
    return os.path.dirname(os.path.abspath(mountpoint)) or os.path.abspath(mountpoint)


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError(
            "The filesystem guard requires Windows (WinFsp). On Linux the "
            "equivalent layer is the syscall guard: demo_cli run <cmd>."
        )
    try:
        import winfspy  # noqa: F401
    except Exception as exc:
        raise RuntimeError(
            f"winfspy is not importable ({exc}). Install WinFsp from winfsp.dev "
            "with the Developer feature enabled, then: pip install winfspy"
        ) from None


def build_operations(config: Config, volume_label: str = "demo_cli",
                     mountpoint: Optional[str] = None):
    """Build the guarded filesystem. winfspy is imported here, not at module
    scope, so this file stays importable on any platform.

    `mountpoint` is what makes recorded targets absolute - see `_absolute`. It
    is optional only so the class can be constructed in tests without a mount;
    `mount()` always supplies it.
    """
    _require_windows()

    from pathlib import PureWindowsPath

    from winfspy.memfs import FileObj, InMemoryFileSystemOperations

    class GuardedFileSystem(InMemoryFileSystemOperations):
        """An in-memory filesystem that snapshots before it destroys.

        None of these overrides carry winfspy's `@operation` decorator. That
        decorator takes `self._thread_lock`, and `super()` is decorated already
        - decorating here too would take a non-reentrant lock twice and
        deadlock the mount.
        """

        def __init__(self, label: str, cfg: Config, read_only: bool = False,
                     mountpoint: Optional[str] = None):
            super().__init__(label, read_only)
            self.cfg = cfg
            self.mountpoint = mountpoint
            self.captured = 0
            self.skipped = 0

        def _absolute(self, virtual: str) -> str:
            return absolute_target(self.mountpoint, virtual)

        # ------------------------------------------------------------------
        # A bug in winfspy's own reference implementation, not ours.
        #
        # read_directory() filters entries after a pagination marker. When the
        # marker names an entry that has just been DELETED - exactly what a
        # recursive delete does - the loop matches nothing, falls off the end,
        # and implicitly returns None. ll_read_directory then raises
        # `TypeError: 'NoneType' object is not iterable`, the operation fails,
        # and the directory tree is left HALF DELETED while PowerShell reports
        # only a generic I/O error. 100% reproducible on 0.8.4.
        #
        # Inheriting from InMemoryFileSystemOperations inherits the bug, so it
        # is corrected here. Worth reporting upstream.
        # ------------------------------------------------------------------
        def read_directory(self, file_context, marker):
            entries = super().read_directory(file_context, marker)
            return [] if entries is None else entries

        # ------------------------------------------------------------------
        # The four destructive hooks
        # ------------------------------------------------------------------

        def cleanup(self, file_context, file_name, flags):
            verdict = fsguard.on_cleanup(file_name, flags)
            if verdict.destructive:
                self._capture(verdict, file_context.file_obj)
            return super().cleanup(file_context, file_name, flags)

        def set_file_size(self, file_context, new_size, set_allocation_size):
            obj = file_context.file_obj
            verdict = fsguard.on_set_file_size(obj.file_name, new_size, obj.file_size)
            if verdict.destructive:
                self._capture(verdict, obj)
            return super().set_file_size(file_context, new_size, set_allocation_size)

        def rename(self, file_context, file_name, new_file_name, replace_if_exists):
            # The DESTINATION is what dies here, and nothing else will ever
            # announce it - no cleanup, no can_delete. Look it up before the
            # rename runs, because afterwards it is gone.
            destination = self._entries.get(PureWindowsPath(new_file_name))
            verdict = fsguard.on_rename(file_name, new_file_name, replace_if_exists,
                                        dest_exists=destination is not None)
            if verdict.destructive:
                self._capture(verdict, destination)
            return super().rename(file_context, file_name, new_file_name,
                                  replace_if_exists)

        def overwrite(self, file_context, file_attributes,
                      replace_file_attributes, allocation_size):
            obj = file_context.file_obj
            verdict = fsguard.on_overwrite(obj.file_name, exists=obj.file_size > 0)
            if verdict.destructive:
                self._capture(verdict, obj)
            return super().overwrite(file_context, file_attributes,
                                     replace_file_attributes, allocation_size)

        # ------------------------------------------------------------------
        # Snapshot + receipt
        # ------------------------------------------------------------------

        def _capture(self, verdict: fsguard.Verdict, file_obj) -> None:
            """Preserve the bytes about to be destroyed, then record it.

            Never raises: a fault in the guard must not break the filesystem
            the user is working in. A failure is recorded as an honest
            ESCALATE receipt rather than a silent pass - the operation still
            proceeds, but the ledger says no recovery was taken.
            """
            if not isinstance(file_obj, FileObj):
                # Directories hold no bytes of their own. Their contents are
                # deleted leaf-first, so each file gets its own cleanup call.
                self.skipped += 1
                return

            entry, reason = None, None
            try:
                # A snapshot of a live buffer. bytes() copies in one step,
                # which is as close to atomic as this gets - winfspy dispatches
                # from a thread pool and only the decorated bodies are locked.
                data = bytes(file_obj.data[: file_obj.file_size])
                entry = recovery.snapshot_bytes(
                    # `name` only decides the .bak filename, so the short
                    # virtual path is right there. `target` is where `undo`
                    # will WRITE, so it must be absolute - see _absolute.
                    verdict.target, data, self.cfg.recovery_dir,
                    action=f"{verdict.kind} {verdict.target}",
                    target=self._absolute(verdict.target),
                )
            except Exception as exc:                      # pragma: no cover
                reason = f"could not capture {verdict.target}: {exc}"

            self._receipt(verdict, entry, reason)
            if entry:
                self.captured += 1
                sys.stderr.write(
                    f"demo_cli [fs] {verdict.kind}: {verdict.target} "
                    f"snapshotted ({entry['id']}) - undo: demo_cli undo {entry['id']}\n")

        def _receipt(self, verdict, entry, failure: Optional[str]) -> None:
            try:
                ctx = build_context(verdict.target or "", cwd=self.cfg.project_root)
                append_receipt(self.cfg.receipts_path, Receipt(
                    action_raw=f"[fs] {verdict.kind} {verdict.target}",
                    action_type="filesystem",
                    target_environment=ctx.environment,
                    decision="REVERSIBLE" if entry else "ESCALATE",
                    reason=failure or f"Snapshotted before {verdict.reason}.",
                    mode="enforce-fs",
                    matched_rule=f"fs_{verdict.kind}",
                    classification="destructive",
                    recovery_point=entry["recovery_point"] if entry else None,
                    context=ctx.as_dict(),
                    agent_id="fsguard",
                    session_id="mount",
                ))
            except Exception as exc:                      # pragma: no cover
                sys.stderr.write(f"demo_cli [fs] receipt error: {exc}\n")

    return GuardedFileSystem(volume_label, config, mountpoint=mountpoint)


def build_passthrough_operations(config: Config, backing_dir: str,
                                 volume_label: str = "demo_cli",
                                 mountpoint: Optional[str] = None):
    """STAGE 2: the same guard, over a real directory instead of memory.

    Stage 1 keeps files in a Python dict and loses everything on unmount,
    which makes it a laboratory instrument. This maps every operation onto a
    real backing directory, so the mount can be unmounted and the work is
    still there.

    THE FOUR DESTRUCTIVE HOOKS AND ALL OF fsguard.py ARE UNCHANGED. Only where
    the bytes live changes - the payoff of having split judgement from
    plumbing at the start, collected a second time.

    Written against the installed winfspy 0.8.4 source rather than from
    documentation, for the same reason the hooks were: three of the four probe
    findings contradicted what the API's own method names imply.

    NO GLOBAL LOCK, unlike winfspy's memfs. memfs must serialise because its
    state is a shared dict; ours is the operating system, whose individual
    calls are already atomic, and whose positional reads and writes take an
    offset instead of moving a shared file position (fspassthrough.read_at).
    Serialising here would throw away the concurrency for nothing.
    """
    _require_windows()

    from winfspy import (BaseFileSystemOperations, CREATE_FILE_CREATE_OPTIONS,
                         FILE_ATTRIBUTE, NTStatusAccessDenied,
                         NTStatusDirectoryNotEmpty, NTStatusEndOfFile,
                         NTStatusError, NTStatusNotADirectory,
                         NTStatusObjectNameCollision, NTStatusObjectNameNotFound)
    from winfspy.plumbing.security_descriptor import SecurityDescriptor
    from winfspy.plumbing.win32_filetime import filetime_now

    from .fspassthrough import (Backing, PathEscape, is_directory_not_empty,
                                normalize)

    EPOCH_AS_FILETIME = 116444736000000000
    ALLOCATION_UNIT = 4096

    def _filetime(unix_seconds: float) -> int:
        """os.stat gives seconds since 1970; Windows wants 100ns units since
        1601. Getting this wrong does not fail loudly - it makes every file
        look like it was written in 1601, and tools that compare timestamps
        (make, git, an editor's reload prompt) start behaving strangely."""
        return int(unix_seconds * 10_000_000) + EPOCH_AS_FILETIME

    def guarded(fn):
        """Turn any leaked OSError into a proper NTSTATUS.

        An unhandled exception inside a filesystem operation is not a bug
        report, it is a broken filesystem: winfspy prints a traceback and the
        caller gets a generic "I/O device error" with no idea what happened -
        which is exactly what the first live passthrough run produced. Windows
        has status codes for all of these; using them means the shell prints
        "access denied" or "file exists" and the mount stays healthy.

        NTStatus exceptions pass through untouched: they are the intended
        signalling mechanism, not errors.
        """
        import functools

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except NTStatusError:
                raise
            except PathEscape:
                raise NTStatusObjectNameNotFound()
            except FileExistsError:
                raise NTStatusObjectNameCollision()
            except FileNotFoundError:
                raise NTStatusObjectNameNotFound()
            except NotADirectoryError:
                raise NTStatusNotADirectory()
            except OSError as exc:
                if exc.errno == errno.ENOTEMPTY:
                    raise NTStatusDirectoryNotEmpty()
                # EVERY converted failure is logged, including the permission
                # ones. The first version stayed silent for PermissionError
                # because "access denied" felt self-explanatory - and then a
                # read through the mount failed with an empty log and nothing
                # to debug from. A guard that swallows the interesting failure
                # is the recurring bug in this project; the caller gets a clean
                # NTSTATUS either way, so the log costs nothing.
                sys.stderr.write(f"demo_cli [fs] {fn.__name__} denied: {exc}\n")
                raise NTStatusAccessDenied()
        return wrapper

    class Handle:
        """One open file or directory. WinFsp hands this back on every call.

        Holds the VIRTUAL path, not the real one: every translation goes
        through Backing.resolve, which is the single place containment is
        enforced. Caching a resolved path here would be a second door.
        """
        __slots__ = ("virtual", "is_dir", "fd")

        def __init__(self, virtual, is_dir, fd=None):
            self.virtual, self.is_dir, self.fd = virtual, is_dir, fd

    class PassthroughOperations(BaseFileSystemOperations):

        def __init__(self, label: str, backing: Backing, cfg: Config,
                     mount: Optional[str] = None):
            super().__init__()
            if len(label) > 31:
                raise ValueError("`volume_label` must be 31 characters max")
            self.backing = backing
            self.cfg = cfg
            self.mountpoint = mount
            self.captured = 0
            self.skipped = 0
            self._label = label
            # One descriptor for everything. The backing directory's own ACL
            # is the real access control - and under `demo_cli protect` that
            # ACL is the whole point, because it is what stops anyone writing
            # to the backing directory behind the mount's back.
            self._sd = SecurityDescriptor.from_string(
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)")

        # ------------------------------------------------------------------
        # Translation
        # ------------------------------------------------------------------

        def _info(self, virtual: str) -> dict:
            try:
                a = self.backing.attrs(virtual)
            except PathEscape:
                raise NTStatusObjectNameNotFound()
            except FileNotFoundError:
                raise NTStatusObjectNameNotFound()
            attrs = (FILE_ATTRIBUTE.FILE_ATTRIBUTE_DIRECTORY if a.is_dir
                     else FILE_ATTRIBUTE.FILE_ATTRIBUTE_ARCHIVE)
            if a.readonly:
                attrs |= FILE_ATTRIBUTE.FILE_ATTRIBUTE_READONLY
            allocation = ((a.size + ALLOCATION_UNIT - 1) // ALLOCATION_UNIT) * ALLOCATION_UNIT
            return {
                "file_attributes": attrs,
                "allocation_size": allocation,
                "file_size": a.size,
                "creation_time": _filetime(a.ctime),
                "last_access_time": _filetime(a.atime),
                "last_write_time": _filetime(a.mtime),
                "change_time": _filetime(a.mtime),
                "index_number": 0,
            }

        # ------------------------------------------------------------------
        # Volume
        # ------------------------------------------------------------------

        @guarded
        def get_volume_info(self):
            """Real free space from the backing volume. Reporting a made-up
            number makes installers and editors refuse to write, or write
            until the disk genuinely fills."""
            import shutil as _sh
            usage = _sh.disk_usage(self.backing.root)
            return {"total_size": usage.total, "free_size": usage.free,
                    "volume_label": self._label}

        @guarded
        def set_volume_label(self, volume_label):
            self._label = volume_label

        # ------------------------------------------------------------------
        # Lookup, create, open
        # ------------------------------------------------------------------

        @guarded
        def get_security_by_name(self, file_name):
            info = self._info(file_name)
            return info["file_attributes"], self._sd.handle, self._sd.size

        @guarded
        def get_security(self, file_context):
            return self._sd

        @guarded
        def set_security(self, file_context, security_information,
                         modification_descriptor):
            # Deliberately a no-op. Per-file ACLs inside the mount would
            # suggest a protection the backing directory does not actually
            # provide; the backing ACL is the real boundary.
            pass

        @guarded
        def create(self, file_name, create_options, granted_access,
                   file_attributes, security_descriptor, allocation_size):
            virtual = normalize(file_name)
            try:
                if self.backing.exists(virtual):
                    raise NTStatusObjectNameCollision()
                parent = "/".join(virtual.split("/")[:-1])
                if parent and not self.backing.is_dir(parent):
                    raise NTStatusObjectNameNotFound()
                is_dir = bool(create_options
                              & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE)
                if is_dir:
                    self.backing.make_dir(virtual)
                    return Handle(virtual, True)
                self.backing.make_file(virtual)
                return Handle(virtual, False, self.backing.open_fd(virtual))
            except PathEscape:
                raise NTStatusObjectNameNotFound()
            except FileExistsError:
                raise NTStatusObjectNameCollision()
            except FileNotFoundError:
                raise NTStatusObjectNameNotFound()
            except NotADirectoryError:
                raise NTStatusNotADirectory()

        @guarded
        def open(self, file_name, create_options, granted_access):
            virtual = normalize(file_name)
            try:
                if not self.backing.exists(virtual):
                    raise NTStatusObjectNameNotFound()
                if self.backing.is_dir(virtual):
                    return Handle(virtual, True)
                return Handle(virtual, False, self.backing.open_fd(virtual))
            except PathEscape:
                raise NTStatusObjectNameNotFound()
            except PermissionError:
                # A file we may read but not write still has to OPEN, or the
                # mount cannot show read-only content at all.
                return Handle(virtual, False, self.backing.open_fd(virtual, write=False))

        @guarded
        def close(self, file_context):
            if file_context.fd is not None:
                try:
                    os.close(file_context.fd)
                except OSError:
                    pass
                file_context.fd = None

        @guarded
        def get_file_info(self, file_context):
            return self._info(file_context.virtual)

        @guarded
        def set_basic_info(self, file_context, file_attributes, creation_time,
                           last_access_time, last_write_time, change_time,
                           file_info) -> dict:
            # Timestamps and attributes are not mutated on the backing file.
            # They destroy nothing, the OS maintains them, and writing them
            # back would mean converting FILETIME to Unix time on every
            # touch for no benefit the caller can observe.
            return self._info(file_context.virtual)

        @guarded
        def flush(self, file_context) -> None:
            if file_context.fd is not None:
                os.fsync(file_context.fd)

        # ------------------------------------------------------------------
        # Reading
        # ------------------------------------------------------------------

        @guarded
        def read(self, file_context, offset, length):
            size = self.backing.size_of_fd(file_context.fd)
            if offset >= size:
                raise NTStatusEndOfFile()
            return self.backing.read_at(file_context.fd, offset, length)

        @guarded
        def read_directory(self, file_context, marker):
            virtual = file_context.virtual
            if not self.backing.is_dir(virtual):
                raise NTStatusNotADirectory()

            entries = []
            if virtual:                       # '.' and '..' only below the root
                parent = "/".join(virtual.split("/")[:-1])
                entries.append({"file_name": ".", **self._info(virtual)})
                entries.append({"file_name": "..", **self._info(parent)})
            for name in self.backing.listdir(virtual):
                child = f"{virtual}/{name}" if virtual else name
                try:
                    entries.append({"file_name": name, **self._info(child)})
                except Exception:
                    # A file deleted between listdir and stat is normal on a
                    # live filesystem. Skipping it beats failing the listing.
                    continue
            entries.sort(key=lambda e: e["file_name"])

            if marker is None:
                return entries
            for i, entry in enumerate(entries):
                if entry["file_name"] == marker:
                    return entries[i + 1:]
            # THE winfspy memfs BUG, avoided rather than inherited: falling off
            # this loop returns None, ll_read_directory raises TypeError, and a
            # recursive delete leaves the tree HALF DELETED behind a generic
            # I/O error. The marker naming a just-deleted entry is exactly what
            # a recursive delete produces.
            return []

        @guarded
        def get_dir_info_by_name(self, file_context, file_name):
            parent = file_context.virtual
            child = f"{parent}/{file_name}" if parent else file_name
            return {"file_name": file_name, **self._info(child)}

        # ------------------------------------------------------------------
        # Writing
        # ------------------------------------------------------------------

        @guarded
        def write(self, file_context, buffer, offset, write_to_end_of_file,
                  constrained_io):
            fd = file_context.fd
            size = self.backing.size_of_fd(fd)
            if write_to_end_of_file:
                offset = size
            if constrained_io:
                # "Write only within the current file size" - the caller wants
                # no extension. Silently growing the file here would corrupt
                # the caller's own bookkeeping.
                if offset >= size:
                    return 0
                buffer = bytes(buffer)[: size - offset]
            return self.backing.write_at(fd, bytes(buffer), offset)

        # ------------------------------------------------------------------
        # The four destructive hooks - IDENTICAL DECISIONS TO STAGE 1
        # ------------------------------------------------------------------

        @guarded
        def cleanup(self, file_context, file_name, flags) -> None:
            verdict = fsguard.on_cleanup(file_name or file_context.virtual, flags)
            if verdict.destructive:
                self._capture(verdict)
            if not flags & fsguard.FSP_CLEANUP_DELETE:
                return

            # Drop our own descriptor first. FILE_SHARE_DELETE makes the unlink
            # legal with the handle open, but Windows then marks the file
            # DELETE-PENDING and only removes it once every handle closes - so
            # it would linger, visible, after a delete the user watched
            # succeed. Closing here makes the removal immediate.
            fd, file_context.fd = file_context.fd, None
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

            try:
                self.backing.remove(file_context.virtual)
            except OSError as exc:
                if is_directory_not_empty(exc):
                    # Expected and not a failure: Windows removes a tree
                    # leaf-first and will come back for this directory once
                    # its children are gone.
                    return
                # ANYTHING ELSE MUST BE SAID OUT LOUD.
                #
                # This used to be a bare `except OSError: pass`, written for
                # the case above and silently swallowing every other one. On
                # 2026-08-25 a Remove-Item printed no error, produced a
                # "[fs] delete ... snapshotted" line, and left the file sitting
                # in the backing directory. The ledger recorded a destruction
                # that never happened, and the user's delete never happened
                # either - both silently.
                #
                # cleanup() cannot return a status to Windows (it is void, and
                # WinFsp ignores errors here), so raising would tell nobody.
                # Saying so on stderr and in the ledger is the only honest
                # option left.
                sys.stderr.write(
                    f"demo_cli [fs] DELETE FAILED: {file_context.virtual} "
                    f"still exists ({exc.strerror or exc}). Any snapshot taken "
                    f"for it describes a file that was not destroyed.\n")
                if verdict.destructive:
                    self._receipt(verdict, None,
                                  f"delete did not complete: {exc.strerror or exc}. "
                                  f"The file is unchanged.")

        @guarded
        def set_file_size(self, file_context, new_size, set_allocation_size):
            fd = file_context.fd
            current = self.backing.size_of_fd(fd)
            verdict = fsguard.on_set_file_size(file_context.virtual, new_size, current)
            if verdict.destructive:
                self._capture(verdict)
            if not set_allocation_size:
                self.backing.set_size_fd(fd, new_size)
            elif new_size < current:
                self.backing.set_size_fd(fd, new_size)

        @guarded
        def rename(self, file_context, file_name, new_file_name, replace_if_exists):
            # The DESTINATION is what dies, and nothing else will announce it:
            # no cleanup, no can_delete. This is Claude Code's Write tool on
            # every save, and the single reason this layer exists.
            dest = normalize(new_file_name)
            verdict = fsguard.on_rename(file_name, new_file_name, replace_if_exists,
                                        dest_exists=self.backing.exists(dest))
            if verdict.destructive:
                self._capture(verdict)

            # Release our own descriptor first. FILE_SHARE_DELETE (see
            # fspassthrough._open_fd_windows) is what makes the rename legal at
            # all; dropping the handle as well costs nothing and removes the
            # last thing on our side that could hold the file. The handle is
            # reopened afterwards because WinFsp keeps using this context.
            fd, file_context.fd = file_context.fd, None
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                self.backing.rename(normalize(file_name), dest, replace_if_exists)
                file_context.virtual = dest
            except FileExistsError:
                raise NTStatusObjectNameCollision()
            except PathEscape:
                raise NTStatusObjectNameNotFound()
            finally:
                if not file_context.is_dir:
                    try:
                        file_context.fd = self.backing.open_fd(file_context.virtual)
                    except OSError:
                        pass        # reads through this context will fail; the
                                    # rename itself already succeeded or raised

        @guarded
        def overwrite(self, file_context, file_attributes,
                      replace_file_attributes, allocation_size) -> None:
            fd = file_context.fd
            exists = self.backing.size_of_fd(fd) > 0
            verdict = fsguard.on_overwrite(file_context.virtual, exists=exists)
            if verdict.destructive:
                self._capture(verdict)
            self.backing.set_size_fd(fd, 0)

        @guarded
        def can_delete(self, file_context, file_name: str) -> None:
            virtual = normalize(file_name)
            if self.backing.is_dir(virtual) and self.backing.listdir(virtual):
                raise NTStatusDirectoryNotEmpty()

        # ------------------------------------------------------------------
        # Snapshot + receipt
        # ------------------------------------------------------------------

        def _capture(self, verdict: fsguard.Verdict) -> None:
            """Preserve the bytes about to be destroyed.

            The ONE substantive difference from Stage 1: the content is read
            off the backing filesystem instead of copied out of a Python
            bytearray. Everything after that - the recovery entry, the
            receipt, the honesty of the ledger - is identical.

            Never raises: a fault in the guard must not break the filesystem
            somebody is working in. A failure is recorded as an ESCALATE
            receipt rather than passing silently.
            """
            if self.backing.is_dir(verdict.target):
                # Directories hold no bytes of their own; their contents are
                # deleted leaf-first and each file gets its own verdict.
                self.skipped += 1
                return

            entry, reason = None, None
            try:
                data = self.backing.read_all(verdict.target)
                entry = recovery.snapshot_bytes(
                    verdict.target, data, self.cfg.recovery_dir,
                    action=f"{verdict.kind} {verdict.target}",
                    target=absolute_target(self.mountpoint, verdict.target),
                )
            except Exception as exc:                      # pragma: no cover
                reason = f"could not capture {verdict.target}: {exc}"

            self._receipt(verdict, entry, reason)
            if entry:
                self.captured += 1
                sys.stderr.write(
                    f"demo_cli [fs] {verdict.kind}: {verdict.target} "
                    f"snapshotted ({entry['id']}) - undo: demo_cli undo {entry['id']}\n")

        def _receipt(self, verdict, entry, failure: Optional[str]) -> None:
            try:
                ctx = build_context(verdict.target or "", cwd=self.cfg.project_root)
                append_receipt(self.cfg.receipts_path, Receipt(
                    action_raw=f"[fs] {verdict.kind} {verdict.target}",
                    action_type="filesystem",
                    target_environment=ctx.environment,
                    decision="REVERSIBLE" if entry else "ESCALATE",
                    reason=failure or f"Snapshotted before {verdict.reason}.",
                    mode="enforce-fs",
                    matched_rule=f"fs_{verdict.kind}",
                    classification="destructive",
                    recovery_point=entry["recovery_point"] if entry else None,
                    context=ctx.as_dict(),
                    agent_id="fsguard",
                    session_id="passthrough",
                ))
            except Exception as exc:                      # pragma: no cover
                sys.stderr.write(f"demo_cli [fs] receipt error: {exc}\n")

    return PassthroughOperations(volume_label, Backing(backing_dir), config,
                                 mountpoint)


def mount(mountpoint: str, config: Optional[Config] = None,
          label: str = "demo_cli", debug: bool = False,
          backing: Optional[str] = None):
    """Mount the guarded filesystem and block until interrupted.

    `mountpoint` may be a drive letter (`X:`) or a directory path. A directory
    is strongly preferred: Claude Code refuses to use a bare drive root as its
    working directory, while a directory mount it accepts with no special
    flags. WinFsp CREATES the path as a junction, so it must NOT already exist.

    `backing` selects the stage, and the difference matters to whoever is
    about to work in this directory:

        None            STAGE 1, in memory. Contents are LOST on unmount.
                        A laboratory instrument - fine for proving the guard,
                        not fine for real work.
        a directory     STAGE 2, passthrough. Files live in that directory and
                        survive unmounting.

    The two share fsguard.py and every destructive decision. Only storage
    differs.
    """
    _require_windows()

    from pathlib import Path

    from winfspy import FileSystem
    from winfspy.plumbing.win32_filetime import filetime_now

    # Resolved before the filesystem is built: the operations object needs the
    # mount point to record absolute targets, and a relative mountpoint would
    # reintroduce exactly the cwd-dependence W5 was about.
    path = Path(os.path.abspath(mountpoint))
    is_drive = path.parent == path
    backing = os.path.abspath(backing) if backing else None

    # THE CONFIG IS ANCHORED TO WHAT IS BEING GUARDED, NOT TO THE SHELL.
    #
    # load_config() defaults to walking up from the current directory, which
    # for a mount is whatever the user happened to be standing in. Observed
    # three times in two days: the same lab mounted from three directories put
    # its recovery points in three different ledgers, and `demo_cli undo`
    # answered "No recovery points found" while the files sat intact somewhere
    # else. Twenty minutes went into the second one.
    #
    # A mount's scope is the mountpoint. The ledger has to follow the thing
    # being protected, not the shell that launched the protection - the mount
    # may outlive that shell entirely, which is precisely what --detach is for.
    #
    if config is None:
        config = load_config(config_anchor(str(path), backing))

    if backing:
        # The backing directory must not be inside the mount point, or the
        # filesystem would be storing its own contents through itself.
        try:
            if os.path.commonpath([backing, str(path)]) == str(path):
                raise RuntimeError(
                    f"the backing directory {backing} is inside the mount point "
                    f"{path}; they must be separate.")
        except ValueError:
            pass                       # different drives: fine
        operations = build_passthrough_operations(config, backing, label, str(path))
    else:
        operations = build_operations(config, label, mountpoint=str(path))

    fs = FileSystem(
        str(path), operations,
        sector_size=512,
        sectors_per_allocation_unit=1,
        volume_creation_time=filetime_now(),
        volume_serial_number=0,
        file_info_timeout=1000,
        case_sensitive_search=1,
        case_preserved_names=1,
        unicode_on_disk=1,
        persistent_acls=1,
        post_cleanup_when_modified_only=1,
        um_file_context_is_user_context2=1,
        file_system_name=str(path),
        prefix="",
        debug=debug,
        # A directory mount needs this; a drive letter does not.
        reject_irp_prior_to_transact0=not is_drive,
    )

    fs.start()
    # The storage line is deliberately blunt. Somebody who does not read it and
    # works in a Stage 1 mount loses everything on Ctrl+C, so it says so in
    # those words rather than in a euphemism.
    storage = (f"  backing         -> {backing}  (files SURVIVE unmount)\n"
               if backing else
               "  in-memory: contents are LOST on unmount; snapshots are on real disk.\n")
    sys.stderr.write(
        f"demo_cli filesystem guard mounted at {path}\n"
        f"  project root    -> {config.project_root}\n"
        f"  recovery points -> {config.recovery_dir}\n"
        f"  receipts        -> {config.receipts_path}\n"
        + storage +
        f"  undo from anywhere:  demo_cli undo <id> --root {config.project_root}\n"
        f"  Ctrl+C to unmount.\n")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        fs.stop()
        sys.stderr.write(
            f"demo_cli filesystem guard stopped. "
            f"{operations.captured} snapshot(s) taken.\n")
    return operations
