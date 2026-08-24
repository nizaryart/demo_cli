"""Windows behavioural guard: the WinFsp filesystem that does the intercepting.

`fsguard.py` decides WHAT is destructive. This is the part that stands where it
can see - a user-mode filesystem below the syscall boundary, where the Win32,
ntdll and direct-syscall routes have all converged, so no amount of obfuscation
in the command text can route around it.

WINDOWS ONLY. `winfspy` is imported lazily inside `build_operations`, never at
module scope, so importing this file on Linux is harmless - the same
arrangement `syscall_guard.py` uses for its `ctypes.CDLL("libc.so.6")`.

Stage 1 (this file) mounts an IN-MEMORY filesystem. That is deliberate: it
proves interception, snapshotting and undo end to end without also having to
write a correct passthrough filesystem, which is 600+ lines whose failure mode
is corrupting the user's real files. Recovery points are written to the REAL
disk, so they survive the mount.

Stage 2, not built: passthrough over real storage. The hooks below do not
change; only where the bytes live does.

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


def mount(mountpoint: str, config: Optional[Config] = None,
          label: str = "demo_cli", debug: bool = False):
    """Mount the guarded filesystem and block until interrupted.

    `mountpoint` may be a drive letter (`X:`) or a directory path. A directory
    is strongly preferred: Claude Code refuses to use a bare drive root as its
    working directory, while a directory mount it accepts with no special
    flags. WinFsp CREATES the path as a junction, so it must NOT already exist.
    """
    _require_windows()

    from pathlib import Path

    from winfspy import FileSystem
    from winfspy.plumbing.win32_filetime import filetime_now

    config = config or load_config()

    # Resolved before the filesystem is built: the operations object needs the
    # mount point to record absolute targets, and a relative mountpoint would
    # reintroduce exactly the cwd-dependence W5 was about.
    path = Path(os.path.abspath(mountpoint))
    is_drive = path.parent == path

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
    sys.stderr.write(
        f"demo_cli filesystem guard mounted at {path}\n"
        f"  recovery points -> {config.recovery_dir}\n"
        f"  receipts        -> {config.receipts_path}\n"
        f"  in-memory: contents are LOST on unmount; snapshots are on real disk.\n"
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
