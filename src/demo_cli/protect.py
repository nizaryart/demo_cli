r"""Turn an ordinary project into a guarded one, and back again.

WHAT `protect` DOES AND WHY IT HAS TO MOVE YOUR FILES:
A WinFsp directory mount point is an NTFS reparse point, and Windows only sets
one on an empty or non-existent directory. So the project's path is vacated
before mounting:
    before      C:\project                 ordinary directory
    after       C:\project.real            the bytes (locked down)
                C:\project                 the mount, created by WinFsp

Moving (via os.rename) rather than mounting as a drive letter keeps existing
paths and tool configs intact.

THE LOCK:
Relocating alone does not protect files; the backing directory must be protected
with an ACL granting access only to Administrators and SYSTEM. The mount runs
elevated while the agent runs normally (unelevated), preventing direct bypass.

UNPROTECT:
Restores original ACLs and moves the project directory back home.
"""
from __future__ import annotations

import json
import ntpath
import os
import re
import shutil
import stat
import sys
import subprocess
import tempfile

try:
    # Imported at module scope so platform detection is static, preventing
    # issues on non-Windows environments when os.name is monkeypatched in tests.
    import ctypes
except Exception:                       # pragma: no cover - ctypes is stdlib
    ctypes = None
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .fspassthrough import Backing

# Suffix used for the backing directory of a protected project.
BACKING_SUFFIX = ".real"

# Absolute path to icacls.exe to prevent binary hijacking from the current
# working directory when running elevated.
_ICACLS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "icacls.exe")


def _icacls_present() -> bool:
    """Return True if icacls.exe exists at the expected System32 path."""
    return os.path.isfile(_ICACLS)

# SIDs permitted to access the backing directory when locked. Using SIDs avoids
# localized group name mismatches across Windows installations.
SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"

# OWNER RIGHTS (S-1-3-4): Replaces the owner's implicit full rights (READ_CONTROL
# and WRITE_DAC) with (RC) [read ACL only]. This prevents the user/agent from
# re-granting themselves access or moving the locked backing directory, while
# allowing is_locked() to verify DACL permissions without elevation.
OWNER_RIGHTS_SID = "S-1-3-4"

# (sid, icacls rights) - the whole definition of a locked directory, in the
# order icacls is asked to apply it.
_LOCK_ACL = [(SYSTEM_SID, "(OI)(CI)F"),
             (ADMINS_SID, "(OI)(CI)F"),
             (OWNER_RIGHTS_SID, "(OI)(CI)(RC)")]

_ACL_PRINCIPALS = [f"*{sid}" for sid, _ in _LOCK_ACL]


@dataclass
class Plan:
    """Structured plan for protect/unprotect operations."""
    source: str
    backing: str
    mountpoint: str
    will_lock: bool
    problems: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def backing_for(project: str) -> str:
    return os.path.abspath(project).rstrip("\\/") + BACKING_SUFFIX


def is_elevated() -> bool:
    """Return True if the current process is running elevated (root or elevated token)."""
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def rerun_elevated(args: List[str]) -> Optional[int]:
    """Re-run demo_cli with the given arguments elevated via ShellExecuteW 'runas'.

    Returns the child process exit code, or None if elevation failed or was refused.
    """
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                    ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                    ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Explicitly declare ctypes signatures to prevent 64-bit handle truncation.
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE,
                                            ctypes.POINTER(wintypes.DWORD)]

    # Launch sys.executable directly without cmd.exe or PATH search to prevent
    # binary hijacking from agent-writable directories and command injection.
    exe, argv = _elevation_target(args)
    if not exe:
        return None

    # ShellExecute cannot redirect output directly; create an exclusive temporary
    # log file that the elevated child writes to.
    global _LAST_ELEVATED_LOG
    fd, log = tempfile.mkstemp(prefix="demo_cli-elevated-", suffix=".log")
    os.close(fd)
    _LAST_ELEVATED_LOG = log
    params = subprocess.list2cmdline(argv + ["--elevated-log", log])

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040                      # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"                        # this is what prompts UAC
    info.lpFile = exe
    info.lpParameters = params
    # Explicitly set working directory so relative paths resolve correctly
    # rather than defaulting to System32 under elevation.
    try:
        info.lpDirectory = os.getcwd()
    except OSError:
        info.lpDirectory = None                  # deleted cwd: let Windows choose
    info.nShow = 0                               # SW_HIDE: no console flash
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return None                              # cancelled at the prompt, or refused

    kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wintypes.DWORD()
    # Return None if GetExitCodeProcess fails rather than assuming 0 (success).
    ok = kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    try:
        kernel32.CloseHandle(info.hProcess)      # SEE_MASK_NOCLOSEPROCESS gave it to us
    except Exception:
        pass
    return int(code.value) if ok else None


# Path to the temporary log file of the most recent elevated run.
_LAST_ELEVATED_LOG: Optional[str] = None


def _elevation_target(args: List[str]):
    """Return (absolute executable path, argv) for elevated execution."""
    exe = os.path.abspath(sys.executable)
    if not os.path.isfile(exe):
        return None, []
    base = os.path.basename(exe).lower()
    if base.startswith("demo_cli"):
        return exe, list(args)          # a console-script shim: already us
    return exe, ["-m", "demo_cli"] + list(args)


def elevated_output() -> str:
    """Return output captured from the last elevated run, or empty string."""
    log = _LAST_ELEVATED_LOG
    if not log:
        return ""
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _resolved(path: str) -> str:
    r"""Resolve symlinks, junctions, 8.3 short names, and relative paths."""
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))
    except OSError:
        return os.path.normcase(os.path.abspath(path))


def plan_protect(project: str, backing: Optional[str] = None,
                 lock: bool = True) -> Plan:
    """Validate prerequisites and generate a protect plan without modifying state."""
    source = os.path.abspath(project).rstrip("\\/")
    dest = os.path.abspath(backing) if backing else backing_for(source)
    p = Plan(source=source, backing=dest, mountpoint=source, will_lock=lock)

    if not os.path.isdir(source):
        p.problems.append(f"{source} is not a directory.")
        return p
    if os.path.dirname(source) == source:
        p.problems.append("Refusing to protect a drive root.")
    if source == os.path.abspath(os.path.expanduser("~")):
        p.problems.append("Refusing to protect your home directory.")
    if os.path.lexists(dest):
        p.problems.append(
            f"{dest} already exists. Refusing to merge two trees - that is how "
            f"work disappears. Move or remove it first.")
    try:
        # Backing directory must not reside within the project directory.
        if os.path.commonpath([_resolved(dest), _resolved(source)]) == _resolved(source):
            p.problems.append(f"{dest} is inside {source}; they must be separate.")
    except ValueError:
        pass                                    # different drives: fine

    # Current working directory holds an open handle on Windows, preventing rename.
    try:
        here = _resolved(os.getcwd())
        if here == _resolved(source) or os.path.commonpath(
                [here, _resolved(source)]) == _resolved(source):
            p.problems.append(
                f"You are standing inside {source}. A process's current "
                f"directory holds it open, so it cannot be moved. "
                f"cd somewhere else and re-run.")
    except (OSError, ValueError):
        pass                                    # cwd gone, or another drive

    if os.name != "nt":
        p.warnings.append(
            "Not Windows: the directory will be relocated but nothing will "
            "mount. On Linux the behavioural layer is `demo_cli run <cmd>`.")
    if lock and not is_elevated():
        p.warnings.append(
            "Not elevated, so the backing directory will NOT be locked. "
            "Anything can then write to it directly and bypass the guard "
            "entirely. Re-run from an Administrator shell for the lock.")
    return p


def protect(plan: Plan) -> List[str]:
    """Execute protect plan by locking the directory first, then relocating it.

    Locking before moving ensures the backing directory is never exposed under
    its final name without protection. If the subsequent move fails, the lock
    is removed to avoid leaving the original directory inaccessible.
    """
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = []
    locked_before_move = False
    # Capture custom ACLs before applying lock, as lock_directory overwrites explicit ACLs.
    record = capture_custom_acls(plan.source) if plan.will_lock and is_elevated() else {}
    if plan.will_lock and is_elevated():
        reset = lock_directory(plan.source)
        if is_locked(plan.source) is True:
            locked_before_move = True
        else:
            # Revert lock if partial application occurred to prevent moving an inconsistent ACL.
            unlock_directory(plan.source)

    try:
        Backing.relocate(plan.source, plan.backing)
    except Exception:
        if locked_before_move:
            unlock_directory(plan.source)
        raise
    done.append(f"moved {plan.source} -> {plan.backing}")

    if plan.will_lock and is_elevated():
        # Verify the lock directly from the filesystem at destination rather
        # than relying solely on command return codes.
        state = is_locked(plan.backing)
        if state is True:
            done.append(f"locked {plan.backing} to Administrators and SYSTEM")
            done += _coverage_notes(reset, plan.source, plan.backing)
            # Save ACL record into the locked backing directory to prevent tampering.
            if record:
                if write_acl_record(plan.backing, record):
                    done.append(f"recorded the permissions of {len(record)} "
                                f"entr{'y' if len(record) == 1 else 'ies'} that "
                                f"had their own, to restore on unprotect")
                else:
                    done.append(f"COULD NOT RECORD the permissions of "
                                f"{len(record)} entries; unprotect will restore "
                                f"inherited defaults instead of what they had")
        elif state is False:
            done.append(f"COULD NOT LOCK {plan.backing} - it is writable by "
                        f"anything, so the guard can be bypassed")
        else:
            done.append(f"COULD NOT VERIFY THE LOCK on {plan.backing} - its "
                        f"ACL could not be read, so whether the guard can be "
                        f"bypassed is unknown")
    return done


def _coverage_notes(reset: "ResetOutcome", walked: str, shown: str,
                    verb: str = "are NOT covered by the lock") -> List[str]:
    """Format per-entry failure and skipped link outcomes into actionable notes."""
    def _show(paths: List[str]) -> str:
        rel = []
        for pth in paths[:5]:
            try:
                rel.append(os.path.relpath(pth, walked))
            except ValueError:
                rel.append(pth)
        return ", ".join(rel) + (" ..." if len(paths) > 5 else "")

    notes = []
    if reset.failed:
        notes.append(f"{len(reset.failed)} entr"
                     f"{'y' if len(reset.failed) == 1 else 'ies'} under {shown} "
                     f"{verb}: {_show(reset.failed)}")
    if reset.links:
        notes.append(f"{len(reset.links)} link"
                     f"{'' if len(reset.links) == 1 else 's'} were left alone "
                     f"because they point outside the project: "
                     f"{_show(reset.links)}")
    return notes


def plan_unprotect(project: str, backing: Optional[str] = None) -> Plan:
    source = os.path.abspath(project).rstrip("\\/")
    dest = os.path.abspath(backing) if backing else backing_for(source)
    p = Plan(source=source, backing=dest, mountpoint=source, will_lock=False)

    if not os.path.isdir(dest):
        p.problems.append(f"{dest} does not exist - nothing to restore.")
        return p
    if os.path.lexists(source):
        # Reparse point check: live mount must be unmounted before restoring.
        p.problems.append(
            f"{source} still exists. If the guard is mounted there, unmount it "
            f"first (Ctrl+C in the window running `demo_cli mount`).")
    if not is_elevated():
        p.warnings.append(
            "Not elevated: if the backing directory was locked, the move will "
            "fail. Re-run from an Administrator shell.")
    return p


def unprotect(plan: Plan) -> List[str]:
    """Restore project by relocating directory home first, then unlocking ACLs.

    Moving before unlocking prevents exposing files unlocked at the backing path.
    """
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = []
    # When unelevated, renaming an Administrators-locked backing directory fails with
    # PermissionError; catch and explain clearly.
    try:
        os.rename(plan.backing, plan.source)
    except OSError as exc:
        raise PermissionError(
            f"could not move {plan.backing} back to {plan.source}: {exc.strerror or exc}. "
            f"The backing directory is locked to Administrators; run this from "
            f"an Administrator shell. Nothing was moved, and your files are "
            f"intact at {plan.backing}.") from None
    done.append(f"moved {plan.backing} -> {plan.source}")

    # Unprotect verifies whether the restored tree is successfully unlocked.
    if is_elevated():
        # Read ACL record before unlocking as /reset alters individual file ACLs.
        record, problem = read_acl_record(plan.source)
        reset = unlock_directory(plan.source)
        ok = reset.ok
        state = is_locked(plan.source)
        freed = (state is False) if state is not None else ok
        if freed:
            done.append(f"unlocked {plan.source}")
        else:
            done.append(f"COULD NOT UNLOCK {plan.source} - the restored "
                        f"project is still Administrators-only. Fix with: "
                        f"icacls <path> /inheritance:e ; icacls <path> /reset /T")
        done += _coverage_notes(reset, plan.source, plan.source,
                                verb="could not be given back")
        if problem:
            done.append(problem)
        elif record:
            # Restore recorded permissions after general inheritance reset.
            restored, failed = restore_custom_acls(plan.source, record)
            if restored:
                done.append(f"restored the permissions of {restored} "
                            f"entr{'y' if restored == 1 else 'ies'}")
            if failed:
                done.append(f"COULD NOT RESTORE the permissions of "
                            f"{len(failed)}: {', '.join(failed[:5])}"
                            f"{' ...' if len(failed) > 5 else ''}")
        if record is not None:
            try:
                os.unlink(os.path.join(plan.source, ACL_RECORD_NAME))
            except OSError:
                pass                    # never there, or already gone
    else:
        done.append("not elevated: the ACL was left as it is. If the backing "
                    "was locked, re-run this from an Administrator shell.")
    return done


# Directory locking implementation using system icacls utility.


def lock_directory(path: str) -> ResetOutcome:
    """Grant the directory to SYSTEM and Administrators only.

    Applies explicit rights to the root directory first, then resets children
    so they inherit the root ACL.
    """
    if os.name != "nt" or not _icacls_present():
        return ResetOutcome(False)
    args = [_ICACLS, path, "/inheritance:r"]
    for sid, rights in _LOCK_ACL:
        args += ["/grant:r", f"*{sid}:{rights}"]
    if not _run(args):
        return ResetOutcome(False, failed=[path])
    return _reset_children(path)


def unlock_directory(path: str) -> ResetOutcome:
    """Give the directory back to its owner and restore inheritance.

    Re-enables inheritance first, resets root ACL, and propagates inherited
    permissions down to children.
    """
    if os.name != "nt" or not _icacls_present():
        return ResetOutcome(False)
    if not _run([_ICACLS, path, "/inheritance:e"]):
        return ResetOutcome(False, failed=[path])
    if not _run([_ICACLS, path, "/reset"]):
        return ResetOutcome(False, failed=[path])
    return _reset_children(path)


@dataclass
class ResetOutcome:
    """Record of entry-by-entry ACL reset results, tracking failures and links."""
    ok: bool
    failed: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def _is_reparse_point(path: str) -> bool:
    """Return True if path is a reparse point (junction, symlink, etc.) or inaccessible."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return os.path.islink(path)         # POSIX, and the tests


def _reset_children(path: str) -> ResetOutcome:
    r"""Reset child ACLs to inherit from parent, avoiding following reparse points.

    If no reparse points exist in the tree, uses a single recursive icacls /T call.
    If reparse points are present, traverses per-entry to prevent modifying ACLs
    outside the project tree.
    """
    try:
        if not os.listdir(path):
            return ResetOutcome(True)
    except OSError:
        return ResetOutcome(False, failed=[path])

    links = _reparse_points_under(path)
    if not links:
        if _run([_ICACLS, os.path.join(path, "*"), "/reset", "/T", "/Q"]):
            return ResetOutcome(True)
        # If recursive /reset fails, fall back to entry-by-entry reset to identify failures.
    return _reset_one_by_one(path)


def _reset_one_by_one(path: str) -> ResetOutcome:
    """Traverse tree entry-by-entry resetting ACLs without crossing reparse points."""
    failed: List[str] = []
    skipped: List[str] = []
    stack = [path]
    while stack:
        here = stack.pop()
        try:
            names = os.listdir(here)
        except OSError:
            failed.append(here)
            continue
        safe: List[str] = []
        for name in sorted(names):
            child = os.path.join(here, name)
            (skipped if _is_reparse_point(child) else safe).append(child)
        if not safe:
            continue
        if any(_is_reparse_point(os.path.join(here, n)) for n in names):
            # Reset entries individually if the directory contains reparse points.
            for child in safe:
                if not _run([_ICACLS, child, "/reset", "/Q"]):
                    failed.append(child)
        elif not _run([_ICACLS, os.path.join(here, "*"), "/reset", "/Q"]):
            # If wildcard reset failed, retry individually to capture exact failure paths.
            for child in safe:
                if not _run([_ICACLS, child, "/reset", "/Q"]):
                    failed.append(child)
        for child in safe:
            if os.path.isdir(child):
                stack.append(child)
    return ResetOutcome(not failed, failed=failed, links=skipped)


def _reparse_points_under(path: str) -> List[str]:
    """Return all junctions or symlinks in the tree without traversing targets."""
    found: List[str] = []
    stack = [path]
    while stack:
        here = stack.pop()
        try:
            names = os.listdir(here)
        except OSError:
            # Unreadable subtree: treat as reparse point to prevent unchecked recursion.
            found.append(here)
            continue
        for name in names:
            child = os.path.join(here, name)
            if _is_reparse_point(child):
                found.append(child)
            elif os.path.isdir(child):
                stack.append(child)
    return found


def _run(args: List[str]) -> bool:
    """Execute icacls and verify return code and error output."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except Exception:
        return False
    if r.returncode != 0:
        return False
    m = re.search(r"Failed processing (\d+)", (r.stdout or "") + (r.stderr or ""))
    return not (m and int(m.group(1)) > 0)


# Access mask and ACE flag bits from winnt.h.
_FULL_CONTROL = 0x001F01FF          # FILE_ALL_ACCESS - what icacls calls (F)
_GENERIC_ALL  = 0x10000000
_READ_CONTROL = 0x00020000          # (RC) - read the ACL, and nothing else
_SYNCHRONIZE  = 0x00100000          # harmless, and often set alongside
_OI           = 0x01                # OBJECT_INHERIT_ACE    - files inherit
_CI           = 0x02                # CONTAINER_INHERIT_ACE - subdirs inherit
_INHERIT_ONLY = 0x08                # does NOT apply to this object
_INHERITED    = 0x10                # came from the parent
EVERYONE_SID  = "S-1-1-0"


@dataclass(frozen=True)
class Ace:
    """Access control entry representation using canonical SID, mask, and flags."""
    sid: str
    allow: bool                     # False == a deny entry
    mask: int
    flags: int
    inherited: bool = False


def judge_lock(aces: Optional[List[Ace]]) -> Optional[bool]:
    """Evaluate whether a DACL represents a working lock.

    Returns True if properly locked, False if unlocked or misconfigured,
    or None if unknown (e.g. DACL could not be read).

    Validation rules:
      1. No allowed access granted to principals outside SYSTEM, Administrators, and OWNER RIGHTS.
      2. Administrators and SYSTEM must hold inheritable full control.
      3. OWNER RIGHTS must grant READ_CONTROL and nothing more.
    """
    if aces is None:
        return None

    lock_sids = {sid for sid, _ in _LOCK_ACL}
    # Inherit-only entries apply to descendants, not to the directory itself.
    live = [a for a in aces if not (a.flags & _INHERIT_ONLY)]

    for a in live:
        if a.allow and a.mask and a.sid not in lock_sids:
            return False                                    # rule 1: unauthorized principal allowed
        if not a.allow and a.mask and a.sid in (SYSTEM_SID, ADMINS_SID):
            return False                                    # rule 1: guard principal denied

    def _granted(sid: str) -> int:
        """Return combined access mask granted to the SID by inheritable entries."""
        m = 0
        for a in live:
            if a.allow and a.sid == sid and (a.flags & _OI) and (a.flags & _CI):
                m |= a.mask
        return m

    for sid in (SYSTEM_SID, ADMINS_SID):                    # rule 2: full control
        m = _granted(sid)
        if not (m & _GENERIC_ALL or m & _FULL_CONTROL == _FULL_CONTROL):
            return False

    owner = _granted(OWNER_RIGHTS_SID)                      # rule 3: owner rights
    if not owner & _READ_CONTROL:
        return False
    if owner & ~(_READ_CONTROL | _SYNCHRONIZE):
        return False

    return True


def _read_dacl(path: str) -> Optional[List[Ace]]:
    """Read path DACL via Win32 GetNamedSecurityInfoW, returning List[Ace] or None."""
    if os.name != "nt" or ctypes is None:
        return None

    class _Acl(ctypes.Structure):
        _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                    ("AclSize", ctypes.c_ushort), ("AceCount", ctypes.c_ushort),
                    ("Sbz2", ctypes.c_ushort)]

    class _AceHeader(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", ctypes.c_ushort)]

    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.GetNamedSecurityInfoW.restype = ctypes.c_ulong

        pdacl = ctypes.c_void_p()
        psd = ctypes.c_void_p()
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION = 1, 0x00000004
        err = advapi.GetNamedSecurityInfoW(
            ctypes.c_wchar_p(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            None, None, ctypes.byref(pdacl), None, ctypes.byref(psd))
        if err != 0:
            return None
        try:
            if not pdacl:
                # NULL DACL grants full access to Everyone.
                return [Ace(EVERYONE_SID, True, _FULL_CONTROL, _OI | _CI)]
            count = ctypes.cast(pdacl, ctypes.POINTER(_Acl)).contents.AceCount
            out: List[Ace] = []
            for i in range(count):
                pace = ctypes.c_void_p()
                if not advapi.GetAce(pdacl, i, ctypes.byref(pace)):
                    return None
                hdr = ctypes.cast(pace, ctypes.POINTER(_AceHeader)).contents
                if hdr.AceType not in (0, 1):       # ACCESS_ALLOWED_ACE_TYPE or ACCESS_DENIED_ACE_TYPE only
                    continue
                # ACCESS_ALLOWED_ACE: header(4) mask(4) then the SID inline.
                mask = ctypes.c_ulong.from_address(pace.value + 4).value
                pstr = ctypes.c_void_p()
                if not advapi.ConvertSidToStringSidW(
                        ctypes.c_void_p(pace.value + 8), ctypes.byref(pstr)):
                    return None
                try:
                    sid = ctypes.wstring_at(pstr.value)
                finally:
                    kernel.LocalFree(pstr)
                out.append(Ace(sid, hdr.AceType == 0, mask, hdr.AceFlags,
                               bool(hdr.AceFlags & _INHERITED)))
            return out
        finally:
            if psd:
                kernel.LocalFree(psd)
    except Exception:
        return None


# Record and restore pre-existing project permissions for entries with explicit ACLs.
ACL_RECORD_NAME = ".demo_cli-acl.json"

_SDDL_REVISION_1 = 1
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_FILE_OBJECT = 1


def has_custom_acl(aces: Optional[List[Ace]]) -> bool:
    """Return True if aces contain non-inherited entries or an empty DACL."""
    if aces is None:
        return False
    if not aces:
        return True
    return any(not a.inherited for a in aces)


def _sddl_of(path: str) -> Optional[str]:
    """Return this entry's DACL as an SDDL string, or None if unreadable."""
    if os.name != "nt" or ctypes is None:
        return None
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.GetNamedSecurityInfoW.restype = ctypes.c_ulong

        psd = ctypes.c_void_p()
        err = advapi.GetNamedSecurityInfoW(
            ctypes.c_wchar_p(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
            None, None, None, None, ctypes.byref(psd))
        if err != 0 or not psd:
            return None
        try:
            out = ctypes.c_void_p()
            if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    psd, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION,
                    ctypes.byref(out), None):
                return None
            try:
                return ctypes.wstring_at(out.value)
            finally:
                kernel.LocalFree(out)
        finally:
            kernel.LocalFree(psd)
    except Exception:
        return None


def dacl_shape(sddl: str) -> Tuple[bool, str]:
    """Return (is_protected, aces_string) determining access, ignoring auto-inherit flags."""
    body = sddl.split("D:", 1)[-1] if "D:" in sddl else sddl
    cut = body.find("(")
    flags, aces = (body[:cut], body[cut:]) if cut >= 0 else (body, "")
    return ("P" in flags.replace("AI", "").replace("AR", ""), aces)


def _sddl_is_protected(sddl: str) -> bool:
    """Return True if SDDL indicates DACL is protected (inheritance disabled)."""
    return dacl_shape(sddl)[0]


def _apply_sddl(path: str, sddl: str) -> bool:
    """Put a recorded DACL back. True only if Windows says it took."""
    if os.name != "nt" or ctypes is None:
        return False
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.SetNamedSecurityInfoW.restype = ctypes.c_ulong

        psd = ctypes.c_void_p()
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                ctypes.c_wchar_p(sddl), _SDDL_REVISION_1,
                ctypes.byref(psd), None):
            return False
        try:
            present = ctypes.c_int()
            pdacl = ctypes.c_void_p()
            defaulted = ctypes.c_int()
            if not advapi.GetSecurityDescriptorDacl(
                    psd, ctypes.byref(present), ctypes.byref(pdacl),
                    ctypes.byref(defaulted)):
                return False
            if not present.value:
                return False
            info = _DACL_SECURITY_INFORMATION | (
                _PROTECTED_DACL_SECURITY_INFORMATION if _sddl_is_protected(sddl)
                else _UNPROTECTED_DACL_SECURITY_INFORMATION)
            err = advapi.SetNamedSecurityInfoW(
                ctypes.c_wchar_p(path), _SE_FILE_OBJECT, ctypes.c_ulong(info),
                None, None, pdacl, None)
            return err == 0
        finally:
            kernel.LocalFree(psd)
    except Exception:
        return False


def safe_member(root: str, rel: str) -> Optional[str]:
    r"""Resolve relative path within root, returning None if it escapes root or is absolute."""
    if not rel or os.path.isabs(rel) or ntpath.isabs(rel):
        return None
    full = os.path.join(root, rel)
    base = _resolved(root)
    here = _resolved(full)
    if here == base:
        return None                     # the root itself is not a member
    try:
        if os.path.commonpath([here, base]) != base:
            return None
    except ValueError:
        return None                     # different drives
    return full


def capture_custom_acls(root: str) -> Dict[str, str]:
    """Return mapping of relative paths to SDDL strings for entries with explicit ACLs."""
    out: Dict[str, str] = {}
    # _read_dacl returns None on non-Windows platforms, so the walk finds nothing there.
    stack = [root]
    while stack:
        here = stack.pop()
        try:
            names = os.listdir(here)
        except OSError:
            continue
        for name in names:
            child = os.path.join(here, name)
            if _is_reparse_point(child):
                continue
            if has_custom_acl(_read_dacl(child)):
                sddl = _sddl_of(child)
                if sddl:
                    out[os.path.relpath(child, root)] = sddl
            if os.path.isdir(child):
                stack.append(child)
    return out


def write_acl_record(root: str, record: Dict[str, str]) -> bool:
    """Persist ACL record to locked root directory using exclusive creation."""
    path = os.path.join(root, ACL_RECORD_NAME)
    try:
        os.unlink(path)                 # removes a symlink, not its target
    except OSError:
        pass
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "acls": record}, f, indent=1)
        return True
    except OSError:
        return False


def read_acl_record(root: str) -> Tuple[Optional[Dict[str, str]], str]:
    """Read ACL record from root, returning (record_dict, error_message)."""
    path = os.path.join(root, ACL_RECORD_NAME)
    if not os.path.exists(path):
        return None, ""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        acls = data["acls"]
        if not isinstance(acls, dict):
            raise ValueError("acls is not an object")
        return {str(k): str(v) for k, v in acls.items()}, ""
    except Exception as exc:
        return None, (f"{path} could not be read ({exc}); the permissions this "
                      f"project had before it was protected were NOT restored")


def restore_custom_acls(root: str, record: Dict[str, str]) -> Tuple[int, List[str]]:
    """Reapply recorded DACLs, returning (restored_count, list_of_failed_entries)."""
    done, failed = 0, []
    for rel, sddl in sorted(record.items()):
        full = safe_member(root, rel)
        if full is None:
            failed.append(f"{rel} (refused: outside the project)")
            continue
        if not os.path.lexists(full):
            continue
        if _is_reparse_point(full):
            failed.append(f"{rel} (refused: became a link)")
            continue
        if not _apply_sddl(full, sddl):
            failed.append(rel)
            continue
        # Verify applied SDDL matches recorded shape.
        back = _sddl_of(full)
        if back is None:
            failed.append(f"{rel} (applied, but could not be read back to check)")
        elif dacl_shape(back) != dacl_shape(sddl):
            failed.append(f"{rel} (applied, but the result does not match)")
        else:
            done += 1
    return done, failed


def is_locked(path: str) -> Optional[bool]:
    """Return True if path is locked, False if unlocked/misconfigured, or None if unreadable."""
    return judge_lock(_read_dacl(path))
