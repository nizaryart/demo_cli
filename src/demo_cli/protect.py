"""Turn an ordinary project into a guarded one, and back again.

--------------------------------------------------------------------------
WHAT `protect` DOES AND WHY IT HAS TO MOVE YOUR FILES
--------------------------------------------------------------------------
A WinFsp directory mount point is an NTFS reparse point, and Windows only sets
one on an empty or non-existent directory. So the project's own path has to be
vacated before it can become the mount:

    before      C:\\project                 ordinary directory
    after       C:\\project.real            the bytes (locked down)
                C:\\project                 the mount, created by WinFsp

The path everybody types stays the same. That is the entire reason to relocate
rather than mount at a drive letter: `X:\\` would change every path, IDE
config and habit permanently, and Claude Code already refuses a bare drive
root as its working directory.

os.rename, never a copy: atomic within a volume, needs no free space, and
cannot half-finish leaving two divergent copies of somebody's work.

--------------------------------------------------------------------------
THE LOCK, AND WHAT IT CAN HONESTLY PROMISE
--------------------------------------------------------------------------
Relocating alone protects nothing. The backing directory still exists and is
still writable, so anything writing straight to it bypasses the guard
entirely. That is not theoretical - on 2026-08-25 an ordinary

    Remove-Item C:\\...\\fslab\\real -Recurse -Force

deleted the backing directory out from under a live mount, and the guard's log
stayed empty. No obfuscation, no cleverness, complete bypass.

An ACL is the fix, but it cannot separate the guard from the agent BY IDENTITY:
they run as the same Windows user. Denying that user denies us too. The
boundary has to come from a privilege difference instead:

    grant the backing directory to Administrators and SYSTEM only,
    run the mount ELEVATED, and let the agent run normally.

Then the agent - an ordinary non-elevated process - cannot reach the backing
directory at all, and the mount is the only route to the bytes.

STATED PLAINLY, because a security tool that overclaims is worse than none:
if the agent also runs elevated, this boundary does not exist. The complete
answer is a Windows service running as SYSTEM, which is a separate, later
piece of work. What is here is real and is not everything.

--------------------------------------------------------------------------
UNPROTECT IS NOT OPTIONAL
--------------------------------------------------------------------------
Nobody should run a command that relocates their project without a way back,
and a way back that only works when everything is healthy is not one. So
`unprotect` restores the ACL and moves the directory home, works with the
guard uninstalled, and says exactly what it will do first.
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
    # AT MODULE SCOPE ON PURPOSE. Imported lazily inside _read_dacl, this
    # picks its platform branch from os.name AT CALL TIME - and a test that
    # sets os.name to "nt" to exercise a Windows path then made ctypes import
    # its Windows half on Linux, which fails on `from _ctypes import
    # FormatError`. Importing here binds it once, from the real platform.
    import ctypes
except Exception:                       # pragma: no cover - ctypes is stdlib
    ctypes = None
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .fspassthrough import Backing

# What a protected project's backing directory is called. A suffix rather than
# a hidden sibling elsewhere: whoever finds it should be able to tell instantly
# what it belongs to, including a year from now with the tool uninstalled.
BACKING_SUFFIX = ".real"

# ABSOLUTE, NEVER A BARE NAME. CreateProcess resolves a bare image name with
# the CURRENT DIRECTORY FIRST on Windows, and the elevated child starts in the
# directory the user invoked from - which plan_protect's own refusal steers
# them to, and which the unelevated agent can write. A planted icacls.exe
# would then run as Administrator. shutil.which does not help: it finds the
# planted copy too (2026-09-09).
_ICACLS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "icacls.exe")


def _icacls_present() -> bool:
    """Is the real icacls there? A named seam, not a bare isfile call.

    Every gate used to be `shutil.which("icacls")`, which is exactly the
    lookup this module must not do. One function so all four gates agree, and
    so a test can say what it is simulating instead of patching os.path.
    """
    return os.path.isfile(_ICACLS)

# Only these may touch the backing directory once it is locked. The guard runs
# elevated and therefore qualifies; an ordinary agent process does not.
# SIDs rather than names, because "Administrators" is localised - on a French
# or Arabic Windows the name differs and icacls would fail with a message
# nobody would connect to a locale.
SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"

# OWNER RIGHTS. THE THIRD ACE, AND THE ONLY REASON THE LOCK WORKS AT ALL.
#
# For three weeks this module granted the backing directory to SYSTEM and
# Administrators and called it locked. On 2026-09-10, on the development
# machine, with the lock applied and no elevation:
#
#     icacls ptest.real /grant "pc:(OI)(CI)F"  ->  Successfully processed 1
#     Get-ChildItem ptest.real                 ->  f.txt
#     cmd /c move ptest.real gone.real         ->  1 dir(s) moved
#
# No UAC prompt. The reason is that os.rename PRESERVES OWNERSHIP: the user
# still owned the directory after protect ran, and an owner holds READ_CONTROL
# and WRITE_DAC IMPLICITLY - not through any ACE, so removing every ACE
# removes nothing. The owner simply grants themselves back in.
#
# S-1-3-4 is the OWNER RIGHTS SID, and an explicit ACE for it REPLACES that
# implicit grant with whatever the ACE says. (RC) says "read the ACL, nothing
# else", which is exactly the residue needed: is_locked keeps working from an
# unelevated shell, and the owner can no longer re-grant or move the
# directory. Verified on hardware, all four outcomes:
#
#     read files DENIED / grant DENIED / read ACL OK / move DENIED
#
# Rejected: /setowner to Administrators (ownership churn, and unprotect then
# cannot give it back to a user it no longer knows) and /deny (which bricked
# the directory outright - only `takeown /F <d> /R /A` recovered it).
#
# WHOSE RIGHTS IT CAPS DEPENDS ON WHO OWNS THE DIRECTORY, and that is not
# something this module chooses - os.rename preserves the owner, so the lock
# inherits whatever the project already had. Both cases are safe and they are
# not the same (measured end to end, 2026-09-10):
#
#   owner is the user      the (Rc) cap applies to them: they cannot grant
#   (a project they made)  themselves back and cannot move the directory, but
#                          CAN still read the ACL - so is_locked answers True
#                          from an ordinary shell, with no elevation.
#
#   owner is Administrators  the user matches no entry at all and is denied
#   (a directory created     everything, the ACL included. Stronger, and
#    from an elevated shell) is_locked can then only answer None.
#
# So a None from is_locked on a directory that plainly exists is not evidence
# that it is unlocked - it may be evidence of the opposite. Nothing here tries
# to read that tea leaf; None stays "I do not know". It is recorded because
# the difference cost two hours of contradictory test results: a lab created
# in the elevated window measured completely differently from one created the
# way a user actually creates a project.
OWNER_RIGHTS_SID = "S-1-3-4"

# (sid, icacls rights) - the whole definition of a locked directory, in the
# order icacls is asked to apply it.
_LOCK_ACL = [(SYSTEM_SID, "(OI)(CI)F"),
             (ADMINS_SID, "(OI)(CI)F"),
             (OWNER_RIGHTS_SID, "(OI)(CI)(RC)")]

_ACL_PRINCIPALS = [f"*{sid}" for sid, _ in _LOCK_ACL]


@dataclass
class Plan:
    """What protect/unprotect intends to do, before it does any of it.

    A dataclass rather than a printed paragraph so the CLI can show it, the
    tests can assert on it, and nothing has to be inferred from output text.
    """
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
    """True when this process can write an Administrators-only directory.

    On POSIX, root. On Windows, IsUserAnAdmin - which reports whether the
    process is running with an elevated token, not merely whether the account
    belongs to the Administrators group. The difference is the whole point:
    an unelevated shell owned by an admin user must still be excluded.
    """
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def rerun_elevated(args: List[str]) -> Optional[int]:
    """Re-run demo_cli with these arguments, elevated. Returns its exit code.

    ShellExecuteW with the "runas" verb is the only way to raise a UAC prompt;
    a process cannot elevate itself in place. So this launches a SECOND
    demo_cli, waits for it, and reports what it did.

    WHY BOTHER, instead of printing "open an admin shell and re-run": the step
    that needs elevation happens in the middle of setup, after the user has
    already read the plan and typed yes. Sending them away to another shell at
    that point means they come back and start over - and every extra manual
    step is a step someone skips, leaving a half-configured machine.

    Returns None when elevation is unavailable or refused, so the caller can
    say so rather than pretending the work was done.
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
    # Declare every signature. ctypes defaults an undeclared return to a
    # 32-bit int, which truncates pointer-sized handles on x64 - the bug that
    # cost three debugging rounds during the privilege investigation.
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE,
                                            ctypes.POINTER(wintypes.DWORD)]

    # NO cmd.exe, AND NO PATH LOOKUP. Both were privilege escalations.
    #
    # It used to be `shutil.which("demo_cli")` launched through
    # `cmd /c "<that> ... > log 2>&1"` under the runas verb. Three defects in
    # those two lines, found by review 2026-09-09:
    #
    #   * shutil.which SEARCHES THE CURRENT DIRECTORY FIRST on Windows
    #     (CPython: _win_path_needs_curdir -> path.insert(0, os.curdir)), and
    #     plan_protect REFUSES to run from inside the project - so the user is
    #     steered to the parent directory, which the unelevated agent can
    #     write. Drop a demo_cli.exe there and it wins, then gets handed to
    #     UAC. The tool's own refusal created the exposure.
    #
    #   * lpFile = "cmd.exe" is a bare image name, resolved against
    #     lpDirectory - the same agent-writable directory - before PATH.
    #
    #   * list2cmdline IS NOT cmd QUOTING. It quotes for space and tab and
    #     nothing else, so `&`, `|`, `%` and `<>` reached an elevated shell
    #     live. _undo_argv forwards an agent-supplied id verbatim, so
    #     `demo_cli undo "x&whatever"` turned a UAC prompt the user is trained
    #     to approve into arbitrary elevated execution.
    #
    # sys.executable is absolute and comes from the running interpreter, not
    # from a search path, so there is nothing to plant. Launching the child
    # DIRECTLY means list2cmdline is used for what it is actually correct for
    # - the CRT argv parsing the child itself will do - with no shell in
    # between to reinterpret it.
    exe, argv = _elevation_target(args)
    if not exe:
        return None

    # The child redirects its own output, because ShellExecute cannot. The
    # file is created HERE with O_EXCL, so the elevated child opens something
    # that already exists and is ours - a fixed, predictable, agent-writable
    # path was a symlink-redirection target for arbitrary elevated file
    # creation, and elevated_output() prints it back as if it were our own.
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
    # THE CHILD DOES NOT INHERIT OUR WORKING DIRECTORY. With lpDirectory left
    # NULL an elevated process starts in C:\Windows\system32, so any argument
    # that was relative - or any command that resolves its project from the
    # current directory - means something different on the other side of the
    # UAC prompt.
    #
    # `demo_cli undo <id>` did exactly that on 2026-09-02: the child looked for
    # the recovery point in C:\Windows\system32\.demo_cli\recovery, found
    # nothing, and exited 1, while the parent reported that the recovery
    # needed Administrator. It had Administrator.
    #
    # Callers should still pass absolute paths - undo now always sends --root -
    # but this closes the class rather than one instance of it.
    try:
        info.lpDirectory = os.getcwd()
    except OSError:
        info.lpDirectory = None                  # deleted cwd: let Windows choose
    info.nShow = 0                               # SW_HIDE: no console flash
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return None                              # cancelled at the prompt, or refused

    kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wintypes.DWORD()
    # CHECK THE RETURN VALUE. GetExitCodeProcess failing leaves the DWORD
    # zero-initialised, and 0 is success - so a call that told us nothing
    # reported that the elevated step worked. None means "we do not know",
    # which every caller already handles.
    ok = kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    try:
        kernel32.CloseHandle(info.hProcess)      # SEE_MASK_NOCLOSEPROCESS gave it to us
    except Exception:
        pass
    return int(code.value) if ok else None


# The log of the most recent elevated run. A per-run temp file rather than a
# fixed name, so nothing can pre-create or symlink the path we are about to
# write as Administrator.
_LAST_ELEVATED_LOG: Optional[str] = None


def _elevation_target(args: List[str]):
    """(absolute image to launch, argv for it) - never resolved through PATH.

    sys.executable is where this interpreter actually lives. Running the child
    as `<python> -m demo_cli ...` means the elevated image is one we are
    already executing, not one a search path chose for us.
    """
    exe = os.path.abspath(sys.executable)
    if not os.path.isfile(exe):
        return None, []
    base = os.path.basename(exe).lower()
    if base.startswith("demo_cli"):
        return exe, list(args)          # a console-script shim: already us
    return exe, ["-m", "demo_cli"] + list(args)


def elevated_output() -> str:
    """What the last elevated run printed. Empty when there was none.

    Without this a failure in the elevated half is completely opaque to the
    half that asked for it.
    """
    log = _LAST_ELEVATED_LOG
    if not log:
        return ""
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _resolved(path: str) -> str:
    r"""A path with links, 8.3 names and relative parts resolved away.

    THE CONTAINMENT GUARDS COMPARED TEXT. os.path.commonpath normalises case
    and separators and nothing else, so

        commonpath(['C:\lab\MYPROJ~1\backing', 'C:\lab\myproject'])  ->  C:\lab

    and `--backing C:\lab\MYPROJ~1\backing` sailed past "dest is inside
    source; they must be separate" - leaving the mount storing its own
    contents through itself. The same trick, or a junction, defeats the "you
    are standing inside" check, which brings back the WinError 32 of
    2026-08-28 from an ELEVATED process, after the UAC prompt (2026-09-09).

    realpath resolves symlinks, junctions and 8.3 components on Windows; it is
    the one call that makes two spellings of one directory compare equal.
    Never raises - a path that cannot be resolved is compared as it was given,
    which is no worse than before.
    """
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))
    except OSError:
        return os.path.normcase(os.path.abspath(path))


def plan_protect(project: str, backing: Optional[str] = None,
                 lock: bool = True) -> Plan:
    """Decide whether this project can be protected, without touching anything.

    Every refusal below is a case where proceeding would either fail halfway or
    quietly do something the user did not ask for. A half-finished relocation
    is somebody's project in a directory they cannot find.
    """
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
        # The backing directory cannot live inside the project, or the mount
        # would be storing its own contents through itself.
        if os.path.commonpath([_resolved(dest), _resolved(source)]) == _resolved(source):
            p.problems.append(f"{dest} is inside {source}; they must be separate.")
    except ValueError:
        pass                                    # different drives: fine

    # A PROCESS'S CURRENT DIRECTORY HOLDS AN OPEN HANDLE ON IT, and Windows
    # refuses to rename a directory anything has open. Running `demo_cli
    # setup` from inside the project you are protecting is the natural thing
    # to do, and it failed with WinError 32 AFTER the UAC prompt - so the
    # first the user knew of it was a traceback from an elevated process.
    # Observed 2026-08-28. Checked here so it costs a message, not a password.
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
    """Carry out a plan. Returns what was done, in order.

    LOCK FIRST, THEN MOVE. The order used to be the other way round, on the
    reasoning that relocating is atomic and locking is cosmetic if it fails.
    The gap that leaves is small and completely reachable: between the rename
    and the icacls call the directory sits UNLOCKED, UNDER ITS FINAL NAME, at
    a path anything can predict from the project's own - `<project>.real`.
    An agent does not have to win a race it cannot see; it can watch for that
    name to appear.

    A same-volume rename preserves the DACL (verified on hardware,
    2026-09-10), so locking the directory before it moves means it is never
    once reachable under the name that gives it away. relocate uses os.rename
    and nothing else, so there is no copy path that could drop the ACL.

    If the move then fails, the lock is taken back off: leaving somebody's
    project locked to Administrators AT ITS ORIGINAL PATH would be a far worse
    outcome than the failure itself.
    """
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = []
    locked_before_move = False
    # BEFORE THE LOCK, or there is nothing left to record: lock_directory
    # gives every entry in the tree an explicit ACL of our own making, and
    # from that moment the project's own permissions are gone (finding #12).
    record = capture_custom_acls(plan.source) if plan.will_lock and is_elevated() else {}
    if plan.will_lock and is_elevated():
        lock_directory(plan.source)
        if is_locked(plan.source) is True:
            locked_before_move = True
        else:
            # A HALF-APPLIED ACL IS NOT CARRIED INTO THE BACKING. icacls can
            # strip inheritance and then fail on the grant, and moving that
            # tree would hand the user a project with an ACL nobody asked for
            # and no record of what it used to be. /reset puts it back.
            unlock_directory(plan.source)

    try:
        Backing.relocate(plan.source, plan.backing)
    except Exception:
        if locked_before_move:
            unlock_directory(plan.source)
        raise
    done.append(f"moved {plan.source} -> {plan.backing}")

    if plan.will_lock and is_elevated():
        # ASK THE FILESYSTEM, NOT THE COMMAND, and ask it HERE - after the
        # move. lock_directory returning True means icacls exited 0 and
        # admitted no failures, and icacls has exited 0 on a grant it did not
        # apply before (see lock_directory's own docstring, 2026-08-25). A
        # claim of protection is the one thing in this tool that must never
        # rest on a tool's self-report.
        #
        # Reading it back at the destination also checks the assumption this
        # whole ordering rests on: that the rename carried the DACL with it.
        state = is_locked(plan.backing)
        if state is True:
            done.append(f"locked {plan.backing} to Administrators and SYSTEM")
            # Stored only now, into a directory that is already locked - so
            # the file an elevated unprotect will act on never sits anywhere
            # an ordinary process could rewrite it.
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


def plan_unprotect(project: str, backing: Optional[str] = None) -> Plan:
    source = os.path.abspath(project).rstrip("\\/")
    dest = os.path.abspath(backing) if backing else backing_for(source)
    p = Plan(source=source, backing=dest, mountpoint=source, will_lock=False)

    if not os.path.isdir(dest):
        p.problems.append(f"{dest} does not exist - nothing to restore.")
        return p
    if os.path.lexists(source):
        # A live mount occupies this path as a reparse point. Renaming over it
        # would either fail or, worse, bury the mount.
        p.problems.append(
            f"{source} still exists. If the guard is mounted there, unmount it "
            f"first (Ctrl+C in the window running `demo_cli mount`).")
    if not is_elevated():
        p.warnings.append(
            "Not elevated: if the backing directory was locked, the move will "
            "fail. Re-run from an Administrator shell.")
    return p


def unprotect(plan: Plan) -> List[str]:
    """Undo a protect. MOVE FIRST, THEN UNLOCK - the mirror of protect().

    This used to unlock first, and said so: "a locked directory cannot be
    moved by the account that is about to move it". That is not true of the
    account that does the moving. The lock grants Administrators (OI)(CI)F,
    full control includes DELETE, and unprotect only gets this far when it is
    running elevated - so the mover is precisely the principal the lock lets
    through.

    Unlocking first opened the same window protect() had, in the same place
    and with the same name: the directory sat UNLOCKED at `<project>.real`,
    the one path an agent can derive from the project's own, for as long as
    three icacls calls take on a tree. Renaming first means the only moment it
    is unlocked, it is already home under the name the user chose.
    """
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = []
    # NEVER let this raise. The backing directory is locked to Administrators,
    # so an unelevated rename fails with WinError 5 - and an unhandled
    # traceback out of the command whose whole job is "get me out of this" is
    # the worst possible place for one. Observed 2026-08-28.
    try:
        os.rename(plan.backing, plan.source)
    except OSError as exc:
        raise PermissionError(
            f"could not move {plan.backing} back to {plan.source}: {exc.strerror or exc}. "
            f"The backing directory is locked to Administrators; run this from "
            f"an Administrator shell. Nothing was moved, and your files are "
            f"intact at {plan.backing}.") from None
    done.append(f"moved {plan.backing} -> {plan.source}")

    # A failed unlock is SAID, not skipped. The first version appended the
    # "unlocked" line only on success and carried on otherwise, so a project
    # came home still locked to Administrators with its owner shut out and
    # nothing in the output to explain it. Handing something back in a state
    # the user cannot use, silently, is the failure this project is about.
    #
    # Read it back where that is possible, for the same reason protect()
    # stopped believing lock_directory (finding #14) - but fall back to the
    # exit code where it is not. is_locked answers None whenever the ACL
    # cannot be read, which is every non-Windows machine and every Windows one
    # where the lock is tighter than usual, and "I could not check" must not
    # become "unlocked". An unverifiable claim falls back to the evidence
    # there is, never up to the claim there is not.
    if is_elevated():
        # Read it before the unlock: /reset is about to overwrite the ACL of
        # every entry the record names, including the record's own.
        record, problem = read_acl_record(plan.source)
        ok = unlock_directory(plan.source)
        state = is_locked(plan.source)
        freed = (state is False) if state is not None else ok
        if freed:
            done.append(f"unlocked {plan.source}")
        else:
            done.append(f"COULD NOT UNLOCK {plan.source} - the restored "
                        f"project is still Administrators-only. Fix with: "
                        f"icacls <path> /inheritance:e ; icacls <path> /reset /T")
        if problem:
            done.append(problem)
        elif record:
            # AFTER the unlock. /reset would undo every one of these.
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


# --------------------------------------------------------------------------
# The lock itself
#
# Shells out to icacls rather than calling the Win32 security APIs through
# ctypes. Same arrangement as mitmdump and pg_dump: use the installed,
# supported tool instead of reimplementing it. Building a correct ACL by hand
# through ctypes is a great deal of code whose failure mode is a directory
# nobody can open, including the person who owns it.
# --------------------------------------------------------------------------

def lock_directory(path: str) -> bool:
    """Grant the directory to SYSTEM and Administrators only.

    TWO PASSES, and the reason is a defect found live on 2026-08-25.

    The first version did it in one:

        icacls <dir> /inheritance:r /grant:r <sid>:(OI)(CI)F ... /T /C

    (OI) and (CI) are CONTAINER-inheritance flags: meaningful on a directory,
    meaningless on a file. /T applies the whole operation to every existing
    child, where /inheritance:r succeeds - stripping the inherited access - and
    the (OI)(CI) grant is rejected. /C then swallows the per-file error and
    icacls still exits 0.

    Every pre-existing file was left with an EMPTY DACL: unreadable by anyone,
    including Administrators, including the owner's own elevated shell. Files
    created afterwards were fine, because they inherited from the directory -
    which is why the failure looked so strange, with `dir` working, new files
    readable, and the user's original notes.txt denied to everybody.

    So: grant on the directory alone, then reset the children so they INHERIT
    it. /reset is what restores an inherited ACL, and it is the only thing that
    can repair a file whose DACL is already empty.
    """
    if os.name != "nt" or not _icacls_present():
        return False
    args = [_ICACLS, path, "/inheritance:r"]
    for sid, rights in _LOCK_ACL:
        args += ["/grant:r", f"*{sid}:{rights}"]
    if not _run(args):
        return False
    return _reset_children(path)


def unlock_directory(path: str) -> bool:
    """Give the directory back to its owner and restore inheritance.

    THREE separate icacls calls, because combining them does not work and
    failed silently when it was one. `/inheritance:e /reset` in a single
    invocation exits non-zero - icacls will not take both - so unprotect moved
    the project home STILL LOCKED, with its owner shut out of it and no
    message saying so. Observed 2026-08-25 on the round-trip test.

    Order matters: re-enable inheritance first, so the /reset that follows has
    a parent ACL to inherit; then push the same down to the children.

    The OWNER RIGHTS entry needs no separate removal: it is an EXPLICIT ACE,
    and /reset replaces the whole explicit ACL with the inherited one. Worth
    stating because it is the one entry whose absence is invisible - a
    directory that still caps its owner's rights after unprotect would look
    completely normal until the owner tried to change its permissions.
    """
    if os.name != "nt" or not _icacls_present():
        return False
    if not _run([_ICACLS, path, "/inheritance:e"]):
        return False
    if not _run([_ICACLS, path, "/reset"]):
        return False
    return _reset_children(path)


def _is_reparse_point(path: str) -> bool:
    """Is this entry a junction, a symlink, or anything else that redirects?

    Junctions are the ones that matter here and they are easy to miss:
    os.path.islink has historically answered False for them on Windows, and
    os.path.isdir answers True, so a junction looks exactly like a directory
    to everything except the reparse attribute. Read the attribute.

    A path that cannot be stat'ed answers True - unknown means do not touch.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return True
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return os.path.islink(path)         # POSIX, and the tests


def _reset_children(path: str) -> bool:
    r"""Make every existing child inherit the directory's ACL.

    NEVER LEAVES THE TREE. This used to be one call:

        icacls <dir>\* /reset /T /Q

    /T is icacls's own recursion, and it follows reparse points. One junction
    inside the project - a node_modules linked to a shared cache, a symlink
    into Program Files, anything an agent could create while unelevated - and
    an ELEVATED icacls resets ACLs on files that were never part of the
    project. It runs during unprotect too, which is the moment a user is least
    expecting anything to be damaged (finding #11, 2026-09-09).

    A wildcard cannot exclude the link either: `<dir>\*` matches it, and icacls
    follows it to the target. So the recursion is done here, where an entry can
    be looked at before it is named to anything.

    Two paths, because correctness must not cost every user a slow protect:

      no reparse points anywhere   one icacls /T call, exactly as before, and
                                   provably safe because there is nothing in
                                   the tree for it to follow.

      any reparse point            per directory, and inside a directory that
                                   contains one, per entry - the only way to
                                   name the children without naming the link.

    Residual, stated rather than hidden: the scan and the icacls call are not
    atomic. Closing that needs ACLs set through handles opened with
    FILE_FLAG_OPEN_REPARSE_POINT, which is the hand-built-security-descriptor
    route this module deliberately avoids. During protect the directory is
    already locked before this runs, so the window is reachable only by a
    process that is already Administrator. During unprotect it is not - by
    then the project is being handed back, and the lock is going away anyway.

    Skipped for an empty directory: `icacls <dir>\*` matches nothing there and
    reports a failure that means nothing went wrong.
    """
    try:
        if not os.listdir(path):
            return True
    except OSError:
        return False

    if not _reparse_points_under(path):
        return _run([_ICACLS, os.path.join(path, "*"), "/reset", "/T", "/Q"])

    ok = True
    stack = [path]
    while stack:
        here = stack.pop()
        try:
            names = os.listdir(here)
        except OSError:
            ok = False
            continue
        safe, links = [], []
        for name in names:
            child = os.path.join(here, name)
            (links if _is_reparse_point(child) else safe).append(child)
        if not safe:
            continue
        if links:
            # The wildcard would match the links. Name the rest one by one.
            for child in safe:
                if not _run([_ICACLS, child, "/reset", "/Q"]):
                    ok = False
        elif not _run([_ICACLS, os.path.join(here, "*"), "/reset", "/Q"]):
            ok = False
        for child in safe:
            if os.path.isdir(child):
                stack.append(child)
    return ok


def _reparse_points_under(path: str) -> List[str]:
    """Every junction or symlink in the tree, without following any of them.

    Used to decide whether icacls's own /T can be trusted with this tree. It
    is a full walk, which is far cheaper than one subprocess per directory -
    and it is the walk the careful path would have to do anyway.
    """
    found: List[str] = []
    stack = [path]
    while stack:
        here = stack.pop()
        try:
            names = os.listdir(here)
        except OSError:
            # Unreadable subtree: assume the worst rather than trust /T with it
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
    """Run icacls and believe it only when it says nothing failed.

    NO /C. That flag means "continue past errors", and icacls then exits 0
    having failed on every single file - which is how the one-pass lock above
    reported success while leaving a directory of unreadable files. The exit
    code is only meaningful once icacls is allowed to stop.

    The "Failed processing N files" line is also checked, because /T walks a
    tree and a single unreachable entry should not be reported as a clean
    lock. That string is not localised by icacls even on a French Windows -
    verified on one - but a mismatch only ever makes this return the exit code
    alone, never a false success.
    """
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except Exception:
        return False
    if r.returncode != 0:
        return False
    m = re.search(r"Failed processing (\d+)", (r.stdout or "") + (r.stderr or ""))
    return not (m and int(m.group(1)) > 0)


# Access mask and ACE flag bits, from winnt.h. Named here so the rules below
# read as rules and not as hexadecimal.
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
    """One access-control entry, as the kernel stores it - not as icacls
    prints it. `sid` is the canonical SID string, which is the same on every
    Windows in every language."""
    sid: str
    allow: bool                     # False == a deny entry
    mask: int
    flags: int
    inherited: bool = False


def judge_lock(aces: Optional[List[Ace]]) -> Optional[bool]:
    """Is this DACL a working lock? True / False / None, and nothing else.

    PURE, so the whole rule set is testable off Windows - the probe that reads
    a real DACL is twelve lines below and does no judging. Same split as
    deps.py.

    WHY THIS REPLACED COUNTING. The previous version counted entries and
    checked their rights string, on the reasoning that "(OI)(CI)(F)" is not
    localised while "BUILTIN\\Administrateurs" is. The reasoning was right and
    the implementation was not:

      * the correct lock now has THREE entries, so `len(aces) == 2` calls it
        broken (2026-09-10);
      * an entry inherited from the parent pushes the count up, so an OPEN
        directory could reach the expected number;
      * `"(OI)(CI)(F)" in line` is a substring test, and a DENY entry prints
        as `(DENY)(OI)(CI)(F)` - which contains it. A directory denied to
        everybody read as locked.

    All three come from reading a rendering of the ACL instead of the ACL.
    SIDs are not localised either, and they are what the check now names.

    The rules, in order:

      1. Nobody outside the three lock principals may be ALLOWED anything.
         Conservative: a deny entry elsewhere might override such an allow,
         and this still answers False. Understating protection is the safe
         direction for this particular claim.
      2. Administrators and SYSTEM must hold full control, INHERITABLE by both
         files and subdirectories - the children were reset to inherit, so an
         entry without (OI)(CI) leaves them with an empty DACL.
      3. OWNER RIGHTS must be present, and must grant READ_CONTROL AND NOTHING
         MORE. Absent, the owner keeps the implicit WRITE_DAC that made the
         first three weeks of this feature a no-op. Granting it more than (RC)
         would be worse than not granting it at all.

    False means "not a working lock", which includes the directory denied to
    everyone - that one is not writable, but the guard cannot use it either,
    and it needs the same attention.
    """
    if aces is None:
        return None

    lock_sids = {sid for sid, _ in _LOCK_ACL}
    # An INHERIT_ONLY entry does not apply to this directory at all; it only
    # seeds children. It cannot lock or unlock the thing being judged.
    live = [a for a in aces if not (a.flags & _INHERIT_ONLY)]

    for a in live:
        if a.allow and a.mask and a.sid not in lock_sids:
            return False                                    # rule 1
        if not a.allow and a.mask and a.sid in (SYSTEM_SID, ADMINS_SID):
            return False                                    # denied to the guard

    def _granted(sid: str) -> int:
        """Everything allowed to this SID by an entry children also inherit."""
        m = 0
        for a in live:
            if a.allow and a.sid == sid and (a.flags & _OI) and (a.flags & _CI):
                m |= a.mask
        return m

    for sid in (SYSTEM_SID, ADMINS_SID):                    # rule 2
        m = _granted(sid)
        if not (m & _GENERIC_ALL or m & _FULL_CONTROL == _FULL_CONTROL):
            return False

    owner = _granted(OWNER_RIGHTS_SID)                      # rule 3
    if not owner & _READ_CONTROL:
        return False
    if owner & ~(_READ_CONTROL | _SYNCHRONIZE):
        return False

    return True


def _read_dacl(path: str) -> Optional[List[Ace]]:
    """The directory's DACL, or None if it cannot be read.

    GetNamedSecurityInfoW rather than parsing `icacls <path>`, because the
    text output names principals in the console's language and flattens an
    access mask into a rights string. This returns the SIDs and the masks
    themselves. It needs no elevation - reading an ACL is READ_CONTROL, which
    the lock deliberately leaves in place.
    """
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
                # A NULL DACL IS NOT AN EMPTY ONE. It grants everyone full
                # access, and reporting that as "no entries" would read as a
                # lock so tight nothing is in it.
                return [Ace(EVERYONE_SID, True, _FULL_CONTROL, _OI | _CI)]
            count = ctypes.cast(pdacl, ctypes.POINTER(_Acl)).contents.AceCount
            out: List[Ace] = []
            for i in range(count):
                pace = ctypes.c_void_p()
                if not advapi.GetAce(pdacl, i, ctypes.byref(pace)):
                    return None
                hdr = ctypes.cast(pace, ctypes.POINTER(_AceHeader)).contents
                if hdr.AceType not in (0, 1):       # ALLOWED / DENIED only
                    continue                        # audit and alarm entries
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
        return None                     # an unreadable ACL is not an open one


# --------------------------------------------------------------------------
# Permissions the project had before we touched it
#
# THE LOSS (finding #12). unlock_directory ends in `icacls /reset`, and /reset
# does not restore the ACL that was there - it restores the parent's
# INHERITABLE ACEs. Nothing else is possible, because nothing recorded what
# was there.
#
# For an ordinary project those are the same thing and /reset is exactly
# right. For a project with permissions of its own they are not, and the
# difference always runs one way: WIDER. A directory reachable only by its
# owner comes back reachable by Administrators and SYSTEM as well. A key file
# readable by one account comes back inheriting the project default. Protect
# then unprotect is advertised as a round trip, and quietly was not one.
#
# So record it. Only entries that HAVE permissions of their own - a protected
# ACL, or any non-inherited ACE - which on a normal project is none of them,
# so the normal project pays a tree walk and stores an empty record.
#
# The record lives INSIDE the locked backing. That is not tidiness: unprotect
# applies it while elevated, so anything that can write the record can write
# an ACL as Administrator. Inside the lock, that requires being Administrator
# already. Paths in it are relative and re-checked for containment on the way
# out, so a record that somehow lies still cannot name C:\Windows.
# --------------------------------------------------------------------------

ACL_RECORD_NAME = ".demo_cli-acl.json"

_SDDL_REVISION_1 = 1
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_DACL_SECURITY_INFORMATION = 0x00000004
_SE_FILE_OBJECT = 1


def has_custom_acl(aces: Optional[List[Ace]]) -> bool:
    """Does this entry carry permissions of its own? Pure, so it is testable.

    An inherited ACE is reproduced exactly by /reset, so it needs no record.
    Anything else does: a non-inherited ACE, or an empty DACL, which is a
    deliberate "nobody" that /reset would silently turn into "whatever the
    parent says".

    None - the ACL could not be read - is False. We cannot record what we
    cannot read, and claiming otherwise would put a hole in the record rather
    than in the answer.
    """
    if aces is None:
        return False
    if not aces:
        return True
    return any(not a.inherited for a in aces)


def _sddl_of(path: str) -> Optional[str]:
    """This entry's DACL as an SDDL string, or None.

    SDDL rather than a hand-built descriptor: it is Windows' own round-trip
    format, it carries the protected/auto-inherited flags in the same string,
    and what goes back is what came out of this very directory - never
    something this module composed.
    """
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


def _sddl_is_protected(sddl: str) -> bool:
    """Does this SDDL disable inheritance? The flags sit between "D:" and the
    first ACE, and "P" among them is what icacls calls /inheritance:r.

    Read here rather than assumed, because restoring a protected ACL as
    unprotected would let the parent's ACEs back in - which is the exact loss
    this whole record exists to prevent.
    """
    head = sddl.split("D:", 1)[-1].split("(", 1)[0] if "D:" in sddl else ""
    return "P" in head.replace("AI", "").replace("AR", "")


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
    r"""Resolve one recorded path, or None if it does not stay inside root.

    Pure enough to test anywhere, and the reason a lying record is only a
    lying record. unprotect applies these while elevated, so a `..\..\Windows`
    or an absolute path or a junction planted mid-tree would each be an
    arbitrary ACL write as Administrator. realpath collapses all three into
    the same question - does it still land under root - which is the same
    check plan_protect uses for --backing (finding #13).
    """
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
    """{relative path: SDDL} for every entry with permissions of its own.

    Never descends into a reparse point and never records one: a junction's
    ACL belongs to its target, which is not part of this project (finding
    #11). Entries whose ACL cannot be read are skipped rather than guessed
    at - a record with a hole in it is better than a record with a lie in it.
    """
    out: Dict[str, str] = {}
    # No os.name guard. _read_dacl already answers None off Windows, so the
    # walk finds nothing there anyway - and an early return would have made
    # this entire function unreachable on the machine the tests run on.
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
    """Store the record at the top of a directory that is ALREADY LOCKED.

    O_EXCL after an unlink, not open(path, "w"). A pre-planted symlink at this
    path would otherwise let an elevated process truncate whatever it points
    at - the same defect as the fixed elevated-log path in finding #8, and it
    would be careless to earn it twice.
    """
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
    """(record, problem). A missing record is (None, "") - the ordinary case
    for a project protected before this existed, and not something to report.
    A record that is there and unusable IS reported: silently falling back to
    /reset is how permissions went missing without anyone noticing.
    """
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
    """Re-apply the record. Returns (restored, entries that failed).

    An entry that no longer exists is not a failure - files change while a
    project is protected, and there is nothing to restore a permission onto.
    An entry that will not stay inside root IS dropped and reported.
    """
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
        if _apply_sddl(full, sddl):
            done += 1
        else:
            failed.append(rel)
    return done, failed


def is_locked(path: str) -> Optional[bool]:
    """True / False / None when it cannot be determined.

    None rather than False when the ACL cannot be read: "I do not know" and
    "it is open" are different answers, and doctor must not report the second
    when it means the first. See OWNER_RIGHTS_SID for the case where None is
    caused by the lock being TIGHTER than usual, not by its absence.
    """
    return judge_lock(_read_dacl(path))
