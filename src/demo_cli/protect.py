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

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from .fspassthrough import Backing

# What a protected project's backing directory is called. A suffix rather than
# a hidden sibling elsewhere: whoever finds it should be able to tell instantly
# what it belongs to, including a year from now with the tool uninstalled.
BACKING_SUFFIX = ".real"

# Only these may touch the backing directory once it is locked. The guard runs
# elevated and therefore qualifies; an ordinary agent process does not.
_ACL_PRINCIPALS = ["*S-1-5-18",         # SYSTEM
                   "*S-1-5-32-544"]     # Administrators
# SIDs rather than names, because "Administrators" is localised - on a French
# or Arabic Windows the name differs and icacls would fail with a message
# nobody would connect to a locale.


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

    exe = shutil.which("demo_cli")
    if not exe:
        return None

    # RUN IT THROUGH cmd.exe WITH THE OUTPUT REDIRECTED.
    #
    # ShellExecute cannot redirect handles, and the elevated console closes the
    # instant the process exits - so a failure produced nothing but "the
    # elevated step failed", with the actual error already gone. Wrapping in
    # `cmd /c "... > log 2>&1"` is the only way to keep it, and it is the same
    # move the detached mount already needed for its [fs] lines.
    log = os.path.join(tempfile.gettempdir(), "demo_cli-elevated.log")
    try:
        os.unlink(log)
    except OSError:
        pass
    inner = subprocess.list2cmdline([exe] + list(args))
    params = f'/c "{inner} > "{log}" 2>&1"'

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040                      # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"                        # this is what prompts UAC
    info.lpFile = "cmd.exe"
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
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    return int(code.value)


def elevated_output() -> str:
    """What the last elevated run printed. Empty when there was none.

    Without this a failure in the elevated half is completely opaque to the
    half that asked for it.
    """
    log = os.path.join(tempfile.gettempdir(), "demo_cli-elevated.log")
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


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
        if os.path.commonpath([dest, source]) == source:
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
        here = os.path.abspath(os.getcwd())
        if here == source or os.path.commonpath([here, source]) == source:
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

    Ordered so that a failure leaves the least damage: relocate first (atomic,
    reversible by one rename), lock second (cosmetic if it fails - the files
    are already where they need to be, merely unlocked, and the warning says
    so).
    """
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = [f"moved {plan.source} -> {plan.backing}"]
    Backing.relocate(plan.source, plan.backing)
    if plan.will_lock and is_elevated():
        if lock_directory(plan.backing):
            done.append(f"locked {plan.backing} to Administrators and SYSTEM")
        else:
            done.append(f"COULD NOT LOCK {plan.backing} - it is writable by "
                        f"anything, so the guard can be bypassed")
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
    """Undo a protect. Unlock first, because a locked directory cannot be moved
    by the account that is about to move it."""
    if not plan.ok:
        raise ValueError("; ".join(plan.problems))
    done = []
    # A failed unlock is SAID, not skipped. The first version appended the
    # "unlocked" line only on success and carried on otherwise, so a project
    # came home still locked to Administrators with its owner shut out and
    # nothing in the output to explain it. Handing something back in a state
    # the user cannot use, silently, is the failure this project is about.
    if is_elevated():
        if unlock_directory(plan.backing):
            done.append(f"unlocked {plan.backing}")
        else:
            done.append(f"COULD NOT UNLOCK {plan.backing} - the restored "
                        f"project will still be Administrators-only. Fix with: "
                        f"icacls <path> /inheritance:e ; icacls <path> /reset /T")
    else:
        done.append("not elevated: the ACL was left as it is. If the backing "
                    "was locked, re-run this from an Administrator shell.")
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
    if os.name != "nt" or not shutil.which("icacls"):
        return False
    args = ["icacls", path, "/inheritance:r"]
    for sid in _ACL_PRINCIPALS:
        args += ["/grant:r", f"{sid}:(OI)(CI)F"]
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
    """
    if os.name != "nt" or not shutil.which("icacls"):
        return False
    if not _run(["icacls", path, "/inheritance:e"]):
        return False
    if not _run(["icacls", path, "/reset"]):
        return False
    return _reset_children(path)


def _reset_children(path: str) -> bool:
    """Make every existing child inherit the directory's ACL.

    Skipped for an empty directory: `icacls <dir>\\*` matches nothing there and
    reports a failure that means nothing went wrong.
    """
    try:
        if not os.listdir(path):
            return True
    except OSError:
        return False
    return _run(["icacls", os.path.join(path, "*"), "/reset", "/T", "/Q"])


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


def is_locked(path: str) -> Optional[bool]:
    """True / False / None when it cannot be determined.

    None rather than False when icacls is unavailable or unreadable: "I do not
    know" and "it is open" are different answers, and doctor must not report
    the second when it means the first.
    """
    if os.name != "nt" or not shutil.which("icacls"):
        return None
    try:
        r = subprocess.run(["icacls", path], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
    except Exception:
        return None

    # Count the access-control entries rather than recognising principal NAMES.
    # The first version looked for "BUILTIN\\Users" and the USERNAME, which is
    # wrong on any localised Windows - the machine this was developed against
    # reports "BUILTIN\\Administrateurs". Rights strings like (OI)(CI)(F) are
    # NOT localised, so counting entries and checking their rights works in any
    # language.
    #
    # Locked == exactly the two principals we granted, each with inheritable
    # full control, and nothing else.
    aces = []
    for i, line in enumerate((r.stdout or "").splitlines()):
        line = line.strip()
        if not line or line.startswith("Successfully") or line.startswith("Failed"):
            continue
        if i == 0:
            line = line[len(path):].strip()     # first line carries the path
        if ":" in line:
            aces.append(line)
    if not aces:
        return None
    return len(aces) == len(_ACL_PRINCIPALS) and \
        all("(OI)(CI)(F)" in a.replace(" ", "") for a in aces)
