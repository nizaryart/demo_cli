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
import shutil
import subprocess
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
    if is_elevated() and unlock_directory(plan.backing):
        done.append(f"unlocked {plan.backing}")
    os.rename(plan.backing, plan.source)
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

    /inheritance:r removes inherited permissions - without it the user's
    inherited Full Control survives and the lock does nothing at all, silently,
    which is the worst possible outcome for a security control.
    """
    if os.name != "nt" or not shutil.which("icacls"):
        return False
    args = ["icacls", path, "/inheritance:r"]
    for sid in _ACL_PRINCIPALS:
        args += ["/grant:r", f"{sid}:(OI)(CI)F"]
    args += ["/T", "/C", "/Q"]
    return _run(args)


def unlock_directory(path: str) -> bool:
    """Give the directory back to its owner and restore inheritance."""
    if os.name != "nt" or not shutil.which("icacls"):
        return False
    return _run(["icacls", path, "/inheritance:e", "/reset", "/T", "/C", "/Q"])


def _run(args: List[str]) -> bool:
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=120)
        return r.returncode == 0
    except Exception:
        return False


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
        # Locked means no entry for anyone outside the two principals. Checking
        # for the ABSENCE of the interactive user is more robust than parsing
        # the whole descriptor, which is localised and format-unstable.
        out = r.stdout
        return "BUILTIN\\Users" not in out and os.environ.get("USERNAME", "\0") not in out
    except Exception:
        return None
