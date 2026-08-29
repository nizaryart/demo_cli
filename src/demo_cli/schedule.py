"""Bring the filesystem guard back after a reboot.

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
Shutting down ends the user session, so the mount process dies like any other
program. The FILES are safe - Stage 2 writes straight through to the backing
directory - but two things are not:

  * C:\\project stops existing. It is a reparse point served by a process that
    is gone, so the path an IDE, a shell and git all know simply is not there.
  * The next session is UNPROTECTED. Someone who recreates the directory, or
    works from the backing path instead, is now unguarded while believing they
    are covered - the sixth appearance of that failure in this project.

A logon task removes "I forgot to mount after rebooting" as a possible state.

--------------------------------------------------------------------------
A TASK, NOT A SERVICE
--------------------------------------------------------------------------
A Windows service starts before logon, restarts on crash, and runs as SYSTEM -
more robust, and it means writing service-lifecycle code and registering with
the SCM. A scheduled task is one `schtasks` command to create, one to delete,
and it is VISIBLE in Task Scheduler, so nothing this tool does to the machine
is hidden from the person running it. Ninety percent of the benefit for a
fraction of the work; the service is noted as future work rather than
pretended away.

`/rl highest` because the mount must write a backing directory locked to
Administrators. That elevation is granted once, at setup, through a UAC prompt
the user has already agreed to - not silently.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional

TASK_PREFIX = "demo_cli guard"


def task_name(project: str) -> str:
    """One task per project, named after it so Task Scheduler is readable.

    Backslashes are the folder separator in the task namespace, so a path
    cannot be used raw - `C:\\Users\\pc\\lab` would create nested folders and
    a task nobody can find again.
    """
    slug = re.sub(r"[^A-Za-z0-9]+", "-", os.path.abspath(project)).strip("-")
    return f"{TASK_PREFIX} - {slug}"


@dataclass
class TaskStatus:
    exists: bool
    name: str
    detail: str = ""


def available() -> bool:
    if os.name != "nt":
        return False
    from shutil import which
    return bool(which("schtasks"))


def _run(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


def status(project: str) -> TaskStatus:
    name = task_name(project)
    if not available():
        return TaskStatus(False, name, "schtasks unavailable")
    r = _run(["schtasks", "/query", "/tn", name])
    if r.returncode != 0:
        return TaskStatus(False, name, "not registered")
    return TaskStatus(True, name, "runs at logon")


def register(project: str, backing: str, port_free_command: Optional[str] = None) -> bool:
    """Create (or replace) the logon task for one project.

    The script does nothing but call `demo_cli mount`, and that is the point.
    Its first version tried to clear a stale mount point itself, in cmd.exe:
    `if exist X rmdir X`, then refuse if anything remained. That refusal fired
    on the first real reboot (2026-08-29) because an empty `.demo_cli` had been
    left inside the mount point, so `rmdir` failed and the guard never came
    back - every boot, with no route out but rmdir by hand.

    Deciding what is safe to delete is judgement, and judgement written in a
    batch file cannot be tested, cannot tell an empty leftover from somebody's
    work, and cannot say why it refused. It now lives in
    `fsmount.mountpoint_obstruction`, which is tested off Windows, and this
    script is left with plumbing only - the same split as fsguard/fsmount.
    """
    if not available():
        return False
    project, backing = os.path.abspath(project), os.path.abspath(backing)
    exe = _demo_cli_command()
    if not exe:
        return False

    # A SCRIPT, NOT AN INLINE COMMAND.
    #
    # The first version built `cmd /c "if exist \"X\" rmdir \"X\" & ..."`,
    # escaping the inner quotes Python-style. cmd.exe DOES NOT USE BACKSLASH
    # ESCAPING - it stored them literally, saw `\"C:\path\"` as garbage, and
    # the action silently did nothing. Observed 2026-08-28: the task reported
    # success, the mount never started, and the log we had just added was
    # never even created.
    #
    # Writing a .cmd file removes the quoting problem entirely, and has two
    # other benefits: the user can READ what the task will do, and can edit it.
    # NOT the project's workspace. That lives INSIDE the mount, which does not
    # exist when this script runs - and the fallback, the backing directory,
    # is locked to Administrators, so the user could not read their own log
    # without an admin shell. %LOCALAPPDATA% is always there, always writable
    # by the person who needs to read it, and survives the project being
    # relocated, mounted, unmounted or removed.
    home = os.path.join(os.environ.get("LOCALAPPDATA")
                        or os.path.expanduser("~"), "demo_cli")
    try:
        os.makedirs(home, exist_ok=True)
    except OSError:
        return False
    slug = task_name(project).replace(TASK_PREFIX + " - ", "")
    script = os.path.join(home, f"autostart-{slug}.cmd")
    log = os.path.join(home, f"autostart-{slug}.log")

    with open(script, "w", encoding="utf-8") as f:
        f.write("@echo off\r\n")
        f.write(f'echo [%DATE% %TIME%] starting >> "{log}"\r\n')
        f.write(f'"{exe}" mount "{project}" --backing "{backing}" >> "{log}" 2>&1\r\n')

    r = _run(["schtasks", "/create", "/tn", task_name(project),
              "/tr", f'"{script}"', "/sc", "onlogon", "/rl", "highest", "/f"])
    return r.returncode == 0


def run_now(project: str) -> bool:
    """Start the task immediately, without waiting for the next logon.

    This is how setup brings the mount up straight away: the task already
    carries /rl highest, so running it needs no SECOND UAC prompt. Without
    this, setup ends with a protected project and no filesystem guard, and
    the user has to reboot or mount by hand - which is exactly the manual
    step the whole command exists to remove.
    """
    if not available() or not status(project).exists:
        return False
    return _run(["schtasks", "/run", "/tn", task_name(project)]).returncode == 0


def unregister(project: str) -> bool:
    """Remove the task. Absent is success - teardown must never refuse to
    continue because a step was already done."""
    if not available():
        return False
    name = task_name(project)
    ok = True
    if status(project).exists:
        ok = _run(["schtasks", "/delete", "/tn", name, "/f"]).returncode == 0
    for path in autostart_paths(project):      # leave nothing behind
        try:
            os.unlink(path)
        except OSError:
            pass
    return ok


def autostart_paths(project: str):
    """The script and log this project's task uses. Public so teardown can
    remove them and doctor can point at the log."""
    home = os.path.join(os.environ.get("LOCALAPPDATA")
                        or os.path.expanduser("~"), "demo_cli")
    slug = task_name(project).replace(TASK_PREFIX + " - ", "")
    return (os.path.join(home, f"autostart-{slug}.cmd"),
            os.path.join(home, f"autostart-{slug}.log"))


def _demo_cli_command() -> Optional[str]:
    """The absolute path to demo_cli, for the task's action.

    Absolute, never bare: a scheduled task does not inherit the interactive
    session's PATH, and a task whose command cannot be found fails silently at
    logon - which is exactly the "installed but inert" state this is meant to
    remove.
    """
    from shutil import which
    return which("demo_cli")
