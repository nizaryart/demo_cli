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

    The command it runs deletes a STALE REPARSE POINT first. If a shutdown
    leaves the junction behind - untested as of writing, and the reason this
    is here - the mount would refuse with "already exists" on every boot, and
    the user would find a broken directory where their project used to be.
    Deleting a dangling reparse point removes nothing: the bytes live in the
    backing directory, and the junction is only a pointer to a filesystem that
    is no longer running.
    """
    if not available():
        return False
    project, backing = os.path.abspath(project), os.path.abspath(backing)
    exe = _demo_cli_command()
    if not exe:
        return False

    # cmd /c so both steps run in one action. rmdir (not del) because a
    # reparse point is a directory entry; it removes the link, never a tree.
    action = (f'cmd /c "if exist \\"{project}\\" rmdir \\"{project}\\" & '
              f'{exe} mount \\"{project}\\" --backing \\"{backing}\\""')
    r = _run(["schtasks", "/create", "/tn", task_name(project),
              "/tr", action, "/sc", "onlogon", "/rl", "highest", "/f"])
    return r.returncode == 0


def unregister(project: str) -> bool:
    """Remove the task. Absent is success - teardown must never refuse to
    continue because a step was already done."""
    if not available():
        return False
    name = task_name(project)
    if not status(project).exists:
        return True
    return _run(["schtasks", "/delete", "/tn", name, "/f"]).returncode == 0


def _demo_cli_command() -> Optional[str]:
    """The absolute path to demo_cli, for the task's action.

    Absolute, never bare: a scheduled task does not inherit the interactive
    session's PATH, and a task whose command cannot be found fails silently at
    logon - which is exactly the "installed but inert" state this is meant to
    remove.
    """
    from shutil import which
    return which("demo_cli")
