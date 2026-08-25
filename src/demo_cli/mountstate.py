"""Is the filesystem guard running right now?

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
"Installed but inert" has now been the dangerous state FOUR separate times in
this project:

    1. Codex's hook config was written in a shape Codex silently ignored.
    2. A UTF-8 BOM made the config unparseable and disabled the whole guard.
    3. `doctor` only knew about Claude Code, so a Codex hook sat unnoticed.
    4. And now: a mount that is not running.

Every time, the tool looked installed and protected nothing, and every time
the unanswerable question was the same one - "is this thing actually guarding
me?". A mount makes it worse than the hooks did, because a hook at least fires
per action; a mount that stopped is simply a directory that no longer exists.

So the guard records that it is running, and `doctor` reads it back. Not a
convenience: it is the only way to answer the question.

--------------------------------------------------------------------------
WHY A DETACHED MOUNT NEEDS A LOG FILE
--------------------------------------------------------------------------
Running in the foreground, `[fs] delete: notes.txt snapshotted (abc123)` goes
to the terminal and the person sees it. Detached, there is no terminal, and
those lines are the ONLY channel telling anyone a snapshot exists and what its
id is. Losing them would make recovery points effectively unfindable, which is
the same failure as not taking them.

So a detached mount writes them to `<workspace>/mount.log`, and doctor points
at it.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from .config import Config

STATE_NAME = "mount.json"
LOG_NAME = "mount.log"


def state_path(cfg: Config) -> str:
    return os.path.join(cfg.workspace, STATE_NAME)


def log_path(cfg: Config) -> str:
    return os.path.join(cfg.workspace, LOG_NAME)


@dataclass
class MountStatus:
    """What doctor needs to say one honest sentence.

    `running` is deliberately Optional. None means "there is a record but I
    cannot tell" - a state file from another machine, a PID check that failed.
    Reporting False there would claim the guard is down when it may not be,
    and a false all-clear in either direction is what this module exists to
    prevent.
    """
    recorded: bool
    running: Optional[bool]
    mountpoint: Optional[str] = None
    backing: Optional[str] = None
    pid: Optional[int] = None
    started: Optional[float] = None
    log: Optional[str] = None

    @property
    def stale(self) -> bool:
        """A record exists but the process behind it is gone - a mount that
        crashed or was killed. Worth saying out loud rather than treating as
        'not mounted': the user believes they are protected."""
        return self.recorded and self.running is False

    @property
    def age_minutes(self) -> Optional[int]:
        if not self.started:
            return None
        return int((time.time() - self.started) / 60)


def write(cfg: Config, pid: int, mountpoint: str,
          backing: Optional[str] = None) -> str:
    os.makedirs(cfg.workspace, exist_ok=True)
    path = state_path(cfg)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pid": pid, "mountpoint": mountpoint, "backing": backing,
                   "started": time.time(), "host": os.name}, f)
    return path


def clear(cfg: Config) -> None:
    try:
        os.unlink(state_path(cfg))
    except OSError:
        pass


def read(cfg: Config) -> Optional[dict]:
    try:
        with open(state_path(cfg), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        # A corrupt or missing state file means "no record", never "running".
        return None


def pid_alive(pid: int) -> Optional[bool]:
    """True / False / None when it cannot be determined.

    PIDs are reused, so this alone is not proof - `status` also requires the
    recorded mount point to still exist, and the two together are enough for
    an honest report.
    """
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            SYNCHRONIZE = 0x00100000
            handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            # ERROR_INVALID_PARAMETER (87) means no such process. Anything
            # else - notably ERROR_ACCESS_DENIED - means the process exists
            # but we may not touch it, which is still alive.
            return ctypes.windll.kernel32.GetLastError() != 87
        except Exception:
            return None
    try:
        os.kill(pid, 0)          # signal 0: existence check, delivers nothing
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True              # exists, owned by someone else
    except Exception:
        return None


def status(cfg: Config) -> MountStatus:
    """The one call doctor makes."""
    data = read(cfg)
    if not data:
        return MountStatus(recorded=False, running=False, log=log_path(cfg))

    pid = data.get("pid")
    alive = pid_alive(pid) if isinstance(pid, int) else None

    # A state file written on another OS cannot be checked here at all - a
    # Windows PID means nothing to a Linux kernel and would give a confident
    # wrong answer either way.
    if data.get("host") != os.name:
        alive = None

    mountpoint = data.get("mountpoint")
    if alive and mountpoint and not os.path.exists(mountpoint):
        # The process lives but the mount point is gone: either a reused PID,
        # or a filesystem that died without cleaning up. Not running.
        alive = False

    return MountStatus(recorded=True, running=alive, mountpoint=mountpoint,
                       backing=data.get("backing"), pid=pid,
                       started=data.get("started"), log=log_path(cfg))
