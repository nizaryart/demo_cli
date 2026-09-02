"""Tell the agent what the filesystem layer did.

WHY THIS EXISTS
---------------
On 2026-09-02 an agent worked through ten scripted tasks on a guarded Windows
project and reported: "one block, four unblocked destructions ... the tool
intercepted the least destructive operation and missed the three that
permanently destroyed data."

Every one of those four had been snapshotted. `mount.log` listed all of them
with recovery ids. The agent was not lying and was not careless - it had no
way to know. The filesystem layer does not block; it snapshots and passes the
operation through, and its only output goes to the mount process's stderr,
which lands in a log inside the BACKING directory. That directory is
Administrators-only, by design, because it is what stops the agent reaching
around the guard. So the one party whose behaviour we are trying to inform is
structurally unable to observe the layer working.

From the agent's seat, a working filesystem guard and an absent one are
identical. That is not a cosmetic problem:

  * a red-teamer reports the guard as broken, with a clean evidence table;
  * an agent that believes a deletion went through uncaught has no reason to
    mention it, so the human is not told either;
  * the layer's whole deterrent value depends on the actor knowing it is there.

WHAT THIS DOES
--------------
The hook already reads and writes `receipts.jsonl`, and the fs guard writes
its captures to the same chain. So the hook can read back what the fs layer
did and say so. A marker file records the last capture reported, so each one
is mentioned once.

THE TIMING IS ONE COMMAND BEHIND, AND IS REPORTED AS SUCH.
PreToolUse fires BEFORE the command runs, so the captures available now are
the ones caused by the PREVIOUS command. Saying "since your last command" is
the honest framing; claiming these relate to the command being gated would be
a new, smaller version of the same dishonesty this module exists to fix.

Deliberately not: reading mount.log. The hook runs unelevated and the log is
in the locked backing. Receipts are the channel that is actually readable
from where the agent stands.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

MARKER = ".fs_seen"

# How far back to look. Receipts are append-only and the fs guard can write
# hundreds in a burst (a recursive delete is one receipt per file), so reading
# the whole file on every single tool call would be a real cost on a hot path.
_TAIL_BYTES = 65536
_MAX_SHOWN = 5


def _tail_lines(path: str, max_bytes: int = _TAIL_BYTES) -> List[str]:
    """The last complete lines of a file, without reading all of it."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        start = max(0, size - max_bytes)
        f.seek(start)
        chunk = f.read()
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    # A mid-line seek leaves a partial first line; drop it rather than fail to
    # parse it. (Torn lines also occur for a second reason - see the receipts
    # lock-domain split - and are skipped the same way below.)
    return lines[1:] if start > 0 else lines


def _marker_path(cfg) -> str:
    return os.path.join(cfg.workspace, MARKER)


def _last_seen(cfg) -> str:
    try:
        with open(_marker_path(cfg), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _remember(cfg, stamp: str) -> None:
    try:
        os.makedirs(cfg.workspace, exist_ok=True)
        with open(_marker_path(cfg), "w", encoding="utf-8") as f:
            f.write(stamp)
    except OSError:
        pass        # a marker we cannot write means a repeat, not a failure


def pending(cfg, mark: bool = True) -> List[str]:
    """One line per filesystem capture the agent has not been told about.

    Never raises: every caller is a hook whose own errors must not reach the
    user's agent. An empty list is the correct answer to "we could not tell".
    """
    try:
        path = cfg.receipts_path
        if not os.path.exists(path):
            return []
        since = _last_seen(cfg)
        rows = []
        newest = since
        for line in _tail_lines(path):
            line = line.strip()
            if not line or '"fsguard"' not in line:
                continue            # cheap reject before the JSON parse
            try:
                r = json.loads(line)
            except ValueError:
                continue            # torn or partial line: skip, never fail
            if r.get("agent_id") != "fsguard":
                continue
            stamp = r.get("timestamp") or ""
            if not stamp or stamp <= since:
                continue
            rows.append(r)
            newest = max(newest, stamp)
        if not rows:
            return []
        if mark:
            _remember(cfg, newest)
        return _describe(rows)
    except Exception:
        return []


def _describe(rows: List[dict]) -> List[str]:
    """Short, actionable lines - what happened and how to undo it."""
    out = []
    for r in rows[:_MAX_SHOWN]:
        action = (r.get("action_raw") or "").replace("[fs] ", "").strip()
        rid = _recovery_id(r)
        if rid:
            out.append(f"{action}  ->  snapshotted, undo: demo_cli undo {rid}")
        else:
            out.append(f"{action}  ->  NOT snapshotted ({r.get('reason') or 'no reason recorded'})")
    extra = len(rows) - _MAX_SHOWN
    if extra > 0:
        out.append(f"...and {extra} more (see `demo_cli log`)")
    return out


def _recovery_id(r: dict) -> Optional[str]:
    """The undo id for a receipt, from the recovery point's filename.

    Recovery points are named `<file>.<stamp>.<id>.bak`, and the id is what
    `demo_cli undo` takes. Reading it back out of the path avoids adding a
    field to the receipt schema for something already encoded there.
    """
    rp = r.get("recovery_point")
    if not rp:
        return None
    parts = os.path.basename(rp).split(".")
    return parts[-2] if len(parts) >= 3 else None


def summary(cfg, mark: bool = True) -> str:
    """`pending` as one block of text, or "" when there is nothing to say."""
    lines = pending(cfg, mark=mark)
    if not lines:
        return ""
    head = ("demo_cli [fs] the filesystem guard captured these since your "
            "last command:")
    return "\n".join([head] + ["  " + line for line in lines])
