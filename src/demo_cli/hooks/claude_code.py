"""Claude Code PreToolUse integration - the auto-fire path.

Claude Code runs a PreToolUse hook *before* a tool executes and passes the tool
call as JSON on stdin:

    {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "...",
     "tool_input": {"command": "...", "description": "..."}, ...}

A hook steers Claude Code by printing JSON on stdout:

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "allow" | "deny" | "ask",
        "permissionDecisionReason": "..."}}

Mapping:
    shadow mode  -> never interferes: evaluate, snapshot, record a receipt,
                    then exit 0 so the normal permission flow is unchanged.
    enforce mode -> ESCALATE => deny, CONTEXT_MISMATCH => ask, otherwise allow
                    (recoverable mutations are snapshotted first, then allowed).

Posture: a *decision* is fail-closed (no recovery path on prod => escalate),
but our *own* errors are fail-open - a bug in this tool must never brick the
user's agent. If we cannot parse or evaluate, we step aside (exit 0).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, List

from . import attributed
from .. import fsreport
from ..classify import POSIX, POWERSHELL
from ..config import load_config
from ..context import Intent
from ..guard import AgentDirectoryUnreachable, Guard, agent_directory
from . import event_list, load_host_config, reconcile_handler

_FILE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
# Claude Code fires the same PreToolUse shape for both a POSIX shell (Bash) and
# a Windows one (PowerShell); tool_input.command carries the raw command line
# either way, so both route through the same command evaluation path.
_SHELL_TOOLS = {"Bash", "PowerShell"}

_BANNER = "\u2500" * 4

def _stderr(msg: str) -> None:
    sys.stderr.write(msg + "\n")

def _loud_save(result) -> None:
    """Unmissable stderr for a captured recovery point (enforce path)."""
    rid = result.recovery_entry.get("id", "")
    n = len(getattr(result, "affected_paths", None) or []) or None
    what = f"{n} files" if n else "target"
    _stderr("")
    _stderr(f"demo_cli \u2705 recovery point {rid} captured before this ran ({what}).")
    _stderr(f"         mistake? undo it with:  demo_cli undo {rid}")
    try:
        from ..render import feedback_url_for
        url = feedback_url_for(result)
        if url:
            _stderr(f"         wrong call?  report it (prefilled): {url}")
    except Exception:
        pass
    _stderr("")

def _loud_block(result) -> None:
    """Unmissable stderr for an escalate/block (enforce path)."""
    _stderr("")
    _stderr(f"demo_cli \u26d4 blocked: {result.decision.reason}")
    entry = getattr(result, "recovery_entry", None)
    if entry:
        # Captured-then-refused. The snapshot is real; the command is not.
        _stderr(f"         a recovery point ({entry.get('id', '')}) was captured before the")
        _stderr("         refusal; the command did not run, so there is nothing to undo.")
    else:
        _stderr("         nothing was captured, and nothing is claimed to be.")
    try:
        from ..render import feedback_url_for
        url = feedback_url_for(result)
        if url:
            _stderr(f"         wrong call?  report it (prefilled): {url}")
    except Exception:
        pass
    _stderr("")


def _emit(stdout, permission: str, reason: str) -> None:
    stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            # Prefixed at the single exit point, so no caller can
            # forget. See hooks.attributed.
            "permissionDecisionReason": attributed(reason),
        }
    }))
    stdout.flush()


def run_pretooluse(stdin, stdout) -> int:
    # Fail-open on our own parsing errors: never brick the agent. But fail-open
    # LOUD - surface it on stderr so the user can see the tool stepped aside
    # rather than silently allowing.
    try:
        raw = stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        sys.stderr.write(f"demo_cli: could not parse hook input, stepping aside ({exc})\n")
        return 0

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    description = tool_input.get("description")

    is_shell = tool_name in _SHELL_TOOLS
    is_file = tool_name in _FILE_TOOLS
    if not (is_shell or is_file):
        # Beta scope: gate shell + file-write tools. Everything else passes.
        return 0

    guard = None
    try:
        cfg = load_config(start=cwd)
        # WHAT THE FILESYSTEM LAYER DID, BEFORE ANYTHING ELSE.
        #
        # It runs in another process, does not block, and logs to a file
        # inside the Administrators-only backing directory - so the agent
        # cannot see it work, and on 2026-09-02 one reported four snapshotted
        # deletions as "unblocked destructions". Reported here because this is
        # the only channel that reaches the agent. One command behind by
        # nature: PreToolUse fires before the command runs, so these belong to
        # the PREVIOUS one, and the wording says so.
        fs_note = fsreport.summary(cfg)
        if fs_note:
            _stderr("")
            _stderr(fs_note)
        guard = Guard(config=cfg)
        if is_shell:
            command = (tool_input.get("command") or "").strip()
            if not command:
                return 0
            # Claude Code fires the same event shape for both shells, and the
            # tool name is the only reliable signal of which one wrote the text.
            # A Windows box can run either, so os.name is NOT a safe guess.
            with agent_directory(cwd):
                result = guard.evaluate(
                    command,
                    intent=Intent(reasoning=description),
                    agent_id=data.get("agent_id", "claude-code"),
                    session_id=data.get("session_id", "unknown"),
                    dialect=POWERSHELL if tool_name == "PowerShell" else POSIX,
                )
        else:
            # Edit / Write / MultiEdit -> file_path ; NotebookEdit -> notebook_path
            file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
            if not file_path:
                return 0
            # BOTH ENTRY POINTS. evaluate_file_edit does its own
            # os.path.abspath(file_path), so wrapping only the shell call
            # above would leave every relative Edit / Write / MultiEdit /
            # NotebookEdit resolving against the hook's directory.
            with agent_directory(cwd):
                result = guard.evaluate_file_edit(
                    file_path, tool_name=tool_name,
                    intent=Intent(reasoning=description),
                    agent_id=data.get("agent_id", "claude-code"),
                    session_id=data.get("session_id", "unknown"),
                )
    except AgentDirectoryUnreachable as exc:
        # We cannot stand where the agent stands, so a relative path in this
        # call cannot be resolved and nothing can be captured for it. Codex has
        # denied here since 09-13; this host fell into the blanket handler below
        # and stepped aside on the identical exception.
        if getattr(guard, "mode", None) != "enforce":
            _stderr(f"demo_cli [shadow] would deny: the directory the agent "
                    f"reported ({exc}) cannot be entered")
            return 0
        _emit(stdout, "deny",
              f"the working directory the agent reported ({exc}) cannot be "
              f"entered, so a relative path in this call cannot be resolved "
              f"and nothing can be captured for it")
        return 0
    except Exception as exc:  # our bug must not block the user
        sys.stderr.write(f"demo_cli: internal error, stepping aside ({exc})\n")
        return 0

    # shadow mode: observe only - but make a genuinely interesting decision or a
    # fresh snapshot *visible* on stderr, so value isn't silently buried.
    if guard.mode != "enforce":
        if result.decision.is_blocking or result.decision.is_ask:
            sys.stderr.write(f"demo_cli [shadow] {result.decision.decision}: {result.decision.reason}\n")
        elif result.recovery_entry:
            rp = os.path.basename(result.recovery_entry["recovery_point"])
            rid = result.recovery_entry.get("id", "")
            sys.stderr.write(f"demo_cli [shadow] snapshot {rid} captured ({rp}); undo with `demo_cli undo {rid}`\n")
        return 0

    reason = result.decision.reason
    # Blocking is tested FIRST. The nonrecoverable-surface branch captures and
    # then refuses, so the save arm would announce a recovery point for a
    # command that never ran. The shadow block above already orders it this way.
    if result.decision.is_blocking:
        _loud_block(result)         # <-- make the block legible, with report link
    elif result.recovery_entry:
        rid = result.recovery_entry.get("id", "")
        reason += f"  (recovery point {rid}; undo with `demo_cli undo {rid}`)"
        _loud_save(result)          # <-- make the save FELT, on stderr
    if fs_note:
        # Also on the decision reason, not only stderr. Whether hook stderr
        # reaches the model is up to the host and its version; this field
        # reliably does, and an agent that cannot see the fs layer draws
        # wrong conclusions about the whole guard.
        reason += "\n\n" + fs_note
    _emit(stdout, result.permission, reason)
    return 0


# --------------------------------------------------------------------------
# Installation helpers
# --------------------------------------------------------------------------

_FILE_MATCHER = "Edit|Write|MultiEdit|NotebookEdit"
# Separate matcher entries (rather than one "Bash|PowerShell" block) so an
# older Bash-only install upgrades by gaining a new PowerShell block, and so
# `"Bash" in matchers` stays a valid way to check coverage.
_SHELL_MATCHERS = ("Bash", "PowerShell")


# DECLARED, not left to the host. We used to declare none here and take
# whatever Claude Code's default is - a number we do not know and therefore
# cannot size the snapshot cap against. Measured 2026-09-16: on a timeout the
# host kills the hook, runs the command unguarded, and prints nothing (a
# CRASHED hook it does announce). An unknown budget for a silent failure is
# not a budget.
_HOOK_TIMEOUT = 120


def _handler() -> Dict:
    return {"type": "command", "command": "demo_cli hook", "timeout": _HOOK_TIMEOUT}


def settings_snippet() -> Dict:
    return {
        "hooks": {
            "PreToolUse": [
                {"matcher": m, "hooks": [_handler()]} for m in _SHELL_MATCHERS
            ] + [
                {"matcher": _FILE_MATCHER, "hooks": [_handler()]},
            ]
        }
    }


def install_into_settings(path: str) -> List[str]:
    """Register or RECONCILE the PreToolUse hooks. Returns what changed.

    Add-if-absent until 2026-09-17: a matching command string skipped the
    whole entry, so the raised timeout never reached an existing install and
    doctor reported it green. Now each matcher is brought up to _handler().
    """
    settings = load_host_config(path)
    pre = event_list(settings, "PreToolUse")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _ours(matcher: str):
        for b in pre:
            if not isinstance(b, dict) or b.get("matcher") != matcher:
                continue
            for h in b.get("hooks") or []:
                if isinstance(h, dict) and h.get("command") == "demo_cli hook":
                    return h
        return None

    # A pre-PowerShell install is still upgraded by appending the missing
    # block; what is new is that the block already there is no longer skipped.
    changed: List[str] = []
    for matcher in (*_SHELL_MATCHERS, _FILE_MATCHER):
        handler = _ours(matcher)
        if handler is None:
            pre.append({"matcher": matcher, "hooks": [_handler()]})
            changed.append(f"{matcher}: registered")
        else:
            changed += [f"{matcher}: {c}" for c in
                        reconcile_handler(handler, _handler())]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    return changed
