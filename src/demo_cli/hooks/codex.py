"""Codex CLI PreToolUse integration - the third host adapter.

Codex fires a PreToolUse hook *before* a tool runs and passes the call as JSON
on stdin:

    {"hook_event_name": "PreToolUse", "tool_name": "Bash",
     "tool_input": {"command": "..."}, "cwd": "...",
     "session_id": "...", "turn_id": "...", "tool_use_id": "...",
     "permission_mode": "...", "model": "..."}

A hook steers Codex by printing the same envelope Claude Code uses:

    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
        "permissionDecision": "allow" | "deny",
        "permissionDecisionReason": "...",
        "additionalContext": "..."}}

Codex adopted Claude Code's hook schema, so most of this adapter is the same
shape as hooks/claude_code.py. Four differences are deliberate decisions:

  * **DENY is the only word Codex listens to.** Its schema lists
    allow/deny/ask, but the RUNTIME rejects everything except deny:
    "PreToolUse hook returned unsupported permissionDecision:allow" (and the
    same for ask). A rejected decision marks the hook FAILED, which fails OPEN
    and prints an error to the user on every single tool call. So this adapter
    speaks only to deny; for anything else it stays silent, which is Codex's
    documented "proceed" and cannot be rejected.

    Consequence for CONTEXT_MISMATCH ("right action, wrong target"): there is
    no way to say "proceed, but be careful" - allow is refused, and a reason
    without a decision is an error too. The snapshot is still taken and the
    receipt still records CONTEXT_MISMATCH honestly; the warning goes to
    stderr. What we must NOT do is send "ask", which would let the command run
    while claiming a human had been consulted - the same class of lie FIX #5
    exists to prevent.

    Found by running it. The published docs say allow is honoured, and the
    binary's own JSON-schema enum lists all three - the enum is what the parser
    accepts, not what the runtime acts on.

  * **`apply_patch` IS gated, via the patch's own grammar.** Codex's file-write
    tool delivers a patch rather than a file path, and the first version of this
    adapter stepped aside rather than guess at it. Real captured payloads showed
    that was wrong: the format names every target explicitly and absolutely -

        *** Begin Patch
        *** Update File: /abs/path
        @@
        -old
        +new
        *** End Patch

    which is stable grammar, not a blob to be guessed at. Each target now goes
    through the SAME second door the Claude Code adapter uses for Edit/Write
    (`evaluate_file_edit`), so an existing file is snapshotted before it is
    overwritten or deleted. This matters: file edits were 3 of the 7 tool calls
    in the first live session - it is how Codex does most of its writing, not an
    edge case.

  * **The command arrives as plain text.** All observed payloads use a string.
    `_command_text` still accepts an argv list (Codex's own schema declares the
    field unconstrained) but WARNS loudly if one ever appears, so a change in
    shape is discovered rather than silently absorbed.

  * **No declared intent.** Codex sends no per-call `description`, so the
    why-ledger degrades to the command text on this host.

Posture: fail-open on our own errors, matching the Claude Code adapter. Note
that fail-CLOSED is not achievable here even if we wanted it: if this process
crashes, Codex marks the hook failed and continues, so a crash can never block
a command. The only honest block is a `deny` we emit ourselves.

Scope: verified against real payloads captured from Codex 0.147.0 on Linux
(`tests/fixtures/codex/`), not only against the published contract. Set
DEMO_CLI_HOOK_DEBUG=1 to dump a raw payload to stderr when re-checking a new
Codex release.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

from . import attributed

from ..classify import POSIX, POWERSHELL
from ..config import load_config
from ..context import Intent
from ..decide import ASK, BLOCKING
from ..guard import AgentDirectoryUnreachable, Guard, agent_directory

# The command Codex invokes; also written into hooks.json on install.
HOOK_COMMAND = "demo_cli hook-codex"

# Codex's shell tool, VERIFIED against live payloads from 0.147.0: the name is
# exactly "Bash". Earlier guesses (`shell`, `local_shell`) are removed - carrying
# names the host never sends is just noise pretending to be safety.
_SHELL_TOOLS = {"Bash"}

# Codex's file-write tool. Gated via the patch grammar (see _patch_targets).
_PATCH_TOOL = "apply_patch"

# `mcp__*` and everything else stay out of beta scope, matching the Claude Code
# adapter.


def _stderr(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def _command_text(tool_input: Dict) -> str:
    """The command to classify, from whatever shape Codex delivers.

    Every payload observed from Codex 0.147.0 uses a plain string. The argv-list
    branch below has never fired - it is kept because Codex's own input schema
    declares `tool_input` unconstrained, so the shape is not contractually
    guaranteed. It WARNS rather than absorbing the change quietly: a silent
    assumption about payload shape is what caused every bug found on this port.

    If a list ever does arrive, `bash -lc "<script>"` carries the real command in
    its last element; classifying the wrapper would match no rule at all. Same
    lesson as finding #010a, where Claude Code's `eval '<cmd>' < /dev/null`
    wrapper hid every `!`-mode command from the classifier.
    """
    cmd = tool_input.get("command")
    if isinstance(cmd, str):
        return cmd.strip()
    if isinstance(cmd, list):
        _stderr("demo_cli: Codex sent a LIST, not text - verify this adapter "
                "(no observed payload does this; the unwrap below is untested "
                "against reality).")
        parts = [str(c) for c in cmd]
        if not parts:
            return ""
        if (len(parts) >= 3 and os.path.basename(parts[0]) in ("bash", "sh", "zsh")
                and parts[1].startswith("-")):
            return parts[-1].strip()
        return " ".join(parts).strip()
    return ""


# A Codex apply_patch payload names each file it touches on its own line:
#     *** Add File: /abs/path        *** Update File: /abs/path
#     *** Delete File: /abs/path     *** Move to: /abs/path
# That is a documented grammar, so the targets are read exactly rather than
# guessed - the same "anchor on stable grammar" rule the classifier follows.
_PATCH_OP = re.compile(
    r"^\*\*\*\s+(Add File|Update File|Delete File|Move to):\s*(.+?)\s*$", re.M)


def _patch_targets(patch_text: str) -> List[Tuple[str, str]]:
    """[(operation, path)] for every file operation in an apply_patch payload.

    A single patch may carry SEVERAL operations (an Add and an Update together
    was observed in the very first live session), so this returns a list - and
    the caller must account for all of them or refuse, never a subset. Same
    discipline as FIX #5.
    """
    return [(m.group(1), m.group(2)) for m in _PATCH_OP.finditer(patch_text or "")]


def _mismatch_summary(mismatches: List[Tuple[str, str, str]]) -> str:
    return ("; ".join(f"{field}: declared {declared}, actual {actual}"
                      for field, declared, actual in mismatches)
            or "the declared context")


def _decide_permission(decision: str,
                       mismatches: List[Tuple[str, str, str]]) -> Tuple[str, Optional[str]]:
    """Map a disposition onto what Codex actually honours: (permission, context).

    Pure, so the CONTEXT_MISMATCH branch is testable on its own. That branch is
    currently unreachable through this hook - the adapter declares no intent, so
    `compare_intent` never produces a mismatch (the same is true of the Claude
    Code adapter). It is implemented and locked by a test anyway, because the
    naive mapping to "ask" is a silent fail-open the moment intent is wired in.
    """
    if decision in BLOCKING:                      # ESCALATE
        return "deny", None
    if decision in ASK:                           # CONTEXT_MISMATCH - no `ask` here
        return "allow", (
            "demo_cli: this command's target does not match "
            f"{_mismatch_summary(mismatches)}. A recovery point was captured, so "
            "the action is reversible - but verify the target before relying on it.")
    return "allow", None


def _emit(stdout, permission: str, reason: str,
          additional: Optional[str] = None) -> None:
    payload: Dict = {
        "hookEventName": "PreToolUse",
        "permissionDecision": permission,
        # Prefixed at the single exit point, so no caller can forget.
        # See hooks.attributed.
        "permissionDecisionReason": attributed(reason),
    }
    if additional:
        payload["additionalContext"] = additional
    stdout.write(json.dumps({"hookSpecificOutput": payload}))
    stdout.flush()


def _handle_apply_patch(guard, patch_text: str, stdout, session_id: str) -> int:
    """Gate Codex's file-write tool by reading the patch's own grammar.

    Each named path goes through the same second door the Claude Code adapter
    uses for Edit/Write (`evaluate_file_edit`), which already does the right
    thing per file: an existing file is snapshotted before it is overwritten or
    deleted; a path that does not exist yet has nothing to lose and passes. One
    receipt per file touched.

    Two refusals, both deliberate:
      * a patch we cannot parse is a mutation with no recovery point, which
        decide.py escalates everywhere else - so it escalates here rather than
        waving through a write we could not account for;
      * if ANY named file could not be snapshotted, the whole call is denied.
        Allowing the rest would be a partial capture dressed up as protection -
        the FIX #5 lie in a new place.
    """
    targets = _patch_targets(patch_text)
    enforce = guard.mode == "enforce"

    if not targets:
        _stderr("demo_cli ⛔ apply_patch: no file targets could be read from the "
                "patch; refusing rather than allowing an unaccounted write.")
        if enforce:
            _emit(stdout, "deny",
                  "apply_patch payload could not be parsed, so no recovery point "
                  "could be captured for the files it writes.")
        return 0

    snapped: List[Tuple[str, str]] = []
    blocked: List[str] = []
    for op, path in targets:
        res = guard.evaluate_file_edit(path, tool_name=_PATCH_TOOL,
                                       agent_id="codex", session_id=session_id)
        if res.recovery_entry:
            snapped.append((path, res.recovery_entry.get("id", "")))
        elif res.decision.is_blocking:
            blocked.append(f"{op} {path}: {res.decision.reason}")

    if blocked:
        detail = "; ".join(blocked)
        _stderr(f"demo_cli ⛔ blocked apply_patch: {detail}")
        if enforce:
            _emit(stdout, "deny",
                  f"Could not capture a recovery point before apply_patch ({detail}).")
        return 0

    if snapped:
        ids = ", ".join(f"{os.path.basename(p)} → {rid}" for p, rid in snapped)
        _stderr("")
        _stderr(f"demo_cli ✅ apply_patch: {len(snapped)} file(s) snapshotted first ({ids}).")
        _stderr(f"         mistake? undo with:  demo_cli undo {snapped[0][1]}")
        _stderr("")
    # Nothing emitted on the allow path - see run_pretooluse: Codex rejects
    # permissionDecision:"allow" and marks the hook failed. Silence = proceed.
    return 0


def _strip_bom(raw: str) -> str:
    r"""Drop a byte-order mark from the front of a hook payload.

    A PARSE FAILURE HERE FAILS OPEN - the hook steps aside and the command
    runs unguarded - so a BOM is not a cosmetic problem. Windows produces one
    readily: piping a string to a native process from PowerShell delivered
    TWO of them (2026-09-13):

        b'\xef\xbb\xbf\xef\xbb\xbf{"hook_event_name":"PreToolUse",...'

    And the failure does not announce itself as a BOM. Read through a cp1252
    locale those bytes decode to the mojibake `ï»¿`, so json reports
    "Expecting value: line 1 column 1 (char 0)" rather than its own
    "Unexpected UTF-8 BOM" - which is exactly why this was first misdiagnosed
    as something else entirely.

    Codex itself sends clean UTF-8; this was found with a hand-fed payload and
    the real host is unaffected. It is fixed anyway, because the cost is one
    lstrip and the failure mode is a guard that silently is not there. A
    Windows BOM has already broken this project's config parsing once.

    Every leading mark is stripped, not just the first: two arrived, so
    assuming one is assuming a number nobody has a reason to trust.
    """
    return raw.lstrip("﻿")


def _dialect() -> str:
    r"""Which shell wrote this command text.

    THE TOOL NAME CANNOT ANSWER THIS, and that is the whole difficulty.
    _SHELL_TOOLS is {"Bash"}, and on Windows Codex sends that name while
    running PowerShell - the live session of 2026-09-13 carried
    `Get-Item -LiteralPath .\important.txt | Select-Object ... | Format-List`
    and `Remove-Item -LiteralPath .\important.txt` under tool_name "Bash".
    The Claude Code adapter CAN use the tool name, because Claude Code sends
    "PowerShell" and "Bash" as different tools; it says so in its own comment,
    and this adapter deliberately does NOT copy it.

    So the platform, which is the next best signal: Codex's shell tool runs
    the platform default shell, and on Windows that is PowerShell.

    THIS REPLACES NO SIGNAL AT ALL. Until now this adapter passed nothing and
    took the POSIX default, so every PowerShell command Codex ran on Windows
    was classified as POSIX. That was harmless in practice - three separate
    layers ignore the dialect, which is why 2026-09-13 gated correctly anyway
    (see tests/test_codex_windows_observed.py) - but it is about to stop
    being harmless, because gating the short PowerShell aliases is the first
    feature that depends on this being right.

    THE RESIDUAL, stated rather than hidden: if Codex on Windows ever shells
    out to bash or WSL directly, the outer guess is wrong. Two things bound
    that. A NAMED nested shell corrects itself - `bash -c "..."`,
    `cmd /c "..."`, `powershell -Command "..."` and `pwsh -c "..."` are all
    unwrapped and re-dialected by recovery.effective_segments regardless of
    what the outer call was told. And the cost of being wrong is small today:
    of eleven dialect-taking functions, the only behavioural difference
    measured is whether a backtick escapes the next character when splitting
    segments (2026-09-14).
    """
    return POWERSHELL if os.name == "nt" else POSIX


def run_pretooluse(stdin, stdout) -> int:
    # Fail-open on our own parsing errors, but LOUD on stderr so the user can
    # see the tool stepped aside rather than silently allowing.
    raw = ""
    try:
        raw = stdin.read()
        # STRIP FIRST, THEN ASK IF IT IS EMPTY. U+FEFF is not whitespace to
        # str.strip(), so a payload of nothing but a BOM read as "there is
        # content here" and then parsed to nothing - an empty-input case
        # reported as a parse failure, which fails open with a scary message.
        body = _strip_bom(raw)
        data = json.loads(body) if body.strip() else {}
    except Exception as exc:
        # DEBUG FIRST, BECAUSE THIS IS THE BRANCH THAT NEEDS IT. The debug
        # print used to sit below, after the except - so it fired only when
        # parsing had ALREADY SUCCEEDED and printed nothing at all for the one
        # failure it exists to diagnose. Setting the flag on a real failure
        # produced no extra output (Windows, 2026-09-13), and the payload had
        # to be captured by piping into a separate python before anyone could
        # see what the hook had been handed.
        if os.environ.get("DEMO_CLI_HOOK_DEBUG"):
            _stderr(f"demo_cli [codex] unparseable payload: {raw[:400]!r}")
        _stderr(f"demo_cli: could not parse Codex hook input, stepping aside ({exc})")
        return 0

    if os.environ.get("DEMO_CLI_HOOK_DEBUG"):
        _stderr(f"demo_cli [codex] raw payload: {raw}")

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.environ.get("CODEX_PROJECT_DIR") or os.getcwd()

    if tool_name not in _SHELL_TOOLS and tool_name != _PATCH_TOOL:
        # mcp__* and anything else: out of beta scope, matching the Claude Code
        # adapter. No output means Codex proceeds normally.
        return 0

    # Both tools carry their payload in tool_input.command: a shell command for
    # Bash, the patch text for apply_patch. Same field, different grammar - so
    # the routing below must happen BEFORE the shell classifier ever sees it.
    command = _command_text(tool_input)
    if not command:
        return 0

    try:
        cfg = load_config(start=cwd)
        guard = Guard(config=cfg)
        with agent_directory(cwd):
            if tool_name == _PATCH_TOOL:
                return _handle_apply_patch(guard, command, stdout,
                                           data.get("session_id", "unknown"))
            result = guard.evaluate(
                command,
                intent=Intent(),              # Codex sends no per-call description
                agent_id="codex",
                session_id=data.get("session_id", "unknown"),
                dialect=_dialect(),
            )
    except AgentDirectoryUnreachable as exc:
        # WE CANNOT STAND WHERE THE AGENT STANDS, so we cannot resolve what it
        # is about to touch. Escalating costs almost nothing - this happens
        # only when the directory is gone or unreadable - and proceeding would
        # mean guessing a base we already know is wrong.
        _emit(stdout, "deny",
              f"the working directory the agent reported ({exc}) cannot be "
              f"entered, so a relative path in this command cannot be "
              f"resolved and nothing can be captured for it")
        return 0
    except Exception as exc:  # our bug must not brick the user's agent
        _stderr(f"demo_cli: internal error, stepping aside ({exc})")
        return 0

    # shadow mode: observe only. Emitting nothing is the safest "proceed" - it
    # cannot be parsed, rejected, or counted as a failed hook.
    if guard.mode != "enforce":
        if result.decision.is_blocking or result.decision.is_ask:
            _stderr(f"demo_cli [shadow] {result.decision.decision}: {result.decision.reason}")
        elif result.recovery_entry:
            rid = result.recovery_entry.get("id", "")
            _stderr(f"demo_cli [shadow] snapshot {rid} captured; undo with `demo_cli undo {rid}`")
        return 0

    permission, additional = _decide_permission(result.decision.decision, result.mismatches)
    reason = result.decision.reason

    if result.recovery_entry:
        rid = result.recovery_entry.get("id", "")
        _stderr("")
        _stderr(f"demo_cli ✅ recovery point {rid} captured before this ran.")
        _stderr(f"         mistake? undo it with:  demo_cli undo {rid}")
        _stderr("")
    elif permission == "deny":
        _stderr("")
        _stderr(f"demo_cli ⛔ blocked: {result.decision.reason}")
        _stderr("         nothing was captured, and nothing is claimed to be.")
        _stderr("")

    # SPEAK ONLY TO DENY. Codex rejects permissionDecision:"allow" at runtime
    # ("PreToolUse hook returned unsupported permissionDecision:allow") even
    # though its own schema lists allow/deny/ask as valid - the enum is what the
    # parser accepts, not what the runtime acts on. Emitting it marks the hook
    # FAILED on every safe command: the user sees a red error per tool call, and
    # a permanently failing guard is a guard that gets uninstalled. Silence is
    # the documented "proceed", and silence cannot be rejected.
    if permission == "deny":
        _emit(stdout, "deny", reason)
    elif additional:
        # No way to say "proceed, but be careful" - allow is refused, and a
        # reason without a decision is an error too. Surface it on stderr and
        # keep the honest record in the receipt.
        _stderr(f"demo_cli ⚠ {additional}")
    return 0


# --------------------------------------------------------------------------
# Installation helpers
# --------------------------------------------------------------------------

def settings_snippet() -> Dict:
    """The `.codex/hooks.json` fragment demo_cli installs.

    Codex's shape is NESTED: each PreToolUse entry is a group with an optional
    `matcher` (a regex over tool_name) and a list of handlers, each internally
    tagged with `type`. The flat `[{"command": ...}]` form this originally wrote
    is accepted by the file parser and then SILENTLY IGNORED - no error, no
    warning, no hook, no protection. It was only caught by running Codex for
    real and finding zero captured payloads.

    `matcher` is deliberately omitted so every tool is seen: restricting to
    "Bash" would skip apply_patch, which is most of what Codex actually does.
    """
    return {"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command",
                    "command": HOOK_COMMAND,
                    "statusMessage": "demo_cli safety check",
                    # 30 was a guess. Capture costs ~1 ms per file on Windows
                    # NTFS with Defender live (measured 2026-09-16), so 30s
                    # bought only ~30,000 files - an ordinary .venv or dist.
                    # Overrunning is not a slow snapshot but a SILENT one: the
                    # hook is killed, the host runs the command unguarded and
                    # says nothing. Buying room is cheap; the cap below is what
                    # actually bounds it.
                    "timeout": 120}]}
    ]}}


def _declares_our_hook(group) -> bool:
    """True if a PreToolUse group already contains our handler. Reads INSIDE the
    nested handler list - checking only the top level would miss it and append a
    duplicate on every install."""
    if not isinstance(group, dict):
        return False
    return any(isinstance(h, dict) and h.get("command") == HOOK_COMMAND
               for h in group.get("hooks", []) or [])


def install_into_hooks_json(path: str) -> None:
    """Merge the PreToolUse hook into an existing `.codex/hooks.json`,
    preserving any other events the user already declared. Idempotent."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    settings: Dict = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                settings = json.load(f)
        except Exception:
            settings = {}
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])

    if not any(_declares_our_hook(g) for g in pre):
        pre.append(settings_snippet()["hooks"]["PreToolUse"][0])

    with open(path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
