"""Terminal rendering. Presentation only; all logic lives elsewhere.

Honours NO_COLOR and non-tty output. Colours follow the product's disposition
palette (green allow, amber recoverable, red escalate, cyan diff).
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from .context import redact
from .decide import (ALLOW, CONTEXT_MISMATCH, DRY_RUN, ESCALATE, REVERSIBLE,
                     SAFE, REVIEW, BLOCKED, posture)
from .diff import DiffLine
from .guard import GuardResult
from .receipts import VerifyResult

import urllib.parse as _urlparse

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "gray": "\033[90m",
}

_DECISION_COLOR = {
    ALLOW: "green", DRY_RUN: "yellow", REVERSIBLE: "yellow",
    CONTEXT_MISMATCH: "red", ESCALATE: "red",
    "RESTORED": "green", "VERIFIED": "green", "TAMPERED": "red", "DIFF": "cyan",
    # Amber, not red: the log is not linear, but nothing was removed or
    # edited. Colouring it like tampering would say with the palette what the
    # wording is careful not to say.
    "DAMAGED": "yellow", "OUT OF ORDER": "yellow",
    # Dim, not green: an empty ledger is not a passed integrity check, and
    # colouring it like one would tell the reader they are covered.
    "NO RECEIPTS": "dim",
}
_TONE_COLOR = {"add": "green", "del": "red", "mod": "yellow", "meta": "cyan", "info": "dim"}

# Three-tier posture -> (glyph, colour). The glyph + colour carry the stance at
# a glance; the precise disposition rides along as a subtitle.
_POSTURE_META = {
    SAFE: ("[+] SAFE", "green"),
    REVIEW: ("[!] REVIEW", "yellow"),
    BLOCKED: ("[x] BLOCKED", "red"),
}


def posture_meta(disposition: str):
    return _POSTURE_META.get(posture(disposition), ("[?] REVIEW", "yellow"))


def set_color(enabled: bool) -> None:
    global _USE_COLOR
    _USE_COLOR = enabled


def c(text, name) -> str:
    if not _USE_COLOR:
        return str(text)
    return f"{_C.get(name, '')}{text}{_C['reset']}"


def kv(label, value) -> str:
    return f"  {c(str(label).ljust(20), 'dim')}{value}"


def _label(decision: str) -> str:
    return c(decision, _DECISION_COLOR.get(decision, "gray"))


def _print(lines: List[str]) -> None:
    print("\n".join(lines))


_ISSUE_BASE = "https://github.com/WePwn/demo_cli/issues/new"

# Only prompt on decisions a user might consider *wrong* — a hard stop, a
# context mismatch, or a snapshot that fired. Plain ALLOWs stay silent so the
# prompt never becomes background noise.
_FEEDBACK_ON = {ESCALATE, CONTEXT_MISMATCH, REVERSIBLE, DRY_RUN}


def feedback_url_for(r: "GuardResult") -> str:
    """The prefilled GitHub-issue URL for a wrong-call report, or '' if the
    decision isn't one worth asking about. Shared by the interactive `check`
    path and the hook stderr path so the feedback channel lives where users
    actually are (the hook), not only where they rarely are (manual `check`).
    """
    d = r.decision
    if d.decision not in _FEEDBACK_ON:
        return ""
    title = f"Wrong call: {d.decision} on `{(r.command or '')[:60]}`"
    body = (
        "**What demo_cli decided**\n"
        f"- decision: {d.decision}\n"
        f"- reason: {d.reason}\n"
        f"- matched rule: {r.classification.matched_rule or '-'}\n"
        f"- command: `{(r.command or '')[:200]}`\n\n"
        "**What I expected instead**\n"
        "<!-- e.g. this should have been allowed / should have snapshotted / "
        "should have blocked -->\n\n"
        "**My .demo_cli.toml** (redact credentials)\n"
        "```toml\n\n```\n"
    )
    return f"{_ISSUE_BASE}?" + _urlparse.urlencode({"title": title, "body": body})


def feedback_line(r: "GuardResult") -> str:
    """One consent-based line inviting a wrong-call report (interactive path)."""
    url = feedback_url_for(r)
    if not url:
        return ""
    return c("  Wrong call? ", "dim") + c("→ report it (prefilled): ", "dim") + url


def render_result(r: GuardResult, version: str) -> None:
    d = r.decision
    glyph, pcolor = posture_meta(d.decision)
    head = (c(f"demo_cli {version}", "dim") + "  " + c(glyph, pcolor)
            + c(f"  ·  {d.decision}", "dim"))
    lines: List[str] = ["", head, ""]

    lines.append(c("Action", "cyan"))
    lines.append(kv("command", r.command[:110]))
    lines.append(kv("type", r.classification.action_type
                    + (" · pipeline" if r.classification.is_pipeline else "")
                    + (" · remote-exec" if r.classification.remote_exec else "")))
    if r.classification.matched_rule:
        lines.append(kv("matched rule", r.classification.matched_rule))
    if r.classification.nonrecoverable_surface:
        lines.append(kv("surface", r.classification.nonrecoverable_surface))
    if r.classification.is_pipeline:
        for seg in r.classification.segments:
            lines.append("    " + c("» " + seg[:96], "gray"))

    lines += ["", c("Context", "cyan")]
    ctx = r.context
    env_line = ctx.environment if ctx.environment_source == "unknown" \
        else f"{ctx.environment}  ({ctx.environment_source})"
    lines.append(kv("environment", env_line))
    lines.append(kv("target", ctx.target_label))
    branch = ctx.branch
    if branch in ("unknown", "HEAD", ""):
        branch = "- (no git branch)"
    lines.append(kv("git branch", branch))
    lines.append(kv("fingerprint", ctx.fingerprint))

    if r.mismatches:
        lines += ["", c("Context mismatch", "red")]
        for name, wanted, actual in r.mismatches:
            lines.append(kv(name, f"intended {wanted}, actual {actual}"))

    if r.preview_count is not None:
        lines += ["", c("Preview (dry run)", "yellow"),
                  kv("rows affected", r.preview_count)]
        if r.preview_cols:
            lines.append("    " + c(" | ".join(str(x) for x in r.preview_cols), "dim"))
        for row in r.preview_rows[:5]:
            lines.append("    " + " | ".join(str(x) for x in row))

    if r.affected_paths:
        n = len(r.affected_paths)
        lines += ["", c("Affected files (preview)", "yellow"),
                  kv("files matched", n)]
        for p in r.affected_paths[:10]:
            lines.append("    " + c("• " + redact(p), "dim"))
        if n > 10:
            lines.append("    " + c(f"... and {n - 10} more", "dim"))

    if r.recovery_entry:
        lines += ["", c("Recovery", "green"),
                  kv("snapshot", os.path.basename(r.recovery_entry["recovery_point"])),
                  kv("undo", "demo_cli undo"),
                  kv("diff", "demo_cli diff")]

    lines += ["", c("Decision", _DECISION_COLOR.get(d.decision, "gray")),
              "  " + c(d.reason, _DECISION_COLOR.get(d.decision, "gray"))]
    if d.next_steps:
        lines += ["", c("Safe next step", "yellow")]
        for i, step in enumerate(d.next_steps, 1):
            lines.append(f"  {i}. {step}")

    fb = feedback_line(r)
    if fb:
        lines += ["", fb]
    lines.append("")
    lines.append(c(f"  mode: {r.mode}"
                   + ("" if r.mode == "enforce" else "  (observe-only; nothing was blocked)"), "dim"))
    lines.append("")
    _print(lines)


def _verify_block(name: str, v: VerifyResult) -> List[str]:
    """One chain's result. Three outcomes, and the middle one is the point.

    VERIFIED  hashes and links hold.
    DAMAGED   a line will not parse. That is a WRITE that did not finish, not
              an edit - so every readable entry is still verified and said to
              be. Calling this "the log was altered", as this used to, is the
              verifier asserting something it cannot know.
    TAMPERED  a line parses but its hash or link is wrong. Content changed.
    """
    if v.absent:
        return ["  " + c(f"{name:<12} no receipts recorded yet", "dim")]
    if v.reordered and not v.broken_at:
        # NOT "TAMPERED". Every referenced receipt is present; only the order
        # is wrong. Saying an entry was removed when it is demonstrably still
        # in the file is the verifier asserting something false.
        out = ["  " + c(f"{name:<12} {v.entries} entries, "
                        f"{len(v.out_of_order)} OUT OF ORDER", "yellow")]
        lines_ = ", ".join(str(n) for n in v.out_of_order[:5])
        more = "" if len(v.out_of_order) <= 5 else f" (+{len(v.out_of_order) - 5} more)"
        out.append(f"             at line {lines_}{more}")
        if v.damaged:
            out.append(f"             {len(v.damaged_lines)} malformed line(s) as well")
        out.append("             " + c("nothing was removed - every referenced "
                                       "receipt is still in the log", "dim"))
        return out
    if not v.ok:
        out = ["  " + c(f"{name:<12} TAMPERED", "red")]
        if v.broken_at:
            out.append(f"             broken at line {v.broken_at}")
        out.append("             " + c(v.detail or "verification failed.", "red"))
        return out
    if v.damaged:
        where = ", ".join(str(n) for n in v.damaged_lines[:5])
        more = "" if len(v.damaged_lines) <= 5 else f" (+{len(v.damaged_lines) - 5} more)"
        return [
            "  " + c(f"{name:<12} {v.entries} entries verified, "
                     f"{len(v.damaged_lines)} unreadable", "yellow"),
            f"             {v.segments} intact segment{'s' if v.segments != 1 else ''}; "
            f"malformed at line {where}{more}",
            "             " + c("a torn write, not an alteration - nothing was "
                                 "edited", "dim"),
        ]
    return ["  " + c(f"{name:<12} {v.entries} entries    INTACT", "green")]


def render_verify(v: VerifyResult, version: str, fs: Optional[VerifyResult] = None,
                  heads: Optional[dict] = None, links=None) -> None:
    """Report every chain. `fs` is the filesystem guard's own log; it is absent
    on a project that has never been mounted, and that is not a failure."""
    ok = v.ok and (fs.ok if fs else True) and (links.ok if links else True)
    damaged = v.damaged or (fs.damaged if fs else False)
    reordered = v.reordered or (fs.reordered if fs else False)
    if v.absent and (fs is None or fs.absent):
        label = "NO RECEIPTS"
    elif ok:
        label = "DAMAGED" if damaged else "VERIFIED"
    else:
        label = "OUT OF ORDER" if reordered and not v.broken_at else "TAMPERED"
    lines = ["", c(f"demo_cli {version}", "dim") + "  " + _label(label), ""]
    # WHICH LEDGER. `verify` run from the wrong directory silently checks a
    # different project's log: on 2026-09-02 running it from Desktop reported
    # VERIFIED over 7 unrelated entries while labubu's own chain was broken.
    # A clean pass for a project you did not ask about is worse than an error.
    if v.ledger:
        lines += [kv("ledger", v.ledger), ""]
    lines.append(c("Receipt chains", "cyan"))
    lines += _verify_block("main", v)
    if fs is not None:
        lines += _verify_block("fs", fs)
    if links is not None and links.checked:
        if links.ok:
            lines.append("  " + c(f"{'cross-links':<12} {links.verified} verified"
                                  f"    all resolve", "green"))
        else:
            lines.append("  " + c(f"{'cross-links':<12} "
                                  f"{len(links.unresolved)} UNRESOLVED", "red"))
            lines.append("             " + c(
                "a receipt references a hash absent from the other chain - "
                "entries were removed", "red"))
    if v.absent and (fs is None or fs.absent):
        # SAY WHAT THIS IS NOT. "verify" exiting 0 on an empty ledger could be
        # read as "the guard is working" - it means only that nothing has been
        # recorded. doctor is the command that answers the other question.
        lines += ["", "  " + c("Nothing has been recorded here yet. This is not "
                               "a passed integrity check,", "dim"),
                  "  " + c("and not evidence that anything is being guarded - "
                           "run `demo_cli doctor` for that.", "dim")]
    if v.ok and not v.absent:
        summary = ", ".join(f"{k}:{n}" for k, n in sorted(v.decisions.items())) or "none"
        lines += ["", c("Decisions", "cyan"), kv("main", summary)]
    if heads:
        # PRINTED SO THEY CAN BE ANCHORED SOMEWHERE WE DO NOT CONTROL.
        # A hash chain proves nothing against someone who can rewrite the whole
        # file; the standard answer is to publish the head where they cannot
        # reach it. Automating that is out of scope, but showing the value
        # makes the manual version - paste it into a commit message or a CI
        # log - available today.
        lines += ["", c("Chain heads", "cyan")]
        for name, head in heads.items():
            lines.append(kv(name, head[:32] + "..." if len(head) > 32 else head))
        lines.append("  " + c("record these outside this machine (a commit "
                              "message, a CI log) to detect a full rewrite", "dim"))
    lines.append("")
    _print(lines)


def render_diff(entry: dict, lines: List[DiffLine], version: str) -> None:
    out = ["", c(f"demo_cli {version}", "dim") + "  " + _label("DIFF"), "",
           c("Diff", "cyan"),
           kv("kind", entry.get("kind", "sqlite")),
           kv("target", redact(entry.get("target", "unknown"))),
           kv("baseline", os.path.basename(entry.get("recovery_point", "unknown"))),
           "", c("What changed", "cyan")]
    for ln in lines:
        out.append("  " + c(ln.text, _TONE_COLOR.get(ln.tone, "info")))
    out.append("")
    _print(out)


def render_restore(entry, ok: bool, version: str,
                   recovery_dir: Optional[str] = None,
                   requested_id: Optional[str] = None,
                   denied: bool = False,
                   problem: Optional[str] = None) -> None:
    """`recovery_dir` and `requested_id` exist so a failure can say WHERE it
    looked.

    "No recovery points found" cost twenty minutes on 2026-08-25. Three
    recovery points existed, complete and correct - in a different ledger,
    because the filesystem guard had been started from a different directory
    and its project root resolved elsewhere. The message named neither the id
    nor the directory searched, so there was nothing to notice. Naming the
    path would have ended it immediately.
    """
    if ok and entry:
        _print(["", c(f"demo_cli {version}", "dim") + "  " + _label("RESTORED"), "",
                c("Recovery", "green"),
                kv("kind", entry.get("kind", "sqlite")),
                kv("target", redact(entry["target"])),
                kv("from", os.path.basename(entry["recovery_point"])),
                "  " + c("Restored from the latest recovery point.", "green"), ""])
        return

    lines = ["", c(f"demo_cli {version}", "dim") + "  " + _label("ESCALATE"), ""]
    if entry and denied:
        # NOT "unrecoverable". The bytes are there and an elevated shell can
        # reach them - saying otherwise is a false negative from the one
        # command a person runs after already losing something (2026-08-29).
        lines += ["  " + c("This recovery point needs Administrator.", "yellow"),
                  kv("target", redact(entry.get("target", "?"))),
                  kv("recovery point", redact(entry.get("recovery_point", "?")))]
        if problem:
            lines += [kv("refused", problem)]
        lines += ["  " + c("The filesystem guard writes its recovery points into "
                           "the protected backing, which is locked to "
                           "Administrators so the agent cannot tamper with them. "
                           "Your file is intact.", "dim")]
    elif entry:
        # The entry was found; the copy is what failed.
        lines += ["  " + c("No recovery point could be restored.", "red"),
                  kv("target", redact(entry.get("target", "?")))]
        lines += ["  " + c(problem or "The recovery point is present but could "
                           "not be written back.", "dim")]
    else:
        what = f"No recovery point matched {requested_id!r}." if requested_id \
            else "No recovery points found."
        lines += ["  " + c(what, "red")]
        if recovery_dir:
            lines += [kv("searched", recovery_dir),
                      "  " + c("A guard started from a different directory writes "
                               "to a different ledger. `demo_cli log` lists this "
                               "one.", "dim")]
    _print(lines + [""])


def _size(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == "GB":
            return f"{int(f)}{u}" if u == "B" else f"{f:.1f}{u}"
        f /= 1024
    return f"{int(n)}B"


def quiet_line(r: GuardResult) -> str:
    """One-line summary for CI / hook-style consumers."""
    glyph, pcolor = posture_meta(r.decision.decision)
    rp = ""
    if r.recovery_entry:
        rp = f"  recovery={r.recovery_entry.get('id', '')}"
    return c(glyph, pcolor) + c(f" {r.decision.decision}", "dim") + f"  {r.decision.reason}{rp}"


def result_json(r: GuardResult, version: str) -> dict:
    """Machine-readable view of a check, for pipelines and other environments."""
    return {
        "version": version,
        "posture": posture(r.decision.decision),
        "disposition": r.decision.decision,
        "reason": r.decision.reason,
        "recoverable": r.decision.recoverable,
        "mode": r.mode,
        "allowed": r.allowed,
        "permission": r.permission,
        "command": r.command,
        "action_type": r.classification.action_type,
        "matched_rule": r.classification.matched_rule,
        "nonrecoverable_surface": r.classification.nonrecoverable_surface,
        "environment": r.context.environment,
        "environment_source": r.context.environment_source,
        "target": r.context.target_label,
        "recovery_point": (r.recovery_entry or {}).get("recovery_point"),
        "recovery_id": (r.recovery_entry or {}).get("id"),
        "preview_affected_rows": r.preview_count,
        "affected_paths": r.affected_paths,
        "context_mismatches": [list(m) for m in r.mismatches],
        "receipt_hash": r.receipt.receipt_hash if r.receipt else None,
        "next_steps": r.decision.next_steps,
    }


def render_log(entries, version: str) -> None:
    if not entries:
        print(c(f"\ndemo_cli {version}", "dim") + "  recovery log\n")
        print("  No recovery points yet. Run some mutating commands first.\n")
        return
    out = ["", c(f"demo_cli {version}", "dim") + "  recovery log", ""]
    out.append("  " + c(f"{'id':<10}{'when':<17}{'kind':<9}{'size':<8}action", "dim"))
    for e in reversed(entries):
        rid = str(e.get("id", "?"))[:8]
        ts = e.get("ts", "?")
        kind = e.get("kind", "?")
        size = _size(_entry_size_safe(e))
        action = redact(e.get("action") or e.get("target", ""))
        if len(action) > 46:
            action = action[:43] + "..."
        out.append(f"  {rid:<10}{ts:<17}{kind:<9}{size:<8}{action}")
    out += ["", c("  undo <id> to restore · diff <id> to inspect", "dim"), ""]
    _print(out)


def _entry_size_safe(e) -> int:
    from . import recovery
    try:
        return recovery.entry_size(e)
    except Exception:
        return 0


def render_doctor(checks, version: str) -> None:
    out = ["", c(f"demo_cli {version}", "dim") + "  doctor", ""]
    glyphs = {"ok": ("[+]", "green"), "warn": ("[!]", "yellow"), "fail": ("[x]", "red")}
    # Size the label column to the longest label actually present. A fixed 26
    # silently fused the columns for "hook self-test (PowerShell)", which is 27
    # characters - in the one report a user reads when something is wrong.
    width = max((len(label) for _, label, _ in checks), default=26) + 2
    for status, label, detail in checks:
        g, col = glyphs.get(status, ("[?]", "gray"))
        line = "  " + c(g, col) + " " + label.ljust(width) + c(detail, "dim")
        out.append(line)
    fails = sum(1 for s, _, _ in checks if s == "fail")
    warns = sum(1 for s, _, _ in checks if s == "warn")
    out.append("")
    summary = "all good" if (fails == 0 and warns == 0) else f"{fails} fail, {warns} warn"
    out.append("  " + c(summary, "green" if fails == 0 else "red"))
    out.append("")
    _print(out)


def render_status(info, version: str) -> None:
    out = ["", c(f"demo_cli {version}", "dim") + "  status", ""]
    out.append(kv("mode", info["mode"] + ("" if info["mode"] == "enforce"
                  else "  (observe-only)")))
    out.append(kv("hook installed", "yes" if info["hook"] else "no  (run: demo_cli install-hook)"))
    out.append(kv("config", info["config"] or "defaults (no .demo_cli.toml)"))
    out.append(kv("receipts", info["receipts"]))
    out.append(kv("chain", info["chain"]))
    out.append(kv("recovery points", info["recovery_points"]))
    out.append(kv("workspace", info["workspace"]))
    out.append("")
    _print(out)
