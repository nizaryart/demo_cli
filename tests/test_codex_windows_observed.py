r"""The Codex-on-Windows session of 2026-09-13, pinned.

Codex CLI 0.154.0 on Windows 10 was gated end to end - Bash and apply_patch
both, snapshots taken, undo restoring byte-for-byte, and `git push --force`
blocked in enforce mode. Those receipts are the ONLY empirical evidence that
that host is protected, and they were expensive: a metered Codex account with
a monthly limit, on a machine this suite does not run on.

WHY THIS FILE EXISTS. Three layers ignore the dialect today - hooks/codex.py
never passes one, _classify_segment never receives one, and
_ps_remove_item_operand takes none - so those results were produced by a
classifier that had been told POSIX while PowerShell was running. Fixing the
first of those (making Codex report POWERSHELL on Windows) is the next
change, and it is exactly the kind of change that could silently un-gate the
host it is meant to describe correctly.

So: the observed commands, verbatim from the transcript, asserted end to end
through the real Guard. They run on Linux and cost no Codex quota. If a
dialect change breaks one of these, it has broken Windows.

Verbatim means verbatim, backslashes included. The paths are rewritten to the
sandbox because the originals were on the Desktop of another machine; the
COMMAND SHAPES - -LiteralPath, the pipeline into Select-Object, the relative
.\ prefix - are the part under test and are untouched.
"""
import glob
import io
import json
import os

import pytest

from demo_cli.hooks.codex import run_pretooluse


def _run(payload, tmp_path, mode="enforce"):
    (tmp_path / ".demo_cli.toml").write_text(f'mode = "{mode}"\n')
    out = io.StringIO()
    rc = run_pretooluse(io.StringIO(json.dumps(payload)), out)
    return rc, out.getvalue()


def _shell(command, tmp_path):
    """The payload shape Codex actually sends - tool_name "Bash" EVEN ON
    WINDOWS, where the command it carries is PowerShell. _SHELL_TOOLS is
    {"Bash"} and the hook acted on every one of these, so the tool name
    cannot be the signal for which dialect wrote the text."""
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": str(tmp_path),
            "session_id": "01a09aa1-b9cf-7d81-ab29-7b74dc0bfda4"}


def _receipts(tmp_path):
    p = tmp_path / ".demo_cli" / "receipts.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def _snapshots(tmp_path):
    return sorted(glob.glob(str(tmp_path / ".demo_cli" / "recovery" / "*.bak")) +
                  glob.glob(str(tmp_path / ".demo_cli" / "recovery" / "*.snapdir")))


def _lab(tmp_path):
    """The lab as it stood: one file with known content."""
    (tmp_path / "important.txt").write_text("keep me\n")
    return tmp_path / "important.txt"


# ------------------------------------------------------- what was observed

def test_echo_hello_was_allowed(tmp_path):
    """receipt 44dade03 - ALLOW. The first proof that Codex hooks fire on
    Windows at all: not a snapshot, just a receipt existing."""
    rc, raw = _run(_shell("echo hello", tmp_path), tmp_path)
    assert rc == 0
    assert raw == ""                      # silence is Codex's "proceed"
    assert _receipts(tmp_path)[-1]["decision"] == "ALLOW"


def test_the_get_item_pipeline_was_allowed(tmp_path):
    """receipt 0aa0f365 - ALLOW. A three-stage PowerShell pipeline reading a
    file. Reads must not be flagged, however PowerShell-shaped they look."""
    _lab(tmp_path)
    cmd = (r"Get-Item -LiteralPath .\important.txt | "
           r"Select-Object FullName,Length,LastWriteTime | Format-List")
    rc, raw = _run(_shell(cmd, tmp_path), tmp_path)
    assert rc == 0
    assert raw == ""
    assert _receipts(tmp_path)[-1]["decision"] == "ALLOW"
    assert _snapshots(tmp_path) == [], "a read must not cost a snapshot"


def test_the_remove_item_shape_is_classified_the_same_on_both_platforms():
    r"""receipt 29c54b8c - REVERSIBLE on Windows, recovery point 0743f13a.

    THIS IS THE ONE THAT MATTERS, and it is asserted at the CLASSIFIER, not
    end to end. `.\important.txt` is a real relative path on Windows and does
    not exist on Linux, so the same command snapshots there and escalates
    here - both correct, and it means the verbatim command cannot be replayed
    across platforms. Discovered while writing this file (2026-09-14).

    What a dialect change would alter is the CLASSIFICATION, and that is
    platform-independent: the rule that fires, and whether recovery is
    demanded. Those are pinned here for the exact text Codex sent. The
    snapshot half is exercised by the test below, with a path that resolves
    wherever the suite happens to be running.

    It is a PowerShell cmdlet, with a PowerShell-only flag, matched by a
    classifier that had been told POSIX - because the rule table matches the
    cmdlet name regardless of dialect. That is the blindness the next change
    removes, so this must keep saying ps_remove_item afterwards.
    """
    from demo_cli.classify import classify_pipeline, POSIX, POWERSHELL
    cmd = r"Remove-Item -LiteralPath .\important.txt"
    for dialect in (POSIX, POWERSHELL):
        c = classify_pipeline(cmd, dialect=dialect)
        assert c.matched_rule == "ps_remove_item", (dialect, c.matched_rule)
        assert c.is_destructive, dialect


def test_remove_item_is_snapshotted_before_it_deletes(tmp_path):
    """The end-to-end half, with a path that resolves on this platform.

    `demo_cli undo` brought "keep me" back on the real machine; here the
    proof is that a recovery point exists BEFORE the delete is allowed
    through, which is the same claim one layer down.
    """
    target = _lab(tmp_path)
    rc, raw = _run(_shell(f"Remove-Item -LiteralPath {target}", tmp_path), tmp_path)
    assert rc == 0
    assert raw == "", "this was allowed through after snapshotting, not blocked"
    assert _receipts(tmp_path)[-1]["decision"] == "REVERSIBLE"
    snaps = _snapshots(tmp_path)
    assert snaps, "no recovery point: the file would have been unrecoverable"
    assert any(target.name in s for s in snaps), snaps


@pytest.mark.skipif(os.name != "nt", reason=r".\file resolves only on Windows")
def test_the_verbatim_windows_command_still_snapshots_on_windows(tmp_path):
    """The transcript replayed exactly, where it can be: on Windows. This is
    the only test in the file that asserts the observed command AND the
    observed outcome together."""
    target = _lab(tmp_path)
    rc, raw = _run(_shell(r"Remove-Item -LiteralPath .\important.txt", tmp_path),
                   tmp_path)
    assert rc == 0
    assert raw == ""
    assert _receipts(tmp_path)[-1]["decision"] == "REVERSIBLE"
    assert any(target.name in s for s in _snapshots(tmp_path))


def test_apply_patch_was_snapshotted(tmp_path):
    """receipt 4d9d6e7c - REVERSIBLE, recovery point f4735a6b, 9 bytes.

    The result I expected to fail. Codex writes most files this way - file
    edits were 3 of 7 tool calls in the first live session - so Bash gated
    and apply_patch not would be the half-working case, where doctor reports
    ACTIVE while most of what the agent does goes unguarded."""
    target = _lab(tmp_path)
    patch = ("*** Begin Patch\n"
             f"*** Update File: {target}\n"
             "@@\n"
             "-keep me\n"
             "+wiped\n"
             "*** End Patch\n")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
               "tool_input": {"command": patch}, "cwd": str(tmp_path),
               "session_id": "s1"}
    rc, raw = _run(payload, tmp_path)
    assert rc == 0
    assert _receipts(tmp_path)[-1]["decision"] == "REVERSIBLE"
    snaps = _snapshots(tmp_path)
    assert snaps, "the original content was not captured before the edit"
    assert any(target.name in s for s in snaps), snaps


def test_git_push_force_was_blocked_in_enforce(tmp_path):
    """receipt ea50a828 - ESCALATE, no recovery point. Codex refused and
    relayed our reason in its own words:

        Blocked by hook
          [demo_cli] Mutation of a non-recoverable surface (remote_vcs_history)

    deny is the only decision Codex's runtime acts on - it rejects allow and
    ask outright - so the reason string is the entire channel to the user."""
    rc, raw = _run(_shell("git push --force", tmp_path), tmp_path)
    assert rc == 0
    assert raw, "enforce mode must emit a decision for an unrecoverable action"
    out = json.loads(raw)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "remote_vcs_history" in out["permissionDecisionReason"]
    last = _receipts(tmp_path)[-1]
    assert last["decision"] == "ESCALATE"
    assert last["recovery_point"] is None, "nothing may claim a recovery here"


def test_the_same_push_only_observes_in_shadow(tmp_path):
    """The lab ran in shadow until the last test, which is why nothing was
    blocked before then. Shadow observes and never blocks - so a silent
    result there is correct, not a failure."""
    rc, raw = _run(_shell("git push --force", tmp_path), tmp_path, mode="shadow")
    assert rc == 0
    assert raw == ""
    assert _receipts(tmp_path)[-1]["decision"] == "ESCALATE"


# --------------------------------------------- and the assumption underneath

def test_a_windows_command_arrives_under_the_bash_tool_name():
    """Pinned because the next change depends on it. hooks/codex.py acts only
    on _SHELL_TOOLS, and every receipt above came from a payload whose
    tool_name was "Bash" while PowerShell was running. If that set ever grows
    a "PowerShell" entry, the dialect decision below it has to be revisited."""
    from demo_cli.hooks.codex import _SHELL_TOOLS
    assert _SHELL_TOOLS == {"Bash"}


# --------------------------------------------------------------------------
# The dialect the adapter reports
#
# It used to report none, so every PowerShell command Codex ran on Windows
# was classified as POSIX. Harmless until now - three layers ignore the
# dialect - and about to stop being harmless, because gating the short
# PowerShell aliases is the first feature that depends on it.

def test_the_adapter_reports_a_dialect_at_all(monkeypatch):
    """The bug this closes: guard.evaluate was called with no dialect= and
    took the POSIX default, on every platform."""
    import inspect
    from demo_cli.hooks import codex as C
    src = inspect.getsource(C.run_pretooluse)
    assert "dialect=" in src, "the adapter is back to taking the POSIX default"


def test_windows_is_powershell_and_everything_else_is_posix(monkeypatch):
    from demo_cli.hooks import codex as C
    from demo_cli.classify import POSIX, POWERSHELL
    monkeypatch.setattr(C.os, "name", "nt")
    assert C._dialect() == POWERSHELL
    monkeypatch.setattr(C.os, "name", "posix")
    assert C._dialect() == POSIX


def test_the_tool_name_is_not_used_to_decide(monkeypatch):
    """Codex sends "Bash" while running PowerShell, so keying on it would
    reintroduce the bug in a form that LOOKS principled. The Claude Code
    adapter can key on tool_name because Claude Code sends two different
    names; this one must not copy it."""
    import inspect
    from demo_cli.hooks import codex as C
    src = inspect.getsource(C._dialect)
    assert "tool_name" not in src.split('"""')[-1], \
        "the dialect is being decided from a name that is always the same"


def test_claude_code_still_decides_from_the_tool_name():
    """The other adapter deliberately does the opposite, and its reason is
    sound: Claude Code DOES distinguish the two shells, and a Windows box can
    run either. Pinned so a later tidy-up does not make them agree by
    flattening the one that is right."""
    import inspect
    from demo_cli.hooks import claude_code as CC
    src = inspect.getsource(CC)
    assert 'tool_name == "PowerShell"' in src


def test_a_named_nested_shell_still_corrects_the_guess():
    """The escape valve that makes a platform guess acceptable. Whatever the
    outer call is told, a command that names its own shell is re-dialected."""
    from demo_cli import recovery
    from demo_cli.classify import POSIX, POWERSHELL
    cases = [(r'bash -c "rm -rf ./out"', POSIX),
             (r'cmd /c "del x.txt"', POSIX),
             (r'powershell -Command "Remove-Item x"', POWERSHELL),
             (r'pwsh -c "Remove-Item x"', POWERSHELL)]
    for cmd, expected in cases:
        for told in (POSIX, POWERSHELL):
            segs = recovery.effective_segments(cmd, told)
            assert segs[0][1] == expected, (cmd, told, segs)


def test_the_observed_windows_commands_classify_the_same_under_powershell():
    """The point of the regression net: telling the classifier the truth must
    not change any verdict it already reached. Every shell command from the
    2026-09-13 transcript, both dialects, same rule."""
    from demo_cli.classify import classify_pipeline, POSIX, POWERSHELL
    observed = [
        "echo hello",
        r"Get-Item -LiteralPath .\important.txt | Select-Object FullName | Format-List",
        r"Remove-Item -LiteralPath .\important.txt",
        "git push --force",
    ]
    for cmd in observed:
        a = classify_pipeline(cmd, dialect=POSIX)
        b = classify_pipeline(cmd, dialect=POWERSHELL)
        assert a.matched_rule == b.matched_rule, (cmd, a.matched_rule, b.matched_rule)
        assert a.is_destructive == b.is_destructive, cmd
