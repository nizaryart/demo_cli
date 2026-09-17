r"""The guard's exit path must not lie, and must not step aside.

Three defects of one shape, found by an independent trace of the PreToolUse
chain on 2026-09-16 and reproduced on 09-17 before any fix was written. Each
one is the LAST thing that happens to a decision that was already correct.

[A] A RECEIPT WRITE DISABLED THE GUARD. `Guard.evaluate` called
    append_receipt unwrapped. The adapters fail open on any exception, so a
    full disk or a locked ledger printed "internal error, stepping aside",
    emitted nothing, and the host ran the command UNGUARDED. The correct
    version was already in the same file 269 lines earlier, in
    _refuse_broken_config, under the comment "the receipt is evidence, not a
    precondition for refusing".

[B] A BLOCKED COMMAND WORE THE SUCCESS BANNER. The enforce arm tested
    `recovery_entry` before `is_blocking`, and `del /f app.db` is BOTH: the
    operand resolves so a snapshot is taken, and `recursive_force_delete` is
    a non-recoverable surface so decide() refuses anyway. The user was told
    "recovery point captured before this ran" about a command that never ran,
    and _loud_block's honest text was unreachable. The shadow arm twenty
    lines above already tested blocking first.

[E] THE SAME EXCEPTION, OPPOSITE POSTURES. AgentDirectoryUnreachable is
    imported by both adapters and was caught by one. Codex denied; Claude
    Code let it fall into the blanket handler and stepped aside. The existing
    coverage in test_hook_cwd.py exercised the host that was already right.

ASSERT ON THE BRANCH, NOT THE WORDING. [B]'s tests record which banner
function ran rather than grepping its text, except where the text itself is
the defect - the false "nothing was captured" claim.
"""
import io
import json
import os

import pytest

from demo_cli import guard as guard_mod
from demo_cli.config import Config
from demo_cli.guard import Guard
from demo_cli.hooks import claude_code as cc
from demo_cli.hooks import codex as cx


def _payload(**kw):
    base = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "session_id": "s", "tool_input": {}}
    base.update(kw)
    return io.StringIO(json.dumps(base))


def _emitted(out):
    raw = out.getvalue()
    return json.loads(raw)["hookSpecificOutput"] if raw.strip() else None


@pytest.fixture
def proj(tmp_path, monkeypatch):
    p = tmp_path / "P"
    p.mkdir()
    (p / ".demo_cli.toml").write_text('mode = "enforce"\n')
    (p / "app.db").write_text("payload")
    monkeypatch.chdir(p)
    return p


@pytest.fixture
def broken_ledger(monkeypatch):
    """Every receipt write raises, as a full disk or a locked file would."""
    def boom(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(guard_mod, "append_receipt", boom)


# --------------------------------------------------------------- [A]

def test_a_failed_receipt_write_still_denies(proj, broken_ledger):
    """THE DEFECT. Against HEAD this emitted nothing and the host ran it."""
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_input={"command": "del /f app.db"},
                               cwd=str(proj)), out)
    got = _emitted(out)
    assert got is not None, (
        "the hook emitted nothing - it stepped aside because the LEDGER "
        "failed, which runs the command unguarded")
    assert got["permissionDecision"] == "deny"


def test_a_failed_receipt_write_still_denies_a_file_edit(proj, broken_ledger,
                                                         monkeypatch):
    """The second door. Snapshot refused AND ledger broken must still deny."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", "0")
    (proj / "sub").mkdir()
    (proj / "sub" / "a.txt").write_text("x")
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_name="Write",
                               tool_input={"file_path": str(proj / "sub")},
                               cwd=str(proj)), out)
    got = _emitted(out)
    assert got is not None, "stepped aside on a broken ledger"
    assert got["permissionDecision"] == "deny"


def test_evaluate_returns_a_decision_when_the_ledger_fails(proj, broken_ledger):
    """The library half: the decision is reached, not raised past."""
    g = Guard(config=Config(mode="enforce", project_root=str(proj)))
    r = g.evaluate("del /f app.db")
    assert r.decision.decision == "ESCALATE"
    assert r.permission == "deny"


def test_a_failed_receipt_write_is_announced(proj, broken_ledger, capsys):
    """Silent degradation is the thing this project treats as the enemy: an
    audit trail with an unannounced hole is worse than a noisy one."""
    g = Guard(config=Config(mode="enforce", project_root=str(proj)))
    g.evaluate("del /f app.db")
    assert "receipt not written" in capsys.readouterr().err


# --------------------------------------------------------------- [B]

def _record_banners(monkeypatch):
    called = []
    monkeypatch.setattr(cc, "_loud_save", lambda r: called.append("save"))
    monkeypatch.setattr(cc, "_loud_block", lambda r: called.append("block"))
    return called


def test_a_captured_then_refused_command_gets_the_block_banner(proj, monkeypatch):
    """THE DEFECT. `del /f app.db` captures AND refuses; HEAD said "save"."""
    called = _record_banners(monkeypatch)
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_input={"command": "del /f app.db"},
                               cwd=str(proj)), out)
    assert _emitted(out)["permissionDecision"] == "deny"
    assert called == ["block"], (
        "a refused command wore the success banner; the user was told a "
        f"recovery point was captured before it ran, and it never ran: {called}")


def test_the_precondition_for_that_test_still_holds(proj):
    """The test above is only meaningful while this command BOTH captures and
    blocks. If a rule change breaks that pairing the test silently stops
    testing anything, so the pairing is pinned on its own."""
    g = Guard(config=Config(mode="enforce", project_root=str(proj)))
    r = g.evaluate("del /f app.db")
    assert r.decision.is_blocking, "no longer blocks - retarget the [B] test"
    assert r.recovery_entry is not None, "no longer captures - retarget it"


def test_an_ordinary_save_still_gets_the_save_banner(proj, monkeypatch):
    """The reorder must not swallow the banner it was built for."""
    called = _record_banners(monkeypatch)
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_input={"command": "rm app.db"},
                               cwd=str(proj)), out)
    assert _emitted(out)["permissionDecision"] == "allow"
    assert called == ["save"]


def test_the_block_banner_does_not_deny_a_capture_it_made(proj, capsys):
    """The one place the WORDING is the defect: the banner's fixed line said
    "nothing was captured" while a snapshot sat on disk."""
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_input={"command": "del /f app.db"},
                               cwd=str(proj)), out)
    err = capsys.readouterr().err
    assert "blocked" in err
    assert "nothing was captured" not in err, (
        "the block banner denied a recovery point that exists")
    assert "recovery point" in err, "the snapshot it did take went unmentioned"


def test_a_block_with_no_capture_still_says_so(proj, capsys):
    """And the honest line must survive for the case it was written for."""
    out = io.StringIO()
    cc.run_pretooluse(_payload(tool_input={"command": "mkfs.ext4 /dev/sdb1"},
                               cwd=str(proj)), out)
    assert "nothing was captured" in capsys.readouterr().err


# --------------------------------------------------------------- [E]

@pytest.mark.parametrize("hook", [cc.run_pretooluse, cx.run_pretooluse],
                         ids=["claude_code", "codex"])
def test_an_unreachable_agent_directory_denies_on_both_hosts(proj, hook):
    """THE DEFECT, for claude_code. The codex leg passed before the fix and is
    kept so the two hosts are asserted from one place."""
    out = io.StringIO()
    hook(_payload(tool_input={"command": "rm app.db"},
                  cwd=str(proj / "does-not-exist")), out)
    got = _emitted(out)
    assert got is not None, "an unresolvable base must not pass silently"
    assert got["permissionDecision"] == "deny"


@pytest.mark.parametrize("hook", [cc.run_pretooluse, cx.run_pretooluse],
                         ids=["claude_code", "codex"])
def test_shadow_mode_never_denies_an_unreachable_directory(tmp_path, monkeypatch,
                                                           hook, capsys):
    """Shadow observes and never blocks - that is the whole contract, and it
    is what makes the tool adoptable. Codex denied here regardless of mode,
    so fixing claude_code by copying it would have imported the bug."""
    p = tmp_path / "P"
    p.mkdir()
    (p / ".demo_cli.toml").write_text('mode = "shadow"\n')
    monkeypatch.chdir(p)
    out = io.StringIO()
    hook(_payload(tool_input={"command": "rm app.db"},
                  cwd=str(p / "does-not-exist")), out)
    assert _emitted(out) is None, "shadow mode blocked a command"
    assert "would deny" in capsys.readouterr().err, (
        "shadow must still say what enforce would have done")
