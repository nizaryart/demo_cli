"""Coverage for the 0.4.0b7 'felt value' batch: the loud save-moment on the
hook path, the shared feedback URL, and doctor's PATH + self-test checks.

These behaviors are what turn an invisible clone into an identified, retained
user, so a silent regression here is expensive. Pin them."""
import io
import json
import os
import tempfile

from demo_cli.hooks import claude_code
from demo_cli import render, cli


def _run_hook(command, mode="enforce", tool="Bash", cwd=None):
    """Drive the real PreToolUse entrypoint, capturing stdout+stderr."""
    import sys
    d = cwd or tempfile.mkdtemp()
    prev = os.getcwd()
    try:
        os.chdir(d)
        open(os.path.join(d, ".demo_cli.toml"), "w").write(
            f'mode = "{mode}"\n[workspace]\ndir = ".demo_cli"\n')
        payload = {"tool_name": tool, "tool_input": {"command": command},
                   "cwd": d}
        out, err = io.StringIO(), io.StringIO()
        real = sys.stderr
        sys.stderr = err
        try:
            claude_code.run_pretooluse(io.StringIO(json.dumps(payload)), out)
        finally:
            sys.stderr = real
        return out.getvalue(), err.getvalue()
    finally:
        os.chdir(prev)


def test_reversible_prints_felt_save_on_stderr():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.txt"), "w").write("x")
    _, err = _run_hook("rm -rf a.txt", cwd=d)
    # the three things a saved user must SEE
    assert "recovery point" in err
    assert "captured before this ran" in err
    assert "demo_cli undo" in err


def test_felt_save_carries_the_prefilled_report_link():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.txt"), "w").write("x")
    _, err = _run_hook("rm -rf a.txt", cwd=d)
    assert "report it (prefilled)" in err
    assert "github.com/nizaryart/DEMO_LOADING/issues/new" in err


def test_block_prints_honest_no_capture_line():
    # a recursive-force delete hard-stops in every env -> loud block, no claim
    _, err = _run_hook("Remove-Item -Recurse -Force C:\\\\x")
    assert "blocked" in err.lower()
    assert "nothing was captured" in err
    assert "claimed" in err


def test_shadow_mode_stays_quiet_on_stdout():
    # shadow must never emit a permission decision on stdout
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.txt"), "w").write("x")
    out, _ = _run_hook("rm -rf a.txt", mode="shadow", cwd=d)
    assert out.strip() == ""


def test_feedback_url_for_is_shared_by_both_paths():
    assert hasattr(render, "feedback_url_for")
    # feedback_line must be built ON TOP of feedback_url_for (no divergence)
    assert hasattr(render, "feedback_line")


def test_feedback_url_empty_on_plain_allow():
    class _D:  # minimal stand-in for a non-feedback decision
        decision = "ALLOW"
        reason = "non-mutating"
    class _R:
        decision = _D()
        command = "ls"
        classification = type("C", (), {"matched_rule": None})()
    assert render.feedback_url_for(_R()) == ""


def test_hook_selftest_exists_and_returns_bool():
    assert hasattr(cli, "_hook_selftest")
    assert isinstance(cli._hook_selftest("Bash", "rm -rf canary.txt"), bool)


# --------------------------------------------------------------------------
# A block has to say who blocked it
#
# Observed 2026-08-26 on Windows. demo_cli denied `curl.exe -X DELETE ...` and
# the agent read only:
#
#     No recovery path for a mutating action on 'unknown';
#     cannot auto-recover. Human input required.
#
# So it guessed - told the user "this looks like a safety gate in the
# environment", then suggested running the command outside the session to get
# past it. Honest reasoning from an unattributed message, and exactly the
# wrong conclusion.
# --------------------------------------------------------------------------
import io as _io
import json as _json

from demo_cli.hooks import TAG, attributed


def _deny_reason(monkeypatch, tmp_path, module, entry, payload):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    out = _io.StringIO()
    getattr(module, entry)(_io.StringIO(_json.dumps(payload)), out)
    data = _json.loads(out.getvalue())
    inner = data.get("hookSpecificOutput", data)
    return (inner.get("permissionDecisionReason")
            or data.get("agentMessage") or data.get("agent_message") or "")


_BLOCKED = "curl.exe -X DELETE https://httpbin.org/delete"


def test_claude_code_attributes_its_denial(monkeypatch, tmp_path):
    from demo_cli.hooks import claude_code
    reason = _deny_reason(monkeypatch, tmp_path, claude_code, "run_pretooluse",
                          {"tool_name": "Bash", "tool_input": {"command": _BLOCKED}})
    assert reason.startswith(TAG)


def test_codex_attributes_its_denial(monkeypatch, tmp_path):
    from demo_cli.hooks import codex
    reason = _deny_reason(monkeypatch, tmp_path, codex, "run_pretooluse",
                          {"tool_name": "Bash", "tool_input": {"command": _BLOCKED}})
    assert reason.startswith(TAG)


def test_cursor_attributes_its_denial(monkeypatch, tmp_path):
    from demo_cli.hooks import cursor
    reason = _deny_reason(monkeypatch, tmp_path, cursor, "run_before_shell",
                          {"command": _BLOCKED})
    assert reason.startswith(TAG)


def test_the_reason_itself_survives_the_prefix():
    assert attributed("no recovery path").endswith("no recovery path")


def test_prefixing_is_idempotent():
    """Belt and braces: a caller that already tagged must not double-tag."""
    once = attributed("blocked")
    assert attributed(once) == once


def test_an_empty_reason_still_names_us():
    assert attributed("") == TAG
    assert attributed(None) == TAG


def test_receipt_reasons_are_NOT_tagged(monkeypatch, tmp_path):
    """The ledger records what was decided, not who printed it. Tagging there
    would put presentation text into the hash chain forever."""
    from demo_cli.config import Config
    from demo_cli.guard import Guard
    monkeypatch.chdir(tmp_path)
    r = Guard(Config(mode="enforce", project_root=str(tmp_path))).evaluate(
        _BLOCKED, agent_id="t", session_id="t")
    assert TAG not in r.receipt.reason
