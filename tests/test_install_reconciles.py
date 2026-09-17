r"""install-hook was add-if-absent, so a raised value never reached anyone.

    claude_code:  if not _present(matcher): pre.append(...)
    codex:        if not any(_declares_our_hook(g) for g in pre): pre.append(...)

One matching command string and the whole entry was skipped - not compared,
not repaired, just carried through and re-serialised. So the hook timeout
raised on 2026-09-16 (30 -> 120 on Codex, declared-where-nothing-was-declared
on Claude Code) reached new installs only. `doctor` reported the old ones ok,
and `install-hook` printed the same "Installed..." line as a real install.

FOUND ON THIS PROJECT'S OWN MACHINE: ~/.codex/hooks.json still held
"timeout": 30, from before commit 35e5c34. 25,000 files at the measured 991 us
is 24.8 s - 83% of a 30 s budget - and overrunning it is the silent kill.

CURSOR ALREADY DID THIS, FOR ONE FIELD. cursor.py repaired a missing
failClosed on re-install, with its own test, while the two hosts actually in
scope did not. Fifth instance in this project of the correct version already
being in the tree, applied to something else. All three now share
reconcile_handler.

A TIMEOUT THE USER RAISED IS KEPT. Nizar's call, and the reasoning is that the
defect is a budget too LOW: raising ours is never wrong, and overriding a
higher value would re-introduce the failure the raise was for. A deliberately
LOWERED value is NOT honoured, and that is the one thing this overrides on
purpose - a shorter budget brings back the silent kill.
"""
import json
import os

import pytest

from demo_cli.hooks import reconcile_handler
from demo_cli.hooks.claude_code import _HOOK_TIMEOUT, install_into_settings
from demo_cli.hooks.codex import HOOK_COMMAND as CODEX_COMMAND
from demo_cli.hooks.codex import install_into_hooks_json as codex_install
from demo_cli.hooks.cursor import HOOK_COMMAND as CURSOR_COMMAND
from demo_cli.hooks.cursor import install_into_hooks_json as cursor_install

MATCHERS = ("Bash", "PowerShell", "Edit|Write|MultiEdit|NotebookEdit")


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _blocks(path):
    return json.loads(open(path, encoding="utf-8").read())["hooks"]["PreToolUse"]


def _handler_of(path, matcher):
    for b in _blocks(path):
        if b.get("matcher") == matcher:
            for h in b.get("hooks") or []:
                if h.get("command") == "demo_cli hook":
                    return h
    return None


def _codex_handler(path):
    for g in json.loads(open(path, encoding="utf-8").read())["hooks"]["PreToolUse"]:
        for h in g.get("hooks") or []:
            if h.get("command") == CODEX_COMMAND:
                return h
    return None


# ------------------------------------------------------------ claude code

def test_a_stale_timeout_is_raised(tmp_path):
    """THE DEFECT. Three blocks with no timeout stayed that way forever."""
    p = str(tmp_path / ".claude" / "settings.json")
    _write(p, {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": "demo_cli hook"}]}
        for m in MATCHERS]}})
    install_into_settings(p)
    for m in MATCHERS:
        assert _handler_of(p, m)["timeout"] == _HOOK_TIMEOUT, m


def test_it_reports_what_it_changed(tmp_path):
    """An install that repairs and one that no-ops printed the same line."""
    p = str(tmp_path / ".claude" / "settings.json")
    _write(p, {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": "demo_cli hook",
                                  "timeout": 30}]} for m in MATCHERS]}})
    changed = install_into_settings(p)
    assert len(changed) == 3, changed
    assert all("timeout 30 -> 120" in c for c in changed)


def test_a_second_run_reports_nothing(tmp_path):
    p = str(tmp_path / ".claude" / "settings.json")
    assert install_into_settings(p), "a fresh install must report registering"
    assert install_into_settings(p) == [], "a no-op must say nothing changed"


def test_a_hand_raised_timeout_survives(tmp_path):
    """Nizar's decision: raise, never lower."""
    p = str(tmp_path / ".claude" / "settings.json")
    _write(p, {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": "demo_cli hook",
                                  "timeout": 300}]} for m in MATCHERS]}})
    assert install_into_settings(p) == []
    assert _handler_of(p, "Bash")["timeout"] == 300


def test_the_users_other_settings_and_hooks_survive(tmp_path):
    p = str(tmp_path / ".claude" / "settings.json")
    _write(p, {"model": "sonnet",
               "permissions": {"deny": ["Bash(sudo *)"]},
               "hooks": {"PreToolUse": [
                   {"matcher": "Bash", "hooks": [
                       {"type": "command", "command": "their-own-tool"},
                       {"type": "command", "command": "demo_cli hook", "timeout": 30}]}],
                         "PostToolUse": [{"matcher": "Bash", "hooks": [
                             {"type": "command", "command": "theirs"}]}]}})
    install_into_settings(p)
    after = json.loads(open(p, encoding="utf-8").read())
    assert after["model"] == "sonnet"
    assert after["permissions"] == {"deny": ["Bash(sudo *)"]}
    assert "PostToolUse" in after["hooks"]
    bash = [b for b in after["hooks"]["PreToolUse"] if b["matcher"] == "Bash"][0]
    assert [h["command"] for h in bash["hooks"]] == ["their-own-tool", "demo_cli hook"]
    assert bash["hooks"][1]["timeout"] == _HOOK_TIMEOUT


def test_a_partial_install_is_both_reconciled_and_completed(tmp_path):
    """The pre-PowerShell shape: one stale block, two missing. Before the fix
    the stale one kept no timeout while the appended ones got 120 - one
    machine, two budgets, one green doctor row."""
    p = str(tmp_path / ".claude" / "settings.json")
    _write(p, {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "demo_cli hook"}]}]}})
    changed = install_into_settings(p)
    assert any("Bash: timeout" in c for c in changed), changed
    assert any("PowerShell: registered" in c for c in changed), changed
    assert {h["timeout"] for h in
            (_handler_of(p, m) for m in MATCHERS)} == {_HOOK_TIMEOUT}


# ------------------------------------------------------------ codex

def test_codex_stale_timeout_is_raised(tmp_path):
    p = str(tmp_path / ".codex" / "hooks.json")
    _write(p, {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": CODEX_COMMAND,
         "statusMessage": "demo_cli safety check", "timeout": 30}]}]}})
    changed = codex_install(p)
    assert changed == ["timeout 30 -> 120"], changed
    assert _codex_handler(p)["timeout"] == 120


def test_codex_repairs_the_inert_shape(tmp_path):
    """A handler with no "type" is accepted and then silently ignored by the
    host - codex.py's own words. Re-installing used to leave it untouched, so
    the one state that means NO PROTECTION was also the one install skipped."""
    p = str(tmp_path / ".codex" / "hooks.json")
    _write(p, {"hooks": {"PreToolUse": [{"hooks": [
        {"command": CODEX_COMMAND, "timeout": 120}]}]}})
    changed = codex_install(p)
    assert any("type" in c for c in changed), changed
    assert _codex_handler(p)["type"] == "command"


def test_codex_does_not_duplicate_the_group(tmp_path):
    p = str(tmp_path / ".codex" / "hooks.json")
    codex_install(p)
    codex_install(p)
    groups = json.loads(open(p, encoding="utf-8").read())["hooks"]["PreToolUse"]
    assert len(groups) == 1


def test_codex_keeps_a_hand_raised_timeout(tmp_path):
    p = str(tmp_path / ".codex" / "hooks.json")
    _write(p, {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": CODEX_COMMAND,
         "statusMessage": "demo_cli safety check", "timeout": 600}]}]}})
    assert codex_install(p) == []
    assert _codex_handler(p)["timeout"] == 600


# ------------------------------------------------------------ cursor

def test_cursor_still_repairs_failclosed_through_the_shared_helper(tmp_path):
    p = str(tmp_path / ".cursor" / "hooks.json")
    _write(p, {"version": 1, "hooks": {
        "beforeShellExecution": [{"command": CURSOR_COMMAND}]}})
    changed = cursor_install(p)
    assert any("failClosed" in c for c in changed), changed
    entries = json.loads(open(p, encoding="utf-8").read())["hooks"]["beforeShellExecution"]
    assert all(b["failClosed"] is True for b in entries if b["command"] == CURSOR_COMMAND)


# ------------------------------------------------------------ the helper

def test_the_helper_keeps_keys_it_does_not_write(tmp_path):
    """Dropping something a user added would be the silent loss H1 stopped."""
    got = {"command": "x", "theirOwnKey": "keep me"}
    reconcile_handler(got, {"command": "x", "timeout": 120})
    assert got["theirOwnKey"] == "keep me"


def test_a_lowered_timeout_is_overridden_on_purpose(tmp_path):
    """The one case the helper refuses to honour: a SHORTER budget brings back
    the silent kill, so it is raised and the change is reported."""
    got = {"command": "x", "timeout": 5}
    assert reconcile_handler(got, {"command": "x", "timeout": 120}) == ["timeout 5 -> 120"]
    assert got["timeout"] == 120


@pytest.mark.parametrize("bogus", ["30", None, True, [30]])
def test_a_non_numeric_timeout_is_replaced_not_compared(bogus):
    """`True > 120` is False and `"30" > 120` raises; neither may be treated as
    a deliberately raised budget."""
    got = {"command": "x", "timeout": bogus}
    reconcile_handler(got, {"command": "x", "timeout": 120})
    assert got["timeout"] == 120
