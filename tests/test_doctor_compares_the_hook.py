r"""doctor answered "am I protected" with presence, and presence was one
string compared.

    _hook_installed:  if h.get("command") == command: return True

That is all it ever asked. It never read `timeout`, never read `type`, never
checked that all three Claude Code matchers exist, and never compared anything
against what the current version would install. So an entry written by an older
demo_cli kept whatever it had and doctor printed a green row naming the file.

TWO CONSEQUENCES, BOTH LIVE ON THIS PROJECT'S OWN MACHINES.

`~/.codex/hooks.json` on the Linux box holds `"timeout": 30` - the value from
before the raise. 25,000 files at the measured 991 us is 24.8 s, which is 83%
of a 30 s budget, and overrunning it is the SILENT kill measured on 09-16: the
host kills the hook, runs the command unguarded, and prints nothing. The cap
shipped on 09-16 is sized for a budget that machine does not have, and nothing
could tell anyone so.

REGISTERED BUT INERT is the worse state, and it had no row at all. codex.py's
own docstring: a handler without `type` is "accepted by the file parser and
then SILENTLY IGNORED - no error, no warning, no hook, no protection". Both
`_declares_our_hook` and `_hook_installed` key on `command` alone, so such an
entry was installed, inert, and green. That is a FAIL here, not a warning, for
the same reason the PATH check is a hard fail: every other signal reports it as
present, so a soft row is how it stays broken.

Asserted on the (status, label, detail) tuples, never on rendered glyphs.

ISOLATION MATTERS IN THIS FILE. The audit searches the project and then the
user's home, so a test asserting "nothing stale" would read the developer's
real ~/.codex/hooks.json and fail for a true reason in the wrong place. Every
test here fakes HOME.
"""
import json
import os

import pytest

from demo_cli.cli import _hook_check_rows, _host_hook_audit, _host_hook_status
from demo_cli.config import Config

MATCHERS = ("Bash", "PowerShell", "Edit|Write|MultiEdit|NotebookEdit")


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A project, and a HOME with nothing in it."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr("os.path.expanduser", lambda p: p.replace("~", str(home), 1))
    proj = tmp_path / "P"
    proj.mkdir()
    return proj


def _claude(proj, blocks):
    d = proj / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": blocks}}))


def _codex(proj, handler, bom=False):
    d = proj / ".codex"
    d.mkdir(exist_ok=True)
    text = json.dumps({"hooks": {"PreToolUse": [{"hooks": [handler]}]}})
    with open(d / "hooks.json", "wb") as f:
        if bom:
            f.write(b"\xef\xbb\xbf")
        f.write(text.encode("utf-8"))


def _handler(**kw):
    return dict({"type": "command", "command": "demo_cli hook"}, **kw)


def _audit(proj, label):
    return {l: (s, i) for l, _p, s, i in
            _host_hook_audit(Config(project_root=str(proj)))}[label]


def _row(proj, label):
    return {name: (status, detail) for status, name, detail in
            _hook_check_rows(Config(project_root=str(proj)))}[f"hook: {label}"]


# ------------------------------------------------------------- clean = quiet

def test_a_current_install_reports_nothing(lab):
    _claude(lab, [{"matcher": m, "hooks": [_handler(timeout=120)]} for m in MATCHERS])
    assert _audit(lab, "claude code") == ([], [])
    assert _row(lab, "claude code")[0] == "ok"


# ------------------------------------------------------------- stale

def test_a_pre_timeout_install_is_stale_not_ok(lab):
    """THE DEFECT. Three blocks, no timeout, and doctor said ok."""
    _claude(lab, [{"matcher": m, "hooks": [_handler()]} for m in MATCHERS])
    stale, inert = _audit(lab, "claude code")
    assert inert == []
    assert len(stale) == 3, stale
    assert all("timeout absent" in s and "current 120" in s for s in stale)
    status, detail = _row(lab, "claude code")
    assert status == "warn"
    assert "stale" in detail and "re-run: demo_cli install-hook" in detail


def test_a_wrong_timeout_names_both_values(lab):
    _codex(lab, {"type": "command", "command": "demo_cli hook-codex",
                 "statusMessage": "demo_cli safety check", "timeout": 30})
    stale, inert = _audit(lab, "codex")
    assert inert == []
    assert stale == ["timeout 30, current 120"], stale


def test_a_pre_powershell_install_names_the_missing_matchers(lab):
    """Registered for Bash only: PowerShell and file edits are unguarded, and
    the row was green."""
    _claude(lab, [{"matcher": "Bash", "hooks": [_handler(timeout=120)]}])
    stale, _ = _audit(lab, "claude code")
    assert "no entry for 'PowerShell'" in stale
    assert "no entry for 'Edit|Write|MultiEdit|NotebookEdit'" in stale


# ------------------------------------------------------------- inert

def test_a_handler_without_type_is_inert_and_fails(lab):
    """codex.py documents this shape as silently ignored by the host."""
    _codex(lab, {"command": "demo_cli hook-codex",
                 "statusMessage": "demo_cli safety check", "timeout": 120})
    stale, inert = _audit(lab, "codex")
    assert inert == ['handler has no "type"'], inert
    status, detail = _row(lab, "codex")
    assert status == "fail", "an entry that cannot fire was not a failure"
    assert "INERT" in detail


def test_inert_outranks_stale(lab):
    """Both wrong at once: the one that means "no protection at all" wins.

    Asserted on the audit lists and the status, not by grepping the detail -
    the first version of this test looked for "stale" in the detail string and
    found it in the pytest tmp path, which is this project's own rule about
    asserting on renderings, self-inflicted.
    """
    _codex(lab, {"command": "demo_cli hook-codex", "timeout": 30})
    stale, inert = _audit(lab, "codex")
    assert stale and inert, "the fixture must be both stale AND inert"
    status, detail = _row(lab, "codex")
    assert status == "fail"
    assert "INERT" in detail


# ------------------------------------------------------------- absent / broken

def test_nothing_installed_is_still_a_warning(lab):
    status, detail = _row(lab, "claude code")
    assert status == "warn"
    assert "not installed" in detail


def test_an_unparseable_config_reads_as_not_installed(lab):
    """It must not crash doctor, and it must not claim protection."""
    d = lab / ".claude"
    d.mkdir()
    (d / "settings.json").write_text("{broken")
    assert _row(lab, "claude code")[0] == "warn"
    assert _audit(lab, "claude code") == ([], [])


def test_a_bom_does_not_read_as_absent(lab):
    """_read_host_config uses utf-8-sig; a BOM'd install is a real install."""
    _codex(lab, {"type": "command", "command": "demo_cli hook-codex",
                 "statusMessage": "demo_cli safety check", "timeout": 120}, bom=True)
    assert _row(lab, "codex")[0] == "ok"


# ------------------------------------------------------------- one source of truth

def test_expected_values_come_from_the_installer_not_a_copy(lab, monkeypatch):
    """The comparison must read settings_snippet(), so it cannot drift from
    what install actually writes. A retyped 120 here is how _walk_cost once
    measured a different ignore set than the copy it was bounding."""
    _claude(lab, [{"matcher": m, "hooks": [_handler(timeout=120)]} for m in MATCHERS])
    assert _audit(lab, "claude code") == ([], [])

    monkeypatch.setenv("DEMO_CLI_HOOK_TIMEOUT", "300")
    stale, _ = _audit(lab, "claude code")
    assert stale and all("current 300" in s for s in stale), (
        f"the audit did not follow the installer's own constant: {stale}")


def test_the_two_tuple_view_still_exists_for_assess(lab):
    """guarded.assess unpacks (label, path). Widening the audit must not have
    changed that contract."""
    _claude(lab, [{"matcher": m, "hooks": [_handler(timeout=120)]} for m in MATCHERS])
    rows = _host_hook_status(Config(project_root=str(lab)))
    assert [len(r) for r in rows] == [2, 2, 2]
    assert dict(rows)["claude code"] is not None
