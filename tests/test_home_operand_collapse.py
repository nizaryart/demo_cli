"""`rm -f ~/a ~/b` snapshotted the current directory and called it a recovery.

Found by review 2026-09-08. The first unearned REVERSIBLE this project has
had - the failure §1 of the review brief calls the only one that matters -
and it hid behind a condition that makes it easy to test wrongly.

    cwd = <project root>       ESCALATE   (correct, by accident)
    cwd = <project root>/sub   REVERSIBLE, snapshot of <root>/sub

The mechanism: `~` and `$VAR` are expanded BY THE SHELL, so the command
reaches the hook literal. `os.path.abspath("~/a")` is "<cwd>/~/a", a path that
cannot exist. Two of them collapse to a common prefix of "<cwd>/~", which is
not a directory, so _common_capture_root takes its dirname - THE CURRENT
DIRECTORY - finds it is a real directory, and captures it.

From the project root, _too_broad refuses that and the command escalates. From
a subdirectory nothing refuses it, so a directory with no relationship to the
deleted files is snapshotted and the tool reports a recovery point the user
can name. A TEST WRITTEN FROM THE PROJECT ROOT PASSES AGAINST THE BROKEN CODE,
which is why every case below runs from a subdirectory.

Fixed two ways, same contract as resolve_redirect_target:
  * `~` is expanded, because it IS resolvable - our view of the operands has
    to match the shell's
  * an operand still carrying $VAR / $( / backtick / %VAR% makes the whole
    capture unresolved, because a common root computed from a non-path is
    meaningless
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def sub(tmp_path, monkeypatch):
    """A project root with a subdirectory, standing IN the subdirectory."""
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    d = tmp_path / "sub"
    d.mkdir()
    (d / "innocent.txt").write_text("do not lose me")
    monkeypatch.chdir(d)
    return d


@pytest.mark.parametrize("cmd", [
    'rm -f ~/a ~/b',
    'rm -f $HOME/a $HOME/b',
    'rm -rf ~/one ~/two',
])
def test_home_operands_never_collapse_to_the_working_directory(sub, cmd):
    """The headline. Deleting in $HOME must not snapshot where you happen to
    be standing and call that a recovery."""
    assert recovery.extract_path_operand(cmd) != str(sub)
    r = Guard(mode="enforce").evaluate(cmd)
    assert r.decision.decision == "ESCALATE", cmd
    assert not r.recovery_entry, "captured a directory unrelated to the damage"


def test_the_bug_needed_a_subdirectory_to_appear(tmp_path, monkeypatch):
    """Pinned so nobody 'simplifies' the fixture above back to the root and
    quietly stops testing anything: from the project root the collapse hits
    _too_broad and escalates whether or not the fix is present."""
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    monkeypatch.chdir(tmp_path)
    assert Guard(mode="enforce").evaluate('rm -f ~/a ~/b').decision.decision == "ESCALATE"


@pytest.mark.parametrize("cmd", [
    'rm -f $(cat list.txt) other.txt',
    'rm -f `cat list.txt` other.txt',
    'rm -f %APPDATA%\\a %APPDATA%\\b',
])
def test_unexpanded_operands_make_the_capture_unresolved(sub, cmd):
    """Same rule as resolve_redirect_target: refusing to answer is an answer,
    guessing is not."""
    assert recovery.extract_path_operand(cmd) is None, cmd


def test_a_legitimate_multi_path_collapse_still_works(sub):
    """The capability this must not cost. Two files in one real subdirectory
    still collapse to that directory and stay recoverable - the whole point of
    the collapse rule."""
    inner = sub / "inner"
    inner.mkdir()
    (inner / "x.txt").write_text("x")
    (inner / "y.txt").write_text("y")
    r = Guard(mode="enforce").evaluate('rm -rf inner/x.txt inner/y.txt')
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry
    assert os.path.samefile(r.recovery_entry["target"], str(inner))


def test_tilde_is_expanded_in_operands_like_the_shell_would(sub):
    """Not escalated - expanded. `~` is resolvable, and treating it as opaque
    would over-fire on an honest, answerable command."""
    ops = recovery._path_operands('rm -f ~/a ~/b')
    assert ops, "operands vanished"
    home = os.path.expanduser("~")
    assert all(p.startswith(home) for p in ops), ops
    assert not any("~" in p for p in ops)
