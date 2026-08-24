"""Same-line variable substitution, both dialects.

The guard reads the text of a command and never runs it, so a path that is not
literally in the text cannot be resolved and the action escalates. Measured on
2026-08-24, four shapes cause that; only one of them is actually unreadable by
accident rather than by necessity:

    rm $(cat list.txt)      resolving it means RUNNING cat. Never.
    python cleanup.py       the paths live inside another file.
    rm $TARGET              assigned in an earlier, separate command. On Linux
                            the value sits in a bash session the hook process
                            cannot reach; on Windows it does not exist at all,
                            because Claude Code spawns a fresh
                            `powershell -NoProfile` for every tool call
                            (verified live against the agent).
    T=notes.txt; rm $T      assignment and use in the SAME string. Readable
                            without executing anything.

These tests cover the last one and, just as importantly, pin the first three as
still escalating. Pure string logic, so it runs on both platforms.
"""
import os

import pytest

from demo_cli.classify import POSIX, POWERSHELL, substitute_assignments
from demo_cli.config import Config
from demo_cli.guard import Guard


def sub(cmd, dialect=POSIX):
    return substitute_assignments(cmd, dialect)


# --------------------------------------------------------------------------
# What it resolves
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,expected", [
    ("T=notes.txt; rm $T",            "T=notes.txt; rm notes.txt"),
    ('T="notes.txt"; rm "$T"',        'T="notes.txt"; rm "notes.txt"'),
    ("T='notes.txt'; rm $T",          "T='notes.txt'; rm notes.txt"),
    ("T=notes.txt; rm ${T}",          "T=notes.txt; rm notes.txt"),
    ("export T=notes.txt && rm $T",   "export T=notes.txt && rm notes.txt"),
    ("T=logs/app.log; rm $T",         "T=logs/app.log; rm logs/app.log"),
])
def test_posix_assignments_resolve(cmd, expected):
    assert sub(cmd) == expected


@pytest.mark.parametrize("cmd,expected", [
    ('$t = "notes.txt"; Remove-Item $t',
     '$t = "notes.txt"; Remove-Item notes.txt'),
    ('$t="notes.txt";Remove-Item $t',
     '$t="notes.txt";Remove-Item notes.txt'),
    ('$t = "C:\\logs\\app.log"; Clear-Content $t',
     '$t = "C:\\logs\\app.log"; Clear-Content C:\\logs\\app.log'),
])
def test_powershell_assignments_resolve(cmd, expected):
    assert sub(cmd, POWERSHELL) == expected


def test_powershell_env_variables_resolve():
    """$env:X = "y" is the form the agent actually used on Windows, observed
    live while testing whether tool calls share a session."""
    assert sub('$env:T = "notes.txt"; Remove-Item $env:T', POWERSHELL) == \
        '$env:T = "notes.txt"; Remove-Item notes.txt'


def test_the_assignment_target_is_not_substituted_with_its_own_value():
    """`$t = "a"` matches the REFERENCE pattern as well as the assignment one.
    Without skipping the left-hand side the assignment rewrites itself."""
    out = sub('$t = "a.txt"; $t = "b.txt"; Remove-Item $t', POWERSHELL)
    assert out.startswith('$t = "a.txt"; $t = "b.txt";')
    assert out.endswith("Remove-Item b.txt")


# --------------------------------------------------------------------------
# Order: only assignments that have already run
# --------------------------------------------------------------------------

def test_the_latest_assignment_before_the_use_wins():
    assert sub("T=a.txt; T=b.txt; rm $T") == "T=a.txt; T=b.txt; rm b.txt"


def test_an_assignment_after_the_use_is_not_applied():
    """It has not run yet when the rm executes."""
    assert sub("T=a.txt; rm $T; T=b.txt") == "T=a.txt; rm a.txt; T=b.txt"


# --------------------------------------------------------------------------
# What it refuses - the honesty half
# --------------------------------------------------------------------------

def test_an_unknown_variable_leaves_the_command_untouched():
    assert sub("rm $T") == "rm $T"


def test_a_value_containing_command_substitution_is_refused():
    """Substituting `$(cat x)` in would turn "I cannot tell what this is" into
    something that LOOKS resolved. Worse than admitting ignorance."""
    assert sub("T=$(cat x); rm $T") == "T=$(cat x); rm $T"


def test_a_value_containing_another_variable_is_refused():
    assert sub("T=$OTHER/data; rm $T") == "T=$OTHER/data; rm $T"


@pytest.mark.parametrize("value", ['"a;rm -rf /"', '"a|tee x"', '"a>out"', '"a&b"'])
def test_a_quoted_value_holding_shell_metacharacters_is_refused(value):
    """Quoting is how a metacharacter gets INSIDE a value. Substituting it back
    unquoted would turn one command into two, and the classifier would then be
    judging a command line nobody wrote."""
    cmd = f"T={value}; rm $T"
    assert sub(cmd) == cmd


@pytest.mark.parametrize("cmd", [
    "T=a.txt | tee log; rm $T",
    "T=a.txt & sleep 1; rm $T",
])
def test_an_assignment_that_runs_in_a_subshell_is_refused(cmd):
    """A pipeline stage and a backgrounded command both fork. The parent shell
    never sees T, so substituting would name a file the shell never touched -
    and then report a snapshot of it.

    An unquoted value cannot contain these characters (the value pattern stops
    before them), so the unsafe-value check never sees this case at all.
    """
    assert sub(cmd) == cmd


@pytest.mark.parametrize("cmd,expected", [
    ("T=notes.txt && rm $T", "T=notes.txt && rm notes.txt"),
    ("T=notes.txt || rm $T", "T=notes.txt || rm notes.txt"),
    ("T=notes.txt > out; rm $T", "T=notes.txt > out; rm notes.txt"),
])
def test_sequencing_operators_do_not_fork_so_the_value_survives(cmd, expected):
    """`&&` and `||` are doubled versions of the forking operators and behave
    completely differently. Refusing them too would give up resolution for no
    reason."""
    assert sub(cmd) == expected


def test_one_unresolved_reference_discards_the_whole_substitution():
    """THE central rule of this function.

    `rm $T $OTHER` with only T known would become `rm notes.txt $OTHER`, where
    $OTHER is now an ordinary-looking operand that happens not to exist. Two
    operands collapse to their common directory, and the guard would consider
    snapshotting a directory for a command it still cannot read. Partial
    knowledge presented as complete is the failure this project is about.
    """
    cmd = "T=notes.txt; rm $T $OTHER"
    assert sub(cmd) == cmd


def test_a_command_with_no_dollar_sign_is_returned_immediately():
    assert sub("rm notes.txt") == "rm notes.txt"


def test_substitution_is_idempotent():
    once = sub("T=notes.txt; rm $T")
    assert sub(once) == once


# --------------------------------------------------------------------------
# End to end: the decision that actually reaches the user
# --------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "notes.txt").write_text("important")
    return Guard(Config(mode="enforce", project_root=str(tmp_path)))


def test_a_resolvable_variable_becomes_a_real_snapshot(workspace):
    r = workspace.evaluate("T=notes.txt; rm $T", agent_id="t", session_id="t")
    assert r.receipt.decision == "REVERSIBLE"
    assert r.receipt.recovery_point, "the whole point: a precise snapshot"


@pytest.mark.parametrize("cmd", [
    "rm $T",                        # nothing to read
    "T=$(cat x); rm $T",            # would require executing
    "T=notes.txt; rm $T $OTHER",    # partial knowledge
])
def test_what_cannot_be_read_still_escalates(workspace, cmd):
    r = workspace.evaluate(cmd, agent_id="t", session_id="t")
    assert r.receipt.decision == "ESCALATE"
    assert not r.receipt.recovery_point


def test_substitution_does_not_defeat_the_too_broad_check(workspace):
    """`T=/; rm -rf $T` resolves perfectly well - to the root of the disk. A
    resolved target is not automatically a snapshotable one, and the existing
    breadth check must still have the last word."""
    r = workspace.evaluate("T=/; rm -rf $T", agent_id="t", session_id="t")
    assert r.receipt.decision == "ESCALATE"
    assert not r.receipt.recovery_point


@pytest.mark.skipif(os.name != "nt", reason="needs real Windows paths")
def test_powershell_variable_resolves_on_windows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "notes.txt").write_text("important")
    g = Guard(Config(mode="enforce", project_root=str(tmp_path)))
    r = g.evaluate('$t = "notes.txt"; Remove-Item $t',
                   agent_id="t", session_id="t", dialect=POWERSHELL)
    assert r.receipt.decision == "REVERSIBLE"
    assert r.receipt.recovery_point
