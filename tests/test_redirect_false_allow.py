"""Five spellings of "overwrite an existing file" that reached ALLOW.

Found by review 2026-09-08, and the worst defect this project has had: not a
false REVERSIBLE - a false ALLOW. The file was truncated with no snapshot, no
recovery entry, no receipt of destruction, and no escalation. The user was not
even told a recovery had been claimed, because none was.

    echo x > app.db              REVERSIBLE   the one spelling that worked
    bash -c "echo x > app.db"    ALLOW
    T=app.db; echo x > $T        ALLOW
    echo x 1> app.db             ALLOW
    echo x &> app.db             ALLOW
    echo x 2> app.db             ALLOW

TWO CAUSES, ONE SHAPE. Three modules resolved the same question three ways:

    classify_pipeline        effective segments        (widened 2026-09-02)
    extract_path_operand     effective segments + substitution
    Guard.evaluate           THE RAW LINE

Widening the classifier to see inside nested shells - the 2026-09-02 fix for
two nested-shell bugs - made it flag commands the guard could then no longer
find a target for. And the guard read "I cannot find the target" as "there is
nothing there yet", clearing the flag. Its own comment had always said the
opposite: "A name that does not resolve at all is AMBIGUOUS and keeps its
classification, so it still escalates - never quietly waved through."

The second cause was independent: `1>`, `2>` and `&>` were skipped as
"fd-prefixed, out of scope", though all three truncate from byte zero.

Every case below is ordinary honest shell. None requires obfuscation, so none
is behind the threat model's evasion frontier - `bash -c "..."` and a variable
holding a filename are what people and agents actually write.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / "app.db").write_text("real data")
    (tmp_path / "notes.txt").write_text("real notes")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _decide(cmd):
    return Guard(mode="enforce").evaluate(cmd).decision.decision


# --------------------------------------------------------------------------
# The hole itself. Each of these truncates a file that exists.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo x > notes.txt',
    'bash -c "echo x > notes.txt"',
    'T=notes.txt; echo x > $T',
    'echo x 1> notes.txt',
    'echo x &> notes.txt',
    'echo x 2> notes.txt',
])
def test_overwriting_an_existing_file_is_never_a_plain_allow(lab, cmd):
    assert _decide(cmd) != "ALLOW", f"{cmd} destroys an existing file unguarded"


@pytest.mark.parametrize("cmd", [
    'bash -c "echo x > notes.txt"',
    'T=notes.txt; echo x > $T',
    'echo x 1> notes.txt',
])
def test_and_it_is_recoverable_not_merely_blocked(lab, cmd):
    """Blocking would close the hole and lose the point. The target IS
    resolvable through the effective, substituted segments, so the honest
    outcome is a snapshot - recovery is the default, blocking is the fallback."""
    r = Guard(mode="enforce").evaluate(cmd)
    assert r.decision.decision == "REVERSIBLE", cmd
    assert r.recovery_entry, "flagged but nothing captured"


# --------------------------------------------------------------------------
# Unresolvable is its own answer, and it is not "creation".
# --------------------------------------------------------------------------

def test_an_unexpanded_variable_escalates_rather_than_reading_as_new(lab):
    """`$HOME/data.db` does not exist under that literal name. Treating "the
    literal string is not on disk" as "the file is new" reads a real file as a
    creation - the same mistake in a different spelling."""
    assert _decide('echo x > $HOME/data.db') == "ESCALATE"


def test_two_redirects_escalate_rather_than_capturing_one(lab):
    """Snapshotting the first while the second is truncated unrecorded is the
    partial-recovery lie."""
    (lab / "second.txt").write_text("also real")
    assert _decide('echo a > notes.txt; echo b > second.txt') == "ESCALATE"


# --------------------------------------------------------------------------
# What must NOT change. Over-firing here would be its own defect.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo x > brand_new.txt',      # creation: nothing to destroy
    'echo x >> notes.txt',         # append
    'echo x > /dev/null',          # sink
    'make 2> /dev/null',           # the commonest idiom in shell
    'make 2>&1',                   # fd duplication truncates nothing
])
def test_the_harmless_forms_stay_allowed(lab, cmd):
    assert _decide(cmd) == "ALLOW", f"{cmd} should not have been flagged"


# --------------------------------------------------------------------------
# The resolver's contract, directly. "Found" and "resolved" are different.
# --------------------------------------------------------------------------

def test_resolver_reports_unresolved_rather_than_guessing(lab):
    assert recovery.resolve_redirect_target('echo x > notes.txt')[1] is True
    assert recovery.resolve_redirect_target('bash -c "echo x > notes.txt"')[1] is True
    assert recovery.resolve_redirect_target('T=notes.txt; echo x > $T')[1] is True
    # Unresolved, each for its own reason.
    assert recovery.resolve_redirect_target('echo x > $HOME/d.db') == (None, False)
    assert recovery.resolve_redirect_target('echo a > x; echo b > y') == (None, False)
    assert recovery.resolve_redirect_target('echo hello') == (None, False)


def test_resolver_and_classifier_cannot_disagree(lab):
    """The defect in one sentence: the classifier saw a redirect the guard
    could not resolve. Anything the classifier flags must be resolvable by the
    same reading, or explicitly unresolved - never silently absent."""
    from demo_cli.classify import classify_pipeline
    for cmd in ('bash -c "echo x > notes.txt"', 'T=notes.txt; echo x > $T',
                'echo x 1> notes.txt', 'echo x &> notes.txt'):
        assert classify_pipeline(cmd).matched_rule == "fs_redirect_truncate", cmd
        tgt, resolved = recovery.resolve_redirect_target(cmd)
        assert resolved and os.path.exists(tgt), cmd
