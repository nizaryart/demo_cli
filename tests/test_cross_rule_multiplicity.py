"""Two destructive steps, two different verbs, one snapshot.

Found by review 2026-09-08. The partial-recovery lie surviving because the two
steps did not use the SAME verb.

    rm a.txt; rm b.txt              ESCALATE    correct, and always was
    rm old.txt; mv new.txt keep.txt REVERSIBLE  snapshot of old.txt only
    rm old.txt; echo z > keep.txt   REVERSIBLE  snapshot of old.txt only

keep.txt is clobbered in the last two with nothing captured, and the receipt
claims a recovery. extract_path_operand looped rule by rule and RETURNED on
the first rule that matched, so each rule could only ever count its own
segments. Multiplicity is now counted across every rule at once, with the
redirect detector included - `> file` is a destructive step even though no
rule regex covers it.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    for name in ("old.txt", "new.txt", "keep.txt", "other.txt"):
        (tmp_path / name).write_text(name)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.parametrize("cmd", [
    'rm old.txt; mv new.txt keep.txt',
    'rm old.txt; echo z > keep.txt',
    'mv new.txt keep.txt; rm old.txt',        # order must not matter
    'echo z > keep.txt; rm old.txt',
    'rm old.txt && mv new.txt keep.txt',      # && as well as ;
    'echo a > keep.txt; echo b > other.txt',  # two redirects
])
def test_two_destructive_steps_never_yield_one_snapshot(lab, cmd):
    assert recovery.extract_path_operand(cmd) is None, cmd
    r = Guard(mode="enforce").evaluate(cmd)
    assert r.decision.decision == "ESCALATE", cmd
    assert not r.recovery_entry, "half the damage captured, reported as a recovery"


def test_the_same_verb_twice_was_already_caught(lab):
    """Pinned so the cross-rule check is not mistaken for the whole story: the
    per-rule count already handled this, and must keep doing so."""
    assert recovery.extract_path_operand('rm old.txt; rm keep.txt') is None


@pytest.mark.parametrize("cmd,expected", [
    ('rm old.txt',                    "old.txt"),
    ('mv new.txt keep.txt',           "keep.txt"),
    ('echo hi; rm old.txt',           "old.txt"),
    ('cat old.txt | grep x; rm old.txt', "old.txt"),
    ('cd . && rm old.txt',            "old.txt"),
])
def test_one_destructive_step_still_resolves(lab, cmd, expected):
    """The capability this must not cost. A single destructive segment among
    any number of harmless ones stays recoverable."""
    got = recovery.extract_path_operand(cmd)
    assert got and os.path.samefile(got, lab / expected), f"{cmd} -> {got}"


def test_one_segment_matching_two_rules_counts_once(lab):
    """`acting` is a set of segment INDICES, not of rule matches - otherwise a
    single segment picked up by two regexes would look like two destructive
    steps and escalate a perfectly resolvable command."""
    segs = ['mv new.txt keep.txt']
    idx = {i for i, seg in enumerate(segs)
           if any(rx.search(seg) for rx in (recovery._RM_RE, recovery._MV_RE))}
    assert len(idx) <= 1
    assert recovery.extract_path_operand('mv new.txt keep.txt') is not None


# --------------------------------------------------------------------------
# The half recovery.py cannot see: a destruction it has no verb for.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'DROP TABLE users; rm old.txt',
    'git reset --hard; rm old.txt',
    'git checkout . ; rm old.txt',
    'rm old.txt; git stash drop',
    'git clean -fd; rm old.txt',
])
def test_a_destruction_with_no_operand_still_blocks_the_snapshot(lab, cmd):
    """recovery.py knows rm / mv / Remove-Item / redirects. It has no idea a
    DROP or a hard reset destroyed anything, so it resolves old.txt quite
    correctly and the receipt claims a recovery for a command that also
    dropped a table.

    The classifier DOES know, so it is the one that reports how many segments
    destroy something. One snapshot can stand behind one of them.
    """
    r = Guard(mode="enforce").evaluate(cmd)
    assert r.classification.destructive_segments > 1, cmd
    assert r.decision.decision == "ESCALATE", cmd
    assert not r.recovery_entry, "claimed a recovery for half the damage"


@pytest.mark.parametrize("cmd", [
    'git status; rm old.txt',
    'git log --oneline; rm old.txt',
    'echo hi; rm old.txt',
    'cat old.txt | grep x; rm old.txt',
])
def test_a_harmless_command_alongside_a_delete_is_still_recoverable(lab, cmd):
    """The count is of DESTRUCTIVE segments, not of segments. A read-only git
    command must not cost the user their snapshot."""
    r = Guard(mode="enforce").evaluate(cmd)
    assert r.classification.destructive_segments == 1, cmd
    assert r.decision.decision == "REVERSIBLE", cmd
    assert r.recovery_entry


def test_an_explicit_target_is_still_honoured(lab):
    """Dropping the target is a refusal to GUESS. When the user names what
    they want captured, overriding them would be its own dishonesty - and
    'the user asked for this one' is a different claim from 'we worked out
    what this command touches'."""
    r = Guard(mode="enforce").evaluate('DROP TABLE users; rm old.txt',
                                       target_path=str(lab / "old.txt"))
    assert r.recovery_entry, "an explicitly named target was discarded"


def test_the_count_is_per_segment_not_per_line(lab):
    """Pinned because the whole fix rests on it: classify_pipeline used to
    collapse everything into one is_destructive flag for the line."""
    from demo_cli.classify import classify_pipeline
    assert classify_pipeline('rm a.txt').destructive_segments == 1
    assert classify_pipeline('rm a.txt; rm b.txt').destructive_segments == 2
    assert classify_pipeline('echo hi; ls').destructive_segments == 0
    assert classify_pipeline('git status; git log').destructive_segments == 0
