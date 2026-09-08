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
