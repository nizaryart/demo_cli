"""A snapshot that silently omits part of the damage, and looks complete.

Found by review 2026-09-08.

    rm proj/.git/config proj/src/a.py

collapses to `proj` and captures it - without `.git`, because IGNORED_DIRS
excludes it. The snapshot holds src/a.py and nothing else, `undo` restores
half the damage, and the recovery entry has NO FIELD recording the omission.
That last part is what makes it a lie rather than a limitation: nothing
distinguishes it from a complete capture.

The ignore list is a sensible default - copying .git and node_modules on every
rm is expensive and they are usually reconstructible. It stops being sensible
the moment the command NAMES something inside one. An ignore is a default, not
a rule.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def proj(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    p = tmp_path / "proj"
    (p / ".git").mkdir(parents=True)
    (p / "src").mkdir()
    (p / "node_modules").mkdir()
    (p / ".git" / "config").write_text("THE GIT CONFIG")
    (p / "src" / "a.py").write_text("code")
    (p / "src" / "b.py").write_text("more code")
    (p / "node_modules" / "x.js").write_text("dep")
    monkeypatch.chdir(tmp_path)
    return p


def _snapshot_contents(entry):
    rp = (entry or {}).get("recovery_point")
    if not rp or not os.path.isdir(rp):
        return None
    out = []
    for root, _, files in os.walk(rp):
        out += [os.path.relpath(os.path.join(root, f), rp) for f in files]
    return sorted(out)


def test_a_named_file_inside_an_ignored_dir_is_captured(proj):
    """The headline. .git/config is named in the command, so it is part of the
    damage and must be part of the capture."""
    r = Guard(mode="enforce").evaluate('rm proj/.git/config proj/src/a.py')
    assert r.decision.decision == "REVERSIBLE"
    held = _snapshot_contents(r.recovery_entry)
    assert held is not None, "no directory snapshot was taken"
    assert os.path.join(".git", "config") in held, \
        f"the snapshot omits a file the command names: {held}"


def test_the_ignore_list_still_applies_when_nothing_reaches_into_it(proj):
    """The capability this must not cost. A normal delete must not start
    copying node_modules and .git on every call."""
    r = Guard(mode="enforce").evaluate('rm proj/src/a.py proj/src/b.py')
    held = _snapshot_contents(r.recovery_entry)
    assert held is not None
    assert not any(h.startswith(".git") or h.startswith("node_modules")
                   for h in held), held


@pytest.mark.parametrize("cmd,expected", [
    ('rm proj/.git/config proj/src/a.py',        {".git"}),
    ('rm proj/node_modules/x.js proj/src/a.py',  {"node_modules"}),
    ('rm proj/src/a.py proj/src/b.py',           set()),
])
def test_only_the_directories_actually_reached_into_are_un_ignored(proj, cmd, expected):
    assert set(recovery.unignorable_dirs(cmd)) == expected, cmd


@pytest.mark.parametrize("cmd", [
    'rm .demo_cli/receipts.jsonl x.txt',
    'rm proj/.demo_cli/a proj/src/a.py',
])
def test_the_recovery_store_is_never_un_ignored(proj, cmd):
    """Un-ignoring it would copy the backup into the backup. And `rm
    .demo_cli/something` is a request to DELETE recovery points, not a reason
    to duplicate them."""
    assert set(recovery.unignorable_dirs(cmd)) == set(), cmd


def test_exceeding_the_cap_escalates_rather_than_capturing_part(proj, monkeypatch):
    """Including .git can make the capture too large. The honest outcome is no
    snapshot and an escalation - which snapshot() already produces by
    returning None, so this needed no extra code. Pinned because the fix would
    be worthless if it silently fell back to the partial capture."""
    big = proj / ".git" / "pack.bin"
    big.write_bytes(b"\0" * (3 * 1024 * 1024))
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "1")
    r = Guard(mode="enforce").evaluate('rm proj/.git/pack.bin proj/src/a.py')
    assert r.decision.decision == "ESCALATE"
    assert not r.recovery_entry, "a partial capture was reported as a recovery"


def test_an_unmodellable_cd_does_not_guess_at_reachable_dirs(proj):
    """Same contract as everywhere else: if we cannot work out where the
    operands point, we do not claim to know which ignores to lift."""
    assert set(recovery.unignorable_dirs('cd $D && rm .git/config a.py')) == set()
