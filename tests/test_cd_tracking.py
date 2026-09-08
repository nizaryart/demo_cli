"""`cd build && rm -rf ./out` snapshotted the wrong directory.

Found by review 2026-09-08, and it is the only defect so far that captured a
REAL, WRONG file. Everything else either captured nothing or captured too
much; this one produced a recovery point full of innocent data, so `undo`
would have restored it OVER whatever was there.

    cd build && rm -rf ./out
      deleted:      <cwd>/build/out
      snapshotted:  <cwd>/out          an unrelated directory
      reported:     REVERSIBLE

It was a regression, which is the part worth remembering. Before 2026-08-25
the anchored rule was applied to the whole line, matched nothing here, and the
command escalated - safe but useless. Moving to per-segment matching gained
resolution and lost correctness: a nuisance traded for a lie.

Fixed in two steps. Step 1 refused every relative operand after a `cd`, which
closed the lie immediately and over-escalated. Step 2 - this file - folds the
`cd`s and resolves against the directory the shell will actually be in.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    (tmp_path / "build" / "out").mkdir(parents=True)
    (tmp_path / "build" / "out" / "data.txt").write_text("THE REAL DATA")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "keep.txt").write_text("INNOCENT - must not be captured")
    (tmp_path / "build" / "out.log").write_text("real log")
    (tmp_path / "out.log").write_text("innocent log")
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    (tmp_path / "a" / "b" / "c" / "t.txt").write_text("deep")
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------
# It resolves the right file, and specifically not the innocent one.
# --------------------------------------------------------------------------

def test_the_snapshot_follows_the_cd(lab):
    got = recovery.extract_path_operand('cd build && rm -rf ./out')
    assert os.path.samefile(got, lab / "build" / "out")
    assert not os.path.samefile(got, lab / "out"), "captured the innocent directory"


def test_the_guard_snapshots_the_file_that_actually_dies(lab):
    r = Guard(mode="enforce").evaluate('cd build && rm -rf ./out')
    assert r.decision.decision == "REVERSIBLE"
    assert os.path.samefile(r.recovery_entry["target"], lab / "build" / "out")


def test_a_redirect_follows_the_cd_too(lab):
    """The same wrong-directory bug hit the redirect path, and would have been
    missed by fixing only operand extraction."""
    tgt, resolved = recovery.resolve_redirect_target('cd build && echo x > out.log')
    assert resolved
    assert os.path.samefile(tgt, lab / "build" / "out.log")


@pytest.mark.parametrize("cmd,expected", [
    ('cd a && cd b && cd c && rm t.txt',      "a/b/c/t.txt"),
    ('cd a/b && cd ../.. && rm -rf out',      "out"),
    ('cd a && cd - && rm -rf out',            "out"),
    ('cd ./a/./b && rm -rf ../../out',        "out"),
])
def test_hops_compose(lab, cmd, expected):
    """normpath(join(cwd, arg)) composes, so any number of hops works and
    `..`, `.` and `-` come for free. bash's default cd is logical (-L), which
    is what normpath does, so the two agree."""
    got = recovery.extract_path_operand(cmd)
    assert got and os.path.samefile(got, lab / expected), f"{cmd} -> {got}"


# --------------------------------------------------------------------------
# What it refuses, and why each one cannot be modelled.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,why", [
    ('cd $D && rm -rf ./out',        "the argument is unexpanded"),
    ('cd $(cat d.txt) && rm -rf ./out', "command substitution"),
    ('(cd build && rm -rf ./out)',   "subshell: the cd does not outlive it"),
    ('cd build | rm -rf ./out',      "pipeline: each side is its own subshell"),
    ('pushd build && rm -rf ./out',  "a directory stack we do not model"),
    ('cd nowhere && rm -rf ./out',   "the target is not a directory"),
    ('cd a b && rm -rf ./out',       "two arguments is an error, not a hop"),
])
def test_what_cannot_be_modelled_is_refused_not_guessed(lab, cmd, why):
    assert recovery.extract_path_operand(cmd) is None, f"{cmd}: {why}"


def test_cdpath_makes_every_hop_unresolvable(lab, monkeypatch):
    """With CDPATH set, `cd foo` can land somewhere entirely different. Rare,
    but silent - so it is checked rather than assumed absent."""
    monkeypatch.setenv("CDPATH", "/usr")
    assert recovery.effective_cwd('cd build && rm x', ['cd build', 'rm x'], 1) is None


# --------------------------------------------------------------------------
# The blast radius. Everything without a cd must be untouched.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,expected", [
    ('rm -rf ./out',                  "out"),
    ('echo hi; rm -rf ./out',         "out"),
    ('cd . && rm out/keep.txt',       "out/keep.txt"),
    ('cd build && rm -rf ' + os.sep.join(("", "tmp")), None),   # absolute, unaffected
])
def test_commands_without_a_real_move_are_unchanged(lab, cmd, expected):
    """`base` stays None whenever the effective cwd equals the real one, so
    the overwhelming majority of commands take exactly the path they took
    before - including a no-op `cd .`, which returns a RELATIVE operand as it
    always did."""
    got = recovery.extract_path_operand(cmd)
    if expected is None:
        assert got is None or os.path.isabs(got)
    else:
        assert got and os.path.samefile(got, lab / expected), f"{cmd} -> {got}"


def test_the_undecidable_case_is_documented_not_hidden(lab):
    """`cd x ; rm y` depends on whether the cd SUCCEEDED, which is a runtime
    fact. Requiring the directory to exist now reduces that to a race rather
    than a guess - pinned so the mitigation is not removed as redundant."""
    assert recovery.extract_path_operand('cd build ; rm -rf ./out') is not None
    assert recovery.extract_path_operand('cd nowhere ; rm -rf ./out') is None
