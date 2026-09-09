r"""The preview said "no files affected" for deletions about to happen.

F12 of the 2026-09-08 review. `expanded_operands` matched `_RM_RE` - anchored
at `^\s*` - against the whole LINE, so anything before the rm hid it:

    cd x && rm -rf a b        preview: (nothing)
    echo hi; rm -rf a b       preview: (nothing)
    bash -c "rm -rf a b"      preview: (nothing)

The snapshot was correct throughout. Only the display lied, which is why no
test caught it - and it is worse than it sounds, because this is the surface
built FOR claude-code#76626, where the agent's stated goal was to COUNT the
files. A preview answering "none" is the wrong answer to the exact question
that incident was about.

THE FIRST FIX REINTRODUCED IT, NARROWER. The shared helper resolved the
working directory once, as of the END of the line, so a trailing `cd` moved it
and `./out` resolved against the wrong directory. Caught in review before
commit; see test_a_trailing_cd_does_not_hide_the_files.

Note the failure shape, because it explains why nothing noticed: the operand
list is filtered by exists(), so a WRONG BASE cannot surface as a wrong path -
only as a missing one. Silence is this bug's only symptom.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "build" / "out").mkdir(parents=True)
    (tmp_path / "build" / "out" / "keep.txt").write_text("k")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _names(cmd):
    return sorted(os.path.basename(p) for p in recovery.expanded_operands(cmd))


# --------------------------------------------------------------------------
# The anchor: anything before the rm used to hide it.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'rm -rf a.txt b.txt',
    'echo hi; rm -rf a.txt b.txt',
    'cat a.txt | grep x; rm -rf a.txt b.txt',
    'bash -c "rm -rf a.txt b.txt"',
    'rm a.txt; rm b.txt',
])
def test_the_preview_finds_the_files_wherever_the_rm_sits(lab, cmd):
    assert _names(cmd) == ["a.txt", "b.txt"], cmd


# --------------------------------------------------------------------------
# The regression the first fix introduced. These fail against it.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'cd build && rm -rf ./out',
    'cd build && rm -rf ./out && cd ..',
    'cd build && rm -rf ./out; cd /tmp',
])
def test_a_trailing_cd_does_not_hide_the_files(lab, cmd):
    """The base must be the directory in force AT THE rm's SEGMENT, not at the
    end of the line. A `cd` after the deletion is irrelevant to it."""
    got = recovery.expanded_operands(cmd)
    assert got and os.path.samefile(got[0], lab / "build" / "out"), f"{cmd} -> {got}"


def test_the_snapshot_and_the_preview_agree(lab):
    """They disagreed for a whole release: the snapshot resolved per segment,
    the preview per line. Both now use _base_at, and this pins that they
    cannot drift again."""
    cmd = 'cd build && rm -rf ./out && cd ..'
    assert os.path.samefile(recovery.extract_path_operand(cmd),
                            recovery.expanded_operands(cmd)[0])


def test_cd_dot_does_not_exercise_base_resolution(lab):
    """KEPT WITH A WARNING. `cd . && rm ...` passes whether or not base
    resolution works, because the effective cwd equals the real one and base
    stays None. It exercises the segment walk only. The base tests are the
    ones above, with a real move - noted because two earlier tests in this
    project passed for exactly this kind of reason."""
    assert _names('cd . && rm -rf a.txt b.txt') == ["a.txt", "b.txt"]


# --------------------------------------------------------------------------
# The count is the product. #76626 was about a count.
# --------------------------------------------------------------------------

def test_one_file_named_twice_counts_once(lab):
    """A string dedupe reported "files matched: 2" for a single file."""
    assert recovery.expanded_operands('rm a.txt; rm ./a.txt') == \
        [os.path.normpath(str(lab / "a.txt"))]


def test_every_path_has_the_same_shape(lab):
    """Relative in one case and absolute in another made render's redact()
    show the same file two ways, depending on whether a cd appeared."""
    for cmd in ('rm -rf a.txt b.txt', 'cd build && rm -rf ./out'):
        got = recovery.expanded_operands(cmd)
        assert got and all(os.path.isabs(p) for p in got), f"{cmd} -> {got}"


def test_the_order_is_deterministic(lab):
    """glob order is os.scandir order - stable on one filesystem, not
    guaranteed across them. An unsorted preview is a test that passes here and
    fails on someone else's machine."""
    got = recovery.expanded_operands('rm -rf *.txt')
    assert got == sorted(got)


# --------------------------------------------------------------------------
# Negative pins. These guard properties of effective_segments, not of this
# change - which is exactly why they would rot unnoticed.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'echo "rm -rf a.txt"',
    'git commit -m "rm -rf a.txt"',
    'cd $D && rm -rf a.txt',
    'ls -la',
    'echo hi',
])
def test_the_preview_never_names_a_file_nothing_will_touch(lab, cmd):
    """If segment unwrapping is ever widened, the preview starts naming files
    no command will delete - and nothing else in the suite would catch it."""
    assert recovery.expanded_operands(cmd) == [], cmd


def test_an_escalating_command_still_shows_what_was_at_stake(lab):
    """Two destructive segments escalate, and the preview still lists both.
    Suppressing it there would make the display least informative at the
    moment a person most needs it - and the count feeds the hook."""
    r = Guard(mode="enforce").evaluate('rm a.txt; rm b.txt')
    assert r.decision.decision == "ESCALATE"
    assert sorted(os.path.basename(p) for p in r.affected_paths) == ["a.txt", "b.txt"]
