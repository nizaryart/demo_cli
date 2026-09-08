"""One broken symlink disabled the recovery layer for a whole project.

Found by review 2026-09-08. Two findings, one root cause: shutil.copytree
defaults to symlinks=False, which FOLLOWS every link and copies what it points
at.

    F8  a DANGLING link raised shutil.Error out of Guard.evaluate. The Claude
        Code adapter fails open on its own errors - deliberately, so a bug
        here cannot brick the agent - so the hook printed "internal error,
        stepping aside" and let the delete run with NO snapshot and NO block.
        Not a visible crash: a silent, project-wide fail-open, triggered by an
        entirely ordinary condition. Build trees and node_modules are full of
        broken links.

    F7  the size cap stopped bounding anything. _dir_size walks with os.walk,
        which does NOT descend symlinked directories, so a link to a 2 MB tree
        measured as ~0 and copied as 2 MB - four times a 0.5 MB cap. The
        measurement and the copy disagreed about what a tree contains.

symlinks=True fixes both, and is the more faithful capture besides: `rm link`
destroys the link, not its target, so restoring a link is correct and
restoring a regular file full of the target's bytes never was.

The try/except stays regardless of the flag. "Degrade, never crash" is the
contract; returning None means no recovery point, which escalates - loudly,
and without a claim.
"""
import os
import shutil
import tempfile

import pytest

from demo_cli import recovery
from demo_cli.guard import Guard


def _symlinks_available() -> bool:
    """Can this process CREATE a symlink? Not the same as "is this POSIX".

    Windows needs Administrator or Developer Mode for os.symlink and returns
    WinError 1314 otherwise. Probed rather than assumed from os.name, so these
    tests still run on a Windows box that has it enabled - the fix matters
    there as much as anywhere, and gating on the platform would silently give
    that up.
    """
    with tempfile.TemporaryDirectory() as d:
        try:
            os.symlink(os.path.join(d, "target"), os.path.join(d, "link"))
            return True
        except (OSError, NotImplementedError, AttributeError):
            return False


# NOTE THE HONEST CONSEQUENCE: where this skips, the symlink half of the fix
# is UNVERIFIED. Encountering a symlink needs no privilege even where creating
# one does, so the defect is reachable on such a machine and the test simply
# cannot reach it. The two tests that mock a copy failure are not gated and do
# run everywhere.
requires_symlinks = pytest.mark.skipif(
    not _symlinks_available(),
    reason="creating a symlink needs Administrator or Developer Mode here "
           "(WinError 1314); the fix is unverified on this machine")


@pytest.fixture()
def proj(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    p = tmp_path / "proj"
    p.mkdir()
    (p / "a.py").write_text("code")
    (p / "b.py").write_text("more")
    monkeypatch.chdir(tmp_path)
    return p


# --------------------------------------------------------------------------
# F8: the guard must not crash, and must not step aside.
# --------------------------------------------------------------------------

@requires_symlinks
def test_a_dangling_symlink_does_not_take_the_guard_down(proj):
    os.symlink("/nonexistent/target", proj / "dangling")
    r = Guard(mode="enforce").evaluate('rm proj/a.py proj/b.py')
    assert r.decision.decision == "REVERSIBLE"
    assert r.recovery_entry, "no snapshot: the guard stepped aside"


@requires_symlinks
def test_the_dangling_link_is_captured_as_a_link(proj):
    os.symlink("/nonexistent/target", proj / "dangling")
    r = Guard(mode="enforce").evaluate('rm proj/a.py proj/b.py')
    held = os.path.join(r.recovery_entry["recovery_point"], "dangling")
    assert os.path.islink(held), "captured as something other than a link"
    assert os.readlink(held) == "/nonexistent/target"


def test_a_copy_failure_still_degrades_instead_of_raising(proj, monkeypatch):
    """symlinks=True removes the known cause; the guard around the copy is for
    the unknown ones. Pinned separately so nobody removes it as redundant now
    that the symlink case is handled."""
    def boom(*a, **k):
        raise shutil.Error("simulated copy failure")
    monkeypatch.setattr(shutil, "copytree", boom)
    r = Guard(mode="enforce").evaluate('rm proj/a.py proj/b.py')
    assert r.decision.decision == "ESCALATE"
    assert not r.recovery_entry


def test_the_file_branch_is_guarded_too(proj, monkeypatch):
    """snapshot() wrapped neither copy2 nor copytree. Both now."""
    def boom(*a, **k):
        raise OSError("simulated copy failure")
    monkeypatch.setattr(shutil, "copy2", boom)
    r = Guard(mode="enforce").evaluate('rm proj/a.py')
    assert r.decision.decision == "ESCALATE"
    assert not r.recovery_entry


# --------------------------------------------------------------------------
# F7: what is measured must be what is copied.
# --------------------------------------------------------------------------

@requires_symlinks
def test_a_symlinked_tree_is_not_copied_past_the_cap(tmp_path, monkeypatch):
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    heavy = tmp_path / "heavy"
    heavy.mkdir()
    (heavy / "big.bin").write_bytes(b"\0" * (2 * 1024 * 1024))
    p = tmp_path / "proj"
    p.mkdir()
    (p / "a.py").write_text("a")
    (p / "b.py").write_text("b")
    os.symlink(str(heavy), p / "link_to_heavy")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0.5")

    measured = recovery._dir_size(str(p), 512 * 1024)
    r = Guard(mode="enforce").evaluate('rm proj/a.py proj/b.py')
    rp = r.recovery_entry["recovery_point"]
    copied = sum(os.path.getsize(os.path.join(root, f))
                 for root, _, files in os.walk(rp) for f in files)

    assert copied <= 512 * 1024, f"copied {copied} bytes past a 512 KB cap"
    assert abs(copied - measured) < 4096, \
        f"measurement ({measured}) and copy ({copied}) disagree"


# --------------------------------------------------------------------------
# Restore has to speak the same language the snapshot now writes.
# --------------------------------------------------------------------------

@requires_symlinks
def test_a_captured_link_is_restored_as_a_link(proj):
    os.symlink("/nonexistent/target", proj / "dangling")
    r = Guard(mode="enforce").evaluate('rm proj/a.py proj/b.py')
    os.remove(proj / "a.py")
    os.remove(proj / "dangling")

    assert recovery.restore_entry(r.recovery_entry) is True
    assert (proj / "a.py").exists()
    assert os.path.islink(proj / "dangling"), \
        "restored as a regular file, or not at all"
