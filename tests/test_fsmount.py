"""The WinFsp filesystem layer - what can be checked without Windows.

The interception itself needs a real mount, so it is verified on Windows. What
is testable here is everything that must hold BEFORE that: the module must
import safely on any platform, refuse clearly rather than crash obscurely, and
its snapshot plumbing must produce ordinary recovery entries that undo and
verify already understand.

The Linux-only syscall guard is gated the same way, for the same reason.
"""
import os

import pytest

from demo_cli import fsmount, recovery


# --------------------------------------------------------------------------
# Importable everywhere, active nowhere it shouldn't be
# --------------------------------------------------------------------------

def test_importing_on_any_platform_is_safe():
    """winfspy exists only on Windows. If it were imported at module scope the
    whole package would fail to load on Linux - the mistake syscall_guard
    avoids by never importing ctypes' libc until it is called."""
    assert hasattr(fsmount, "mount") and hasattr(fsmount, "build_operations")


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_reports_unavailable_off_windows():
    assert fsmount.available() is False


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_refusing_says_what_to_use_instead():
    """A refusal that leaves the user with nowhere to go is its own failure.
    Point them at the layer that DOES work on their platform."""
    with pytest.raises(RuntimeError) as e:
        fsmount.build_operations(config=None)
    message = str(e.value)
    assert "Windows" in message
    assert "demo_cli run" in message, "must name the Linux equivalent"


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_mount_refuses_rather_than_crashing():
    with pytest.raises(RuntimeError):
        fsmount.mount("/tmp/nowhere")


# --------------------------------------------------------------------------
# snapshot_bytes - capturing content held in memory rather than on disk
# --------------------------------------------------------------------------

def test_snapshot_bytes_writes_the_content(tmp_path):
    entry = recovery.snapshot_bytes(r"\notes.txt", b"original", str(tmp_path))
    assert entry is not None
    assert open(entry["recovery_point"], "rb").read() == b"original"


def test_snapshot_bytes_produces_an_ordinary_entry(tmp_path):
    """undo, log, diff and verify must not need a special case for these."""
    entry = recovery.snapshot_bytes(r"\src\app.py", b"x", str(tmp_path), action="delete")
    assert entry["kind"] == "file"
    assert entry["target"] == r"\src\app.py"
    assert set(entry) == {"id", "kind", "target", "recovery_point", "ts", "action"}


def test_snapshot_bytes_is_indexed_so_log_can_find_it(tmp_path):
    recovery.snapshot_bytes(r"\a.txt", b"1", str(tmp_path))
    recovery.snapshot_bytes(r"\b.txt", b"2", str(tmp_path))
    assert len(recovery.load_entries(str(tmp_path))) == 2


def test_snapshot_bytes_survives_a_windows_path_as_a_name(tmp_path):
    """The name arrives as a WinFsp virtual path with backslashes; only the
    basename should reach the filesystem."""
    entry = recovery.snapshot_bytes(r"\deep\nested\file.txt", b"x", str(tmp_path))
    assert os.path.basename(entry["recovery_point"]).startswith("file.txt.")


def test_snapshot_bytes_captures_empty_content(tmp_path):
    """Emptying a file is destruction; an empty snapshot is still a real one.
    Returning None here would report no recovery for a real loss."""
    entry = recovery.snapshot_bytes(r"\a.txt", b"", str(tmp_path))
    assert entry is not None
    assert open(entry["recovery_point"], "rb").read() == b""


def test_snapshot_bytes_refuses_when_there_is_nothing_to_capture(tmp_path):
    assert recovery.snapshot_bytes(r"\a.txt", None, str(tmp_path)) is None


# --------------------------------------------------------------------------
# Defect W5 - where a restore LANDS, not merely whether a snapshot was taken
#
# Found live on 2026-08-24, after 39 fsguard tests and 10 fsmount tests had
# passed. Every one of those asserts on the capture side, because that is the
# side we wrote. None asked the other question: `undo` said RESTORED - did the
# bytes arrive where the user is looking?
#
# They did not. WinFsp names paths relative to the mount, so the ledger stored
# 'notes.txt'; restore_entry copies to that string; run undo one directory up
# and the file lands outside the mount while the tool reports success. A
# recovery that claims to have happened and did not is the one failure class
# this project treats as unacceptable.
# --------------------------------------------------------------------------

def test_recorded_target_is_absolute_so_undo_cannot_land_elsewhere(tmp_path):
    """The regression test for W5.

    The mount point comes from tmp_path rather than being hand-built, because
    "absolute" is not the same shape on both platforms: on Windows a path must
    carry a DRIVE, so '\\mnt\\guarded' is drive-relative, not absolute, and
    ntpath.isabs has rejected it since Python 3.13. mount() gets this right via
    os.path.abspath; only a synthetic test input can get it wrong.
    """
    target = fsmount.absolute_target(str(tmp_path / "guarded"), "notes.txt")
    assert os.path.isabs(target), "a relative target resolves against cwd"
    assert target.endswith("notes.txt")


def test_nested_virtual_paths_keep_their_structure(tmp_path):
    mount = tmp_path / "guarded"
    target = fsmount.absolute_target(str(mount), "src/app.py")
    assert target == str(mount / "src" / "app.py")


def test_without_a_mountpoint_the_virtual_path_is_returned_unchanged():
    """Only reachable when the class is built directly, never via mount().
    Recording something wrong would be worse than recording something short."""
    assert fsmount.absolute_target(None, "notes.txt") == "notes.txt"


def test_undo_lands_in_the_same_place_whatever_the_cwd(tmp_path, monkeypatch):
    """The end-to-end shape of W5, reproduced without WinFsp.

    Capture as the mount would, then restore from an UNRELATED directory. With
    a relative target this wrote into that unrelated directory and returned
    True - the live failure, exactly.
    """
    mount = tmp_path / "guarded"
    mount.mkdir()
    (mount / "notes.txt").write_bytes(b"replaced")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    entry = recovery.snapshot_bytes(
        "notes.txt", b"original", str(tmp_path / "rec"),
        target=fsmount.absolute_target(str(mount), "notes.txt"))

    (mount / "notes.txt").unlink()
    monkeypatch.chdir(elsewhere)
    assert recovery.restore_entry(entry) is True

    assert (mount / "notes.txt").read_bytes() == b"original"
    assert not (elsewhere / "notes.txt").exists(), "restored to the wrong place"


def test_a_restore_that_cannot_write_reports_failure_instead_of_raising(tmp_path):
    """cmd_undo has no try/except, so an exception here is a traceback and the
    user learns nothing about whether their file came back. False renders as
    ESCALATE, which is the honest answer.

    The target here is under a FILE rather than a directory, so the parent
    cannot be created at all. A merely MISSING parent is no longer a failure:
    since 2026-08-25 restore_entry recreates it, because a recursive delete
    removes the directory too and every file captured from one was otherwise
    unrestorable - see test_ledger_durability.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    entry = recovery.snapshot_bytes(
        "notes.txt", b"original", str(tmp_path / "rec"),
        target=str(blocker / "notes.txt"))
    assert recovery.restore_entry(entry) is False
