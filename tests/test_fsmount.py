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
