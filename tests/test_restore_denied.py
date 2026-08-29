"""Undo must not report "unrecoverable" when it means "not allowed".

Found live on Windows, 2026-08-29. The filesystem guard writes its recovery
points into the ACL-locked backing - deliberately, because that is what stops
the agent from deleting the evidence of what it did. The consequence nobody
had traced: an unelevated `demo_cli undo` cannot READ them, restore_entry()
collapsed the PermissionError into False, and the user was told

    ESCALATE - No recovery point could be restored.
    The recovery point is present but could not be written back -
    check the target path is reachable.

about a file that was intact on disk, with a target path that was perfectly
reachable. A FALSE NEGATIVE from the one command somebody runs after they have
already lost something - and they only got the file back by guessing to open
an admin shell.

An unearned "REVERSIBLE" and an unearned "unrecoverable" break the same
invariant. Only the direction differs, and only one of them is dressed as
caution.
"""
import os

import pytest

from demo_cli import recovery


def _entry(tmp_path, content=b"irreplaceable"):
    rp = tmp_path / "store" / "notes.txt.bak"
    rp.parent.mkdir(parents=True)
    rp.write_bytes(content)
    return {"kind": "file", "recovery_point": str(rp),
            "target": str(tmp_path / "proj" / "notes.txt")}


# --------------------------------------------------------------------------
# the happy path is unchanged
# --------------------------------------------------------------------------

def test_a_readable_recovery_point_restores(tmp_path):
    entry = _entry(tmp_path)
    r = recovery.restore(entry)
    assert r.ok and not r.denied
    assert open(entry["target"], "rb").read() == b"irreplaceable"


def test_no_entry_is_not_a_denial(tmp_path):
    r = recovery.restore(None)
    assert not r.ok and not r.denied


def test_a_missing_recovery_point_is_not_a_denial(tmp_path):
    """"Gone" and "not allowed" must not render the same. Only one of them is
    fixed by elevating."""
    entry = _entry(tmp_path)
    os.unlink(entry["recovery_point"])
    r = recovery.restore(entry)
    assert not r.ok and not r.denied
    assert "missing" in (r.problem or "")


# --------------------------------------------------------------------------
# the denial, which is the whole point
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt",
                    reason="chmod does not restrict files on Windows; the real "
                           "case there is an Administrators-only ACL")
@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                    reason="root can read anything, so nothing is denied")
def test_an_unreadable_recovery_point_reports_denied_not_missing(tmp_path):
    """THE REGRESSION. The bytes exist; we simply may not read them."""
    entry = _entry(tmp_path)
    os.chmod(entry["recovery_point"], 0o000)
    try:
        r = recovery.restore(entry)
        assert not r.ok
        assert r.denied, "an elevated retry would work - say so"
        assert "read" in (r.problem or "")
    finally:
        os.chmod(entry["recovery_point"], 0o644)


@pytest.mark.skipif(os.name == "nt", reason="chmod does not restrict directories on Windows")
@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else False,
                    reason="root can write anywhere")
def test_an_unwritable_target_reports_denied(tmp_path):
    entry = _entry(tmp_path)
    target_parent = tmp_path / "proj"
    target_parent.mkdir()
    os.chmod(target_parent, 0o555)
    try:
        r = recovery.restore(entry)
        assert not r.ok and r.denied
    finally:
        os.chmod(target_parent, 0o755)


def test_restore_entry_still_returns_a_plain_bool(tmp_path):
    """restore() is additive. Thirteen call sites and the syscall guard use
    restore_entry(), and widening its contract to carry an error would have
    touched all of them for no gain."""
    entry = _entry(tmp_path)
    assert recovery.restore_entry(entry) is True


# --------------------------------------------------------------------------
# what the user is shown
# --------------------------------------------------------------------------

def test_a_denial_is_not_rendered_as_unrecoverable(tmp_path, capsys):
    from demo_cli import render
    entry = _entry(tmp_path)
    render.render_restore(entry, False, "test", denied=True,
                          problem="x cannot be read from this shell")
    out = capsys.readouterr().out
    assert "Administrator" in out, "say what would fix it"
    assert "intact" in out, "say the file is not lost"
    assert "No recovery point could be restored" not in out, \
        "that sentence is false when the bytes are there"


def test_a_genuine_failure_still_says_so(tmp_path, capsys):
    from demo_cli import render
    entry = _entry(tmp_path)
    render.render_restore(entry, False, "test", denied=False)
    out = capsys.readouterr().out
    assert "No recovery point could be restored" in out
    assert "Administrator" not in out, "do not send people to UAC for nothing"


# --------------------------------------------------------------------------
# undo must not destroy what it overwrites
#
# The last unguarded mutation in the system. Everything an agent does is
# snapshotted first; `undo` overwrote a file with no recovery point of its
# own, so restore -> new work -> restore again lost the new work with nothing
# to go back to. A once-only rule would not have caught it: a DIFFERENT id for
# the same file does the same damage and has never been used.
# --------------------------------------------------------------------------

def test_undo_snapshots_what_it_is_about_to_overwrite(tmp_path):
    entry = _entry(tmp_path, b"OLD")
    target = tmp_path / "proj" / "notes.txt"
    target.parent.mkdir()
    target.write_bytes(b"NEW WORK")

    kept = recovery.snapshot_before_restore(entry, str(tmp_path / "rec"))
    assert kept, "live content must not be overwritten without a recovery point"
    assert open(kept["recovery_point"], "rb").read() == b"NEW WORK"
    assert kept["target"] == str(target)
    assert "undo" in (kept["action"] or "")


def test_the_kept_copy_restores_the_new_work(tmp_path):
    """The whole point: undo the undo."""
    entry = _entry(tmp_path, b"OLD")
    target = tmp_path / "proj" / "notes.txt"
    target.parent.mkdir()
    target.write_bytes(b"NEW WORK")

    kept = recovery.snapshot_before_restore(entry, str(tmp_path / "rec"))
    assert recovery.restore(entry).ok
    assert target.read_bytes() == b"OLD"          # the undo happened
    assert recovery.restore(kept).ok
    assert target.read_bytes() == b"NEW WORK"     # and is itself reversible


def test_identical_bytes_are_not_snapshotted(tmp_path):
    """A recovery point recording no change is noise, and noise is how a real
    one gets missed."""
    entry = _entry(tmp_path, b"SAME")
    target = tmp_path / "proj" / "notes.txt"
    target.parent.mkdir()
    target.write_bytes(b"SAME")
    assert recovery.snapshot_before_restore(entry, str(tmp_path / "rec")) is None


def test_a_missing_target_is_not_snapshotted(tmp_path):
    """Restoring a DELETED file - the common case - has nothing to preserve."""
    entry = _entry(tmp_path)
    assert recovery.snapshot_before_restore(entry, str(tmp_path / "rec")) is None


def test_no_entry_is_handled(tmp_path):
    assert recovery.snapshot_before_restore(None, str(tmp_path / "rec")) is None


def test_a_directory_entry_is_left_alone(tmp_path):
    """Known gap, stated rather than half-done: a 'dir' entry restores by
    copytree overlay and would need snapshot() plus a Target. Every recovery
    point the filesystem guard writes is a file."""
    d = tmp_path / "tree"
    d.mkdir()
    entry = {"kind": "dir", "recovery_point": str(d), "target": str(tmp_path / "t")}
    assert recovery.snapshot_before_restore(entry, str(tmp_path / "rec")) is None
