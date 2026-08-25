"""The recovery INDEX: the ledger that finds your files.

receipts.jsonl is hash-chained, locked and fsynced, because it proves what
happened. recovery/index.jsonl decides whether anything can be given back, and
until 2026-08-25 it was a bare `open(..., "a")` and one `write` - no lock, no
flush, no fsync. Three defects, all found by using the tool rather than by
testing it, all on the RESTORE side rather than the capture side:

  * a write interrupted before its newline let the NEXT append land on the
    same line, and load_entries silently dropped both records. Observed in a
    real index. A recovery point that exists on disk but cannot be found
    through the ledger is indistinguishable from one never taken.
  * a recursive delete removes files first and their directory second, so by
    the time anyone runs undo the parent is gone and copy2 has nowhere to
    write. Bytes captured perfectly, restore impossible.
  * "No recovery points found" named neither the id nor the directory
    searched, so a ledger written by a guard started from a different
    directory looked exactly like data loss.
"""
import json
import os
import shutil

import pytest

from demo_cli import recovery


# --------------------------------------------------------------------------
# Durable append
# --------------------------------------------------------------------------

def _entry(rid):
    return {"id": rid, "kind": "file", "target": f"/x/{rid}",
            "recovery_point": f"/rec/{rid}.bak", "ts": "20260825-000000",
            "action": None}


def test_a_truncated_line_does_not_swallow_the_next_record(tmp_path):
    """THE regression test. A line with no newline is what a killed process
    leaves behind; the append that follows must start on a line of its own."""
    d = str(tmp_path)
    idx = os.path.join(d, "index.jsonl")
    open(idx, "w").write('{"id": "aaa", "kind": "file", "target": "x", "rec')

    recovery._record(d, _entry("bbb"))

    assert [e["id"] for e in recovery.load_entries(d)] == ["bbb"], \
        "only the broken record should be lost, not the one written after it"


def test_the_healed_index_is_still_valid_jsonl(tmp_path):
    d = str(tmp_path)
    open(os.path.join(d, "index.jsonl"), "w").write('{"id": "aaa", "trunc')
    recovery._record(d, _entry("bbb"))
    recovery._record(d, _entry("ccc"))
    assert [e["id"] for e in recovery.load_entries(d)] == ["bbb", "ccc"]


def test_records_survive_a_normal_sequence(tmp_path):
    d = str(tmp_path)
    for rid in ("aaa", "bbb", "ccc"):
        recovery._record(d, _entry(rid))
    assert [e["id"] for e in recovery.load_entries(d)] == ["aaa", "bbb", "ccc"]


def test_every_line_ends_with_a_newline(tmp_path):
    """The property the healing depends on. If an append can leave the file
    without a trailing newline, the next one corrupts a record."""
    d = str(tmp_path)
    recovery._record(d, _entry("aaa"))
    recovery._record(d, _entry("bbb"))
    assert open(os.path.join(d, "index.jsonl"), "rb").read().endswith(b"\n")


def test_concurrent_appends_do_not_interleave(tmp_path):
    """winfspy dispatches filesystem operations from a THREAD POOL, so two
    snapshots really can append at the same moment."""
    import threading
    d = str(tmp_path)
    threads = [threading.Thread(target=recovery._record, args=(d, _entry(f"id{i:03d}")))
               for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    entries = recovery.load_entries(d)
    assert len(entries) == 24, "a lost record means two writers overlapped"
    assert len({e["id"] for e in entries}) == 24


# --------------------------------------------------------------------------
# Restore: where the bytes actually land
# --------------------------------------------------------------------------

def test_undo_recreates_a_parent_removed_by_a_recursive_delete(tmp_path):
    """Confirmed live on Windows: three files captured from a shutil.rmtree,
    and two of them could not be restored - not because anything was missing,
    but because tree/ no longer existed."""
    (tmp_path / "tree" / "sub").mkdir(parents=True)
    target = tmp_path / "tree" / "sub" / "b.txt"
    target.write_text("two")

    entry = recovery.snapshot_bytes("b.txt", b"two", str(tmp_path / "rec"),
                                    target=str(target))
    shutil.rmtree(tmp_path / "tree")
    assert not target.parent.exists()

    assert recovery.restore_entry(entry) is True
    assert target.read_text() == "two"


def test_a_target_that_cannot_be_written_still_returns_false(tmp_path):
    """Creating the parent must not turn every failure into a raise. cmd_undo
    has no try/except."""
    entry = recovery.snapshot_bytes("x.txt", b"x", str(tmp_path / "rec"),
                                    target="\0/impossible/x.txt")
    assert recovery.restore_entry(entry) is False


def test_restoring_does_not_disturb_an_existing_sibling(tmp_path):
    """makedirs(exist_ok=True) must create only what is missing."""
    (tmp_path / "tree").mkdir()
    keep = tmp_path / "tree" / "keep.txt"
    keep.write_text("untouched")
    entry = recovery.snapshot_bytes("gone.txt", b"back", str(tmp_path / "rec"),
                                    target=str(tmp_path / "tree" / "gone.txt"))
    assert recovery.restore_entry(entry) is True
    assert keep.read_text() == "untouched"


# --------------------------------------------------------------------------
# Saying where we looked
# --------------------------------------------------------------------------

def test_a_missing_id_reports_the_ledger_it_searched(capsys):
    """Twenty minutes went into "No recovery points found" while three intact
    recovery points sat in a different directory. The path is the whole fix."""
    from demo_cli import render
    render.render_restore(None, False, "test",
                          recovery_dir="/tmp/somewhere/.demo_cli/recovery",
                          requested_id="f8fead25")
    out = capsys.readouterr().out
    assert "f8fead25" in out, "name the id that did not match"
    assert "/tmp/somewhere/.demo_cli/recovery" in out, "name the ledger searched"


def test_a_found_entry_that_fails_to_restore_says_so_differently(capsys):
    """Two different failures - "I could not find it" and "I found it and
    could not write it back" - need two different messages."""
    from demo_cli import render
    render.render_restore({"target": "/x/notes.txt", "kind": "file"}, False, "test",
                          recovery_dir="/tmp/rec")
    out = capsys.readouterr().out
    assert "No recovery point could be restored" in out
    assert "No recovery point matched" not in out, "that is the other failure"
    assert "notes.txt" in out


def test_a_successful_restore_is_unchanged(capsys):
    from demo_cli import render
    render.render_restore({"target": "/x/notes.txt", "kind": "file",
                           "recovery_point": "/rec/notes.txt.bak"},
                          True, "test", recovery_dir="/tmp/rec")
    out = capsys.readouterr().out
    assert "RESTORED" in out and "notes.txt" in out
