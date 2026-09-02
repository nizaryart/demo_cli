"""The filesystem layer has to be visible to the agent it is guarding.

Background: on 2026-09-02 an agent ran ten scripted tasks on a guarded Windows
project and reported four snapshotted deletions as "irreversible destructions
that went through uncaught". It was right that nothing stopped them - the fs
layer does not block - and wrong that nothing caught them. It had no channel
to find out: the fs guard's output goes to a log inside the Administrators-only
backing directory.

fsreport is that channel. These tests pin the properties that make it
trustworthy: report each capture once, never raise, and survive the malformed
lines the receipts chain currently contains.
"""
import json
import os

import pytest

from demo_cli import fsreport
from demo_cli.config import Config


def _cfg(tmp_path):
    return Config(project_root=str(tmp_path))


def _receipt(tmp_path, *, agent, action, stamp, recovery_point=None):
    cfg = _cfg(tmp_path)
    os.makedirs(cfg.workspace, exist_ok=True)
    row = {"agent_id": agent, "action_raw": action, "timestamp": stamp,
           "recovery_point": recovery_point, "reason": "test"}
    with open(cfg.receipts_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


RP = r"C:\p.real\.demo_cli\recovery\notes.txt.20260902-130619.f12f7c5e.bak"


def test_nothing_to_report_is_empty_not_an_error(tmp_path):
    assert fsreport.pending(_cfg(tmp_path)) == []
    assert fsreport.summary(_cfg(tmp_path)) == ""


def test_a_capture_is_reported_with_its_undo_id(tmp_path):
    _receipt(tmp_path, agent="fsguard", action="[fs] delete notes.txt",
             stamp="2026-09-02T12:06:19Z", recovery_point=RP)
    lines = fsreport.pending(_cfg(tmp_path))
    assert len(lines) == 1
    assert "delete notes.txt" in lines[0]
    assert "demo_cli undo f12f7c5e" in lines[0]


def test_each_capture_is_reported_exactly_once(tmp_path):
    """The marker is the whole point: repeating every capture on every command
    is noise, and noise is how a real warning gets missed."""
    _receipt(tmp_path, agent="fsguard", action="[fs] delete a.txt",
             stamp="2026-09-02T12:00:00Z", recovery_point=RP)
    assert len(fsreport.pending(_cfg(tmp_path))) == 1
    assert fsreport.pending(_cfg(tmp_path)) == []

    _receipt(tmp_path, agent="fsguard", action="[fs] delete b.txt",
             stamp="2026-09-02T12:00:01Z", recovery_point=RP)
    lines = fsreport.pending(_cfg(tmp_path))
    assert len(lines) == 1 and "b.txt" in lines[0]


def test_mark_false_does_not_consume(tmp_path):
    _receipt(tmp_path, agent="fsguard", action="[fs] delete a.txt",
             stamp="2026-09-02T12:00:00Z", recovery_point=RP)
    cfg = _cfg(tmp_path)
    assert fsreport.pending(cfg, mark=False)
    assert fsreport.pending(cfg, mark=False)


def test_only_the_filesystem_layer_is_reported(tmp_path):
    """The agent's own commands are already visible to it; echoing them back
    would bury the one thing it cannot otherwise see."""
    _receipt(tmp_path, agent="claude-code", action="rm -rf x",
             stamp="2026-09-02T12:00:00Z", recovery_point=RP)
    _receipt(tmp_path, agent="egress", action="POST example.com",
             stamp="2026-09-02T12:00:01Z")
    assert fsreport.pending(_cfg(tmp_path)) == []


def test_a_capture_with_no_recovery_point_says_so(tmp_path):
    """An unsnapshotted delete is the one the agent most needs to hear about.
    Reporting it as if it were recoverable would be the same lie in reverse."""
    _receipt(tmp_path, agent="fsguard", action="[fs] delete big.bin",
             stamp="2026-09-02T12:00:00Z", recovery_point=None)
    line = fsreport.pending(_cfg(tmp_path))[0]
    assert "NOT snapshotted" in line
    assert "undo" not in line


def test_torn_lines_are_skipped_not_fatal(tmp_path):
    """receipts.jsonl really does contain malformed lines: the fs guard writes
    through the backing while the hook writes through the mount, and the two
    byte-range locks do not compose across WinFsp, so appends interleave.
    Until that is fixed this function must read past the damage."""
    cfg = _cfg(tmp_path)
    os.makedirs(cfg.workspace, exist_ok=True)
    with open(cfg.receipts_path, "w", encoding="utf-8") as f:
        f.write('{"agent_id":"fsguard","action_raw":"[fs] delete a.txt",'
                '"timestamp":"2026-09-02T12:00:00Z","recovery_point":' +
                json.dumps(RP) + '}\n')
        f.write('nup with FspCleanupDelete.","receipt_hash":"b9f8"}\n')  # torn
        f.write('{"agent_id":"fsguard","action_raw":"[fs] delete b.txt",'
                '"timestamp":"2026-09-02T12:00:02Z","recovery_point":' +
                json.dumps(RP) + '}\n')
    lines = fsreport.pending(cfg)
    assert len(lines) == 2


def test_a_burst_is_capped_and_says_how_many_more(tmp_path):
    for i in range(12):
        _receipt(tmp_path, agent="fsguard", action=f"[fs] delete f{i}.txt",
                 stamp=f"2026-09-02T12:00:{i:02d}Z", recovery_point=RP)
    lines = fsreport.pending(_cfg(tmp_path))
    assert len(lines) == fsreport._MAX_SHOWN + 1
    assert "and 7 more" in lines[-1]


def test_an_unreadable_workspace_is_silent(tmp_path, monkeypatch):
    """A hook's own failure must never reach the user's agent."""
    _receipt(tmp_path, agent="fsguard", action="[fs] delete a.txt",
             stamp="2026-09-02T12:00:00Z", recovery_point=RP)

    def boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(fsreport, "_tail_lines", boom)
    assert fsreport.pending(_cfg(tmp_path)) == []


def test_the_summary_says_it_is_one_command_behind(tmp_path):
    """PreToolUse fires BEFORE the command runs, so these captures belong to
    the previous one. Implying otherwise would be a new version of the same
    dishonesty this module exists to fix."""
    _receipt(tmp_path, agent="fsguard", action="[fs] delete a.txt",
             stamp="2026-09-02T12:00:00Z", recovery_point=RP)
    assert "since your last command" in fsreport.summary(_cfg(tmp_path))


def test_a_long_file_is_not_read_whole(tmp_path):
    """The hook runs on every tool call; reading a 400 KB chain each time is a
    cost on a hot path. Only the tail is read, and a partial leading line from
    the seek must not break parsing."""
    cfg = _cfg(tmp_path)
    os.makedirs(cfg.workspace, exist_ok=True)
    with open(cfg.receipts_path, "w", encoding="utf-8") as f:
        for i in range(4000):
            f.write(json.dumps({"agent_id": "egress", "pad": "x" * 60,
                                "timestamp": f"2026-09-01T00:00:{i % 60:02d}Z"}) + "\n")
        f.write(json.dumps({"agent_id": "fsguard",
                            "action_raw": "[fs] delete late.txt",
                            "timestamp": "2026-09-02T12:00:00Z",
                            "recovery_point": RP}) + "\n")
    assert os.path.getsize(cfg.receipts_path) > fsreport._TAIL_BYTES
    lines = fsreport.pending(cfg)
    assert len(lines) == 1 and "late.txt" in lines[0]
