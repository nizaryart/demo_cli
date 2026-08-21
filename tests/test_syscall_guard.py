"""Behavioral (syscall) guard tests. Linux-only: ptrace is a Linux feature.

These prove the thesis of the layer: destruction the STRING classifier misses
(obfuscation, indirection) is still snapshotted at the syscall level, and the
snapshot is a real, restorable recovery point reusing recovery.py.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="syscall guard requires Linux (ptrace)")

from demo_cli import recovery                       # noqa: E402
from demo_cli.classify import classify              # noqa: E402
from demo_cli.config import Config                  # noqa: E402


def _run(argv, tmp_path):
    from demo_cli import syscall_guard
    # Hermetic: if the developer has the shell guard installed, BASH_ENV would
    # make an inner `bash -c` re-fire the shell guard and double-handle - clear
    # it so these tests exercise the syscall guard alone.
    os.environ.pop("BASH_ENV", None)
    cfg = Config(project_root=str(tmp_path))
    rc = syscall_guard.run_supervised(argv, config=cfg)
    return cfg, rc


def test_plain_rm_snapshotted_and_restorable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data.txt").write_text("PRECIOUS")
    cfg, rc = _run(["rm", "-f", "data.txt"], tmp_path)
    assert rc == 0
    assert not (tmp_path / "data.txt").exists()             # rm actually ran
    entries = recovery.load_entries(cfg.recovery_dir)
    assert entries, "a recovery point should have been captured"
    assert recovery.restore_entry(entries[-1]) is True      # and it restores
    assert (tmp_path / "data.txt").read_text() == "PRECIOUS"


def test_obfuscated_rm_string_misses_syscall_catches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "db.sqlite").write_text("ROWS")
    payload = r"$'\x72\x6d' -f db.sqlite"                    # $'\x72\x6d' -> rm
    # the STRING guard is blind to it ...
    assert classify(payload).is_destructive is False
    # ... the SYSCALL guard is not.
    cfg, _ = _run(["bash", "-c", payload], tmp_path)
    entries = recovery.load_entries(cfg.recovery_dir)
    assert entries and entries[-1]["kind"] == "file"


def test_sourced_file_indirection_is_caught(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "victim").write_text("x")
    (tmp_path / "del.sh").write_text("rm -f victim\n")
    assert classify("source del.sh").is_destructive is False  # string guard blind
    cfg, _ = _run(["bash", "-c", "source del.sh"], tmp_path)
    assert recovery.load_entries(cfg.recovery_dir), "syscall guard should catch it"


def test_redirect_truncation_snapshotted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "log.txt").write_text("OLD LOGS")
    cfg, _ = _run(["bash", "-c", "echo new > log.txt"], tmp_path)
    entries = recovery.load_entries(cfg.recovery_dir)
    assert entries, "openat(O_TRUNC) overwrite should be snapshotted"
    assert recovery.restore_entry(entries[-1]) is True
    assert (tmp_path / "log.txt").read_text() == "OLD LOGS"


def test_command_own_tempfile_not_snapshotted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # the command creates AND removes t.tmp itself -> it is not pre-existing
    # data, so the guard must not snapshot it (noise control).
    cfg, _ = _run(["bash", "-c", "echo x > t.tmp; rm -f t.tmp"], tmp_path)
    assert recovery.load_entries(cfg.recovery_dir) == []


def test_out_of_scope_path_ignored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("not in project")
    try:
        cfg, _ = _run(["rm", "-f", str(outside)], tmp_path)
        # deleted, but outside project_root -> no snapshot claimed
        assert recovery.load_entries(cfg.recovery_dir) == []
    finally:
        if outside.exists():
            outside.unlink()


def test_deny_mode_blocks_the_delete(tmp_path, monkeypatch):
    from demo_cli import syscall_guard
    monkeypatch.chdir(tmp_path)
    (tmp_path / "keep.txt").write_text("SURVIVES")
    cfg = Config(project_root=str(tmp_path))
    syscall_guard.run_supervised(["rm", "-f", "keep.txt"], config=cfg, deny=True)
    # blocked before it ran -> the file is untouched, and nothing is "recovered"
    assert (tmp_path / "keep.txt").read_text() == "SURVIVES"
    assert recovery.load_entries(cfg.recovery_dir) == []
