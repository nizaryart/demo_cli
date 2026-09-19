import os
import sqlite3

from demo_cli import recovery


def _make_db(path):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (id INTEGER, name TEXT)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(1, "a"), (2, "b"), (3, "c")])
    con.commit()
    con.close()


def test_no_default_target(tmp_path, monkeypatch):
    # A destructive command with nothing to resolve must yield no target.
    monkeypatch.chdir(tmp_path)
    assert recovery.resolve_target("rm -rf ./build") is None


def test_resolve_named_db(tmp_path):
    db = tmp_path / "app.db"
    _make_db(str(db))
    t = recovery.resolve_target(f"sqlite3 {db} 'DELETE FROM t'")
    assert t is not None and t.kind == "sqlite" and t.ref == str(db)


def test_resolve_postgres_url():
    t = recovery.resolve_target("psql postgres://u:p@h/db -c 'DELETE FROM t'")
    assert t.kind == "postgres" and t.ref.startswith("postgres://")


def test_snapshot_and_restore_sqlite(tmp_path):
    db = tmp_path / "app.db"
    _make_db(str(db))
    rec_dir = str(tmp_path / "rec")
    target = recovery.Target("sqlite", str(db), str(db))
    entry = recovery.snapshot(target, rec_dir)
    assert entry and os.path.exists(entry["recovery_point"])

    # mutate then restore
    con = sqlite3.connect(str(db))
    con.execute("DELETE FROM t")
    con.commit()
    con.close()
    assert recovery.snapshot is not None
    assert recovery.restore_entry(entry) is True
    con = sqlite3.connect(str(db))
    assert con.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 3
    con.close()


def test_snapshot_strategy_none_captures_nothing(tmp_path):
    db = tmp_path / "app.db"
    _make_db(str(db))
    target = recovery.Target("sqlite", str(db), str(db))
    assert recovery.snapshot(target, str(tmp_path / "rec"), strategy="none") is None


# --------------------------------------------------------------------------
# Operand extraction dispatches on the SEGMENT, not the whole command line
#
# Every rule in extract_path_operand is anchored to the start of its input
# (`^\s*...rm\b`), because a bare `rm` has to be a command word and not the
# middle of a filename. Applied to a whole LINE that anchor also demanded the
# verb come first, so anything chained in front matched nothing at all:
#
#     cd build && rm -rf ./out           -> None, escalated
#     Write-Host hi; Remove-Item a.txt   -> None, escalated
#
# Never dangerous - an unresolved target escalates, so the action was blocked
# rather than run unsnapshotted - but `cd x && rm y` is what agents actually
# write, and a guard that blocks the common case instead of protecting it gets
# uninstalled. Found on Windows 2026-08-25 by a PowerShell test that should
# never have been platform-gated: the logic is pure string handling and the
# failure reproduced on Linux immediately.
# --------------------------------------------------------------------------
import pytest

from demo_cli.classify import POSIX, POWERSHELL


@pytest.fixture
def files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.txt").write_text("out")
    return tmp_path


@pytest.mark.parametrize("cmd", [
    "rm a.txt",
    "echo hi; rm a.txt",
    "cd . && rm a.txt",          # restored by step 2 of the cd fix
    "echo one; echo two; rm a.txt",
    "cat a.txt | grep x; rm a.txt",
    "echo hi & rm a.txt",
    "rm a.txt &",
    "echo one & echo two & rm a.txt",
])
def test_a_chained_rm_still_resolves_its_target(files, cmd):
    assert recovery.extract_path_operand(cmd, POSIX) == "a.txt"


def test_a_chained_rm_in_a_subdirectory_resolves(files):
    assert recovery.extract_path_operand("cd . && rm build/out.txt", POSIX) \
        == "build/out.txt"


@pytest.mark.parametrize("cmd", [
    "Remove-Item a.txt",
    "Write-Host hi; Remove-Item a.txt",
    '$t = "a.txt"; Remove-Item $t',
])
def test_a_chained_powershell_delete_still_resolves(files, cmd):
    assert recovery.extract_path_operand(cmd, POWERSHELL) == "a.txt"


def test_a_chained_clear_content_resolves(files):
    assert recovery.extract_path_operand(
        "Write-Host hi; Clear-Content a.txt", POWERSHELL) == "a.txt"


def test_two_destructive_segments_resolve_to_nothing(files):
    """THE honesty rule. Picking the first would snapshot a.txt and let b.txt
    die unrecorded while the receipt claimed a recovery - the partial-recovery
    lie FIX #5 exists to prevent."""
    assert recovery.extract_path_operand("rm a.txt; rm b.txt", POSIX) is None


def test_two_destructive_segments_in_powershell_resolve_to_nothing(files):
    assert recovery.extract_path_operand(
        "Remove-Item a.txt; Remove-Item b.txt", POWERSHELL) is None


def test_a_safe_command_before_a_destructive_one_is_not_the_target(files):
    """`cd /tmp && rm a.txt` must not snapshot /tmp - the words of the leading
    command used to leak in as operands.

    IT MUST ALSO NOT SNAPSHOT THE LOCAL a.txt, and that half was asserted
    backwards. The old assertion demanded "a.txt", i.e. the file in the CURRENT
    directory - but the shell deletes /tmp/a.txt. It pinned a wrong-file
    snapshot as correct behaviour, which is how the defect survived (2026-09-08).

    The honest assertion is about what it must NOT be. Whether it resolves to
    /tmp/a.txt (step 2, if that file exists) or to nothing (step 1) is a
    capability question; naming the wrong file is a correctness one.
    """
    got = recovery.extract_path_operand("cd /tmp && rm a.txt", POSIX)
    assert got != "a.txt", "resolved to the local file, not the one being deleted"
    assert got != os.path.abspath("a.txt")
    assert got in (None, "/tmp/a.txt", os.path.join("/tmp", "a.txt"))


def test_a_command_with_no_destructive_segment_resolves_to_nothing(files):
    assert recovery.extract_path_operand("echo hi; ls -la", POSIX) is None


def test_audit_recovery_artifacts_detects_missing_and_corrupt(tmp_path):
    rec_dir = str(tmp_path / "rec")
    os.makedirs(rec_dir, exist_ok=True)

    e1 = recovery.snapshot_bytes("a.txt", b"hello world", rec_dir)
    assert e1 is not None

    e2 = recovery.snapshot_bytes("empty.txt", b"temp", rec_dir)
    with open(e2["recovery_point"], "wb") as f:
        pass

    e3 = recovery.snapshot_bytes("missing.txt", b"will delete", rec_dir)
    os.remove(e3["recovery_point"])

    res = recovery.audit_recovery_artifacts(rec_dir)
    assert not res.ok
    assert res.total_active == 3
    assert res.intact == 1
    assert e2["id"] in res.corrupt
    assert e3["id"] in res.missing


def test_verify_fails_on_missing_artifact(tmp_path, capsys):
    from demo_cli import cli
    from types import SimpleNamespace
    rec_dir = str(tmp_path / ".demo_cli" / "recovery")
    os.makedirs(rec_dir, exist_ok=True)
    e = recovery.snapshot_bytes("file.txt", b"bytes", rec_dir)
    os.remove(e["recovery_point"])

    ret = cli.cmd_verify(SimpleNamespace(root=str(tmp_path), anchor=False))
    assert ret == 1
    out = capsys.readouterr().out
    assert "MISSING ARTIFACTS" in out
    assert "snapshot(s) NOT on disk" in out
    assert e["id"] in out

