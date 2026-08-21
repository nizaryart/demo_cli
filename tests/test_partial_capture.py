"""Trou #004: an rm/mv whose full operand set cannot be resolved must ESCALATE,
not falsely claim REVERSIBLE via a partial .db-name snapshot. Confirmed
end-to-end by divergence_harness.py; these lock in the decision-level behaviour.
"""
import os
import sqlite3

from demo_cli.guard import Guard
from demo_cli.config import Config


def _decision(cmd, root):
    cfg = Config(project_root=str(root), mode="enforce")
    return Guard(config=cfg, mode="enforce").evaluate(cmd).decision.decision


def test_command_substitution_escalates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "keeper.db").write_text("k")
    (tmp_path / "extra.txt").write_text("e")
    (tmp_path / "targets.txt").write_text("extra.txt\n")
    # $() targets are invisible to the expander -> partial capture -> escalate
    assert _decision("rm -f keeper.db $(cat targets.txt)", tmp_path) == "ESCALATE"


def test_globstar_escalates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.db").write_text("d")
    os.makedirs(tmp_path / "logs", exist_ok=True)
    (tmp_path / "logs" / "a.log").write_text("x")
    assert _decision("rm -rf app.db logs/**", tmp_path) == "ESCALATE"


def test_single_file_still_reversible(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.db").write_text("d")
    assert _decision("rm -f app.db", tmp_path) == "REVERSIBLE"


def test_glob_dir_superset_still_reversible(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs(tmp_path / "data", exist_ok=True)
    (tmp_path / "data" / "a.txt").write_text("a")
    (tmp_path / "data" / "b.txt").write_text("b")
    # a countable single-level glob still snapshots the common dir (superset)
    assert _decision("rm -rf data/*", tmp_path) == "REVERSIBLE"


def test_sqlite_delete_still_reversible(tmp_path, monkeypatch):
    # the .db fallback is only disabled for rm/mv - a real SQL command must
    # still resolve its sqlite target and stay reversible.
    monkeypatch.chdir(tmp_path)
    con = sqlite3.connect(str(tmp_path / "app.db"))
    con.execute("CREATE TABLE t(x)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    assert _decision('sqlite3 app.db "DELETE FROM t"', tmp_path) in ("REVERSIBLE", "DRY_RUN")
