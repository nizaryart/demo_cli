r"""One file was never bounded, on the door that opens most often.

    if kind in ("sqlite", "file"):
        ...
        shutil.copy2(ref, bak)        # no cap, ever

Both caps lived inside snapshot()'s DIRECTORY branch (recovery.py, the
_walk_cost block). The file branch measured nothing, so a 6 GB SQLite database
or model file was copied in full - and copied AGAIN on every edit, because
there is no dedup and `prune` is manual (cli.py, nothing calls
recovery.prune).

WHY THAT IS NOT MERELY UNTIDY. The hook timeout was measured on 2026-09-16:
when the host kills a hook it runs the command unguarded and says NOTHING - a
crashed hook it announces, a timed-out one it does not. So an unbounded copy is
not a slow guard, it is a silent absent one. That is the same argument that
justified the directory file-count cap, applied to the branch it skipped.

WHAT THIS DELIBERATELY DOES NOT ADD: the file-COUNT cap. One file is one file.
For a single copy bytes bound the time as well as the disk, so a second
instrument would measure nothing new.

THE TRADE-OFF, STATED. A SQLite database is a first-class target of this tool
and 256 MB is not a large one. Past the cap a working REVERSIBLE becomes an
ESCALATE that names the knob. That is deliberate: the alternative is spending
the user's disk without asking, once per edit, unbounded - and over-blocking
that says which knob to turn is recoverable, while a silently filled disk is
not.
"""
import os

import pytest

from demo_cli import recovery
from demo_cli.config import Config
from demo_cli.guard import Guard

TINY_CAP_MB = "0.001"          # 1,048 bytes
OVER = b"x" * 20_000


@pytest.fixture
def capped(tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", TINY_CAP_MB)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _snap(path, recovery_dir, kind="file", notes=None):
    return recovery.snapshot(recovery.Target(kind=kind, ref=str(path),
                                             label=os.path.basename(str(path))),
                             str(recovery_dir), "snapshot", notes=notes)


# ------------------------------------------------------------------ the bound

def test_a_file_over_the_cap_is_refused(capped):
    """THE DEFECT. Against HEAD this returned an entry and copied the file."""
    f = capped / "big.db"
    f.write_bytes(OVER)
    assert _snap(f, capped / "rec") is None, (
        "a file past the byte cap was snapshotted anyway")


def test_nothing_is_left_behind_when_it_refuses(capped):
    """A refusal that has already written half a copy is not a refusal."""
    f = capped / "big.db"
    f.write_bytes(OVER)
    rec = capped / "rec"
    _snap(f, rec)
    assert not [p for p in (os.listdir(rec) if rec.exists() else [])
                if p.endswith(".bak")]


def test_a_file_under_the_cap_still_snapshots(capped):
    """The bound must not swallow the ordinary case."""
    f = capped / "small.txt"
    f.write_text("payload")
    entry = _snap(f, capped / "rec")
    assert entry is not None
    assert open(entry["recovery_point"]).read() == "payload"


def test_the_sqlite_kind_goes_through_the_same_bound(capped):
    """sqlite and file share the branch, so they share the cap."""
    f = capped / "app.sqlite"
    f.write_bytes(OVER)
    assert _snap(f, capped / "rec", kind="sqlite") is None


def test_the_default_cap_leaves_ordinary_files_alone(tmp_path, monkeypatch):
    """No env override: a normal source file must not come near the bound."""
    monkeypatch.delenv("DEMO_CLI_MAX_SNAPSHOT_MB", raising=False)
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.py"
    f.write_text("print(1)\n" * 1000)
    assert _snap(f, tmp_path / "rec") is not None


# ------------------------------------------------------------------ the words

def test_the_refusal_names_the_size_and_the_knob(capped):
    notes = {}
    f = capped / "big.db"
    f.write_bytes(OVER)
    _snap(f, capped / "rec", notes=notes)
    assert "refused" in notes, "the one actionable refusal said nothing"
    assert "DEMO_CLI_MAX_SNAPSHOT_MB" in notes["refused"]
    assert "big.db" in notes["refused"]


def test_it_reaches_the_person_through_the_file_edit_door(capped):
    """End to end: the bound is only useful if the agent's user is told."""
    f = capped / "big.db"
    f.write_bytes(OVER)
    g = Guard(config=Config(mode="enforce", project_root=str(capped)))
    d = g.evaluate_file_edit(str(f), tool_name="Write").decision
    assert d.decision == "ESCALATE"
    assert "DEMO_CLI_MAX_SNAPSHOT_MB" in d.reason, (
        f"the bound fired silently: {d.reason!r}")


def test_a_missing_file_is_still_just_absent(capped):
    """The getsize call must not turn "no such file" into a cap story."""
    notes = {}
    assert _snap(capped / "gone.db", capped / "rec", notes=notes) is None
    assert notes == {}
