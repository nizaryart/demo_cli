"""A snapshot must never copy a tree into itself.

Found 2026-08-29 while clearing a stray ledger out of a new project. The
command was an ordinary `rm -rf .demo_cli`; the shell guard classified it
destructive, tried to make it recoverable, and copytree'd the workspace into
the recovery directory that lives INSIDE the workspace. Fifteen levels of

    .demo_cli/recovery/....snapdir/recovery/....snapdir/...

stopped only by Windows MAX_PATH - after which `rm -rf` could not reach the
bottom to clean it up, and a script had to shorten each level first.

Neither existing safeguard applies:

  _IGNORE           skips directories NAMED .demo_cli. Here .demo_cli is the
                    SOURCE, and the colliding child is named `recovery`. A
                    name-based list cannot see the collision; only the
                    absolute path can.
  the size cap      _dir_size measures BEFORE the copy. The growth happens
                    during it, so the cap bounds nothing.

An agent can issue that command. The guard's own recovery path was a denial of
service against the guard.
"""
import os

from demo_cli import recovery
from demo_cli.recovery import Target


def _snap(ref, recovery_dir):
    return recovery.snapshot(Target(kind="dir", ref=str(ref), label=str(ref)),
                             str(recovery_dir))


def test_snapshotting_the_workspace_does_not_recurse(tmp_path):
    """THE REGRESSION. recovery_dir is inside the target."""
    ws = tmp_path / ".demo_cli"
    rec = ws / "recovery"
    rec.mkdir(parents=True)
    (ws / "receipts.jsonl").write_text('{"a":1}\n')

    entry = _snap(ws, rec)
    assert entry, "the rest of the workspace is still worth keeping"

    nested = [p for p in _all_dirs(rec) if p.count(".snapdir") > 1]
    assert not nested, f"copied into itself: {nested[:2]}"


def test_the_snapshot_keeps_everything_except_the_store(tmp_path):
    """Skipping the recovery store loses nothing - those files ARE the
    backups. Everything else must survive."""
    ws = tmp_path / ".demo_cli"
    rec = ws / "recovery"
    rec.mkdir(parents=True)
    (ws / "receipts.jsonl").write_text("LEDGER")
    (rec / "old.bak").write_text("an existing backup")

    entry = _snap(ws, rec)
    snap = entry["recovery_point"]
    assert open(os.path.join(snap, "receipts.jsonl")).read() == "LEDGER"
    assert not os.path.exists(os.path.join(snap, "recovery"))


def test_snapshotting_something_inside_the_store_is_refused(tmp_path):
    """Backing up a backup into the backup store is meaningless. Returning
    None makes decide() escalate honestly rather than claim a recovery."""
    rec = tmp_path / "recovery"
    inner = rec / "old.snapdir"
    inner.mkdir(parents=True)
    (inner / "f.txt").write_text("x")
    assert _snap(inner, rec) is None


def test_the_store_itself_is_refused(tmp_path):
    rec = tmp_path / "recovery"
    rec.mkdir()
    assert _snap(rec, rec) is None


def test_an_ordinary_directory_is_unaffected(tmp_path):
    """The normal case - recovery_dir OUTSIDE the target - must not change."""
    src = tmp_path / "proj"
    (src / "src").mkdir(parents=True)
    (src / "notes.txt").write_text("irreplaceable")
    (src / "src" / "app.py").write_text("print(1)")
    rec = tmp_path / "store"

    entry = _snap(src, rec)
    snap = entry["recovery_point"]
    assert open(os.path.join(snap, "notes.txt")).read() == "irreplaceable"
    assert os.path.exists(os.path.join(snap, "src", "app.py"))


def test_the_measurement_skips_what_the_copy_skips(tmp_path):
    """The cap only bounds the copy if both sides skip the same thing - the
    lesson from _dir_size's hardcoded ignore list on 2026-08-24, which
    measured a 3 MB .git as 0 MB."""
    ws = tmp_path / ".demo_cli"
    rec = ws / "recovery"
    rec.mkdir(parents=True)
    (ws / "small.txt").write_text("x" * 10)
    (rec / "big.bak").write_text("y" * 100_000)

    measured = recovery._dir_size(str(ws), 10 ** 9, None, skip_path=str(rec))
    assert measured < 1000, "the store must not count toward the cap"


def _all_dirs(root):
    out = []
    for dirpath, dirnames, _ in os.walk(str(root)):
        out.extend(os.path.join(dirpath, d) for d in dirnames)
    return out
