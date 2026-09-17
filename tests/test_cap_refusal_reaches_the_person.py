r"""A cap refusal is the one "no recovery point" a person can act on, and two
of the three doors kept it to themselves.

snapshot()'s own docstring says it: "Returning a bare None says only that there
is no recovery point; it cannot say the tree was too big, by how much, or which
knob to turn - and this is the one refusal a user can actually do something
about." It takes a `notes` dict to carry exactly that.

Only guard.evaluate ever passed one.

DOOR 2, the file-write tools. Measured on 2026-09-17, same tree, same cap:

    rm -rf bigdir   ESCALATE ... bigdir holds more than 2 files; capturing it
                    would outlast the agent's hook timeout ... Raise
                    DEMO_CLI_MAX_SNAPSHOT_FILES and the hook timeout together
    Write bigdir    ESCALATE  Could not snapshot the file before editing; no
                    recovery path.
                    steps: Check the file is readable and within the project root

The path IS readable and IS inside the project root. The advice was not merely
missing, it was false, and it sent the reader to check two things that were
fine. Every Edit / Write / MultiEdit / NotebookEdit and all of Codex's
apply_patch came through here.

DOOR 3, the checkpoint. capture() pre-checked BYTES only. A tree that passed
that and then tripped the FILE cap inside snapshot() came back as
`copy_failed`, whose text is "Checkpoint copy did not complete" - a copy that
never began, and no knob named. It now measures both budgets in one walk and
has its own reason.

NINTH INSTANCE in this project of an augmented reason reaching one caller and
the ledger and nobody else, after checkpoint.reason_text on 09-16.
"""
import os

import pytest

from demo_cli import checkpoint, recovery
from demo_cli.config import Config
from demo_cli.guard import Guard

CAP_FILES = "2"


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A project holding a directory of five files, against a cap of two."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_FILES", CAP_FILES)
    monkeypatch.chdir(tmp_path)
    big = tmp_path / "bigdir"
    big.mkdir()
    for i in range(5):
        (big / f"f{i}.txt").write_text("x")
    return tmp_path, big


def _guard(root):
    return Guard(config=Config(mode="enforce", project_root=str(root)))


# ------------------------------------------------------------------ door 2

def test_the_file_edit_door_names_the_cap_and_the_knob(tree):
    """THE DEFECT. Against HEAD the reason stopped at "no recovery path"."""
    root, big = tree
    d = _guard(root).evaluate_file_edit(str(big), tool_name="Write").decision
    assert d.decision == "ESCALATE"
    assert "more than 2 files" in d.reason, (
        f"the refusal did not reach the person: {d.reason!r}")
    assert "DEMO_CLI_MAX_SNAPSHOT_FILES" in d.reason, "no knob was named"


def test_the_file_edit_door_stops_giving_false_advice(tree):
    """The old next_steps sent the reader to check two things that were fine."""
    root, big = tree
    d = _guard(root).evaluate_file_edit(str(big), tool_name="Write").decision
    joined = " ".join(d.next_steps)
    assert "readable" not in joined, (
        f"still advising a check that cannot be the cause: {d.next_steps}")
    assert "Raise the cap" in joined


def test_both_doors_carry_the_same_refusal(tree):
    """One tree, one cap, two entry points - and the same sentence. Asserted on
    the refusal TEXT rather than on each door's wording, because the shared
    part is the only part that has to match."""
    root, big = tree
    g = _guard(root)
    shell = g.evaluate(f"rm -rf {big}").decision.reason
    edit = g.evaluate_file_edit(str(big), tool_name="Write").decision.reason
    needle = "holds more than 2 files"
    assert needle in shell and needle in edit


def test_an_ordinary_snapshot_failure_keeps_its_own_advice(tmp_path, monkeypatch):
    """The cap is not the only way a snapshot fails. A copy error is exactly
    the case the original wording was written for, and must keep it."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.py"
    f.write_text("payload")

    def boom(*a, **k):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(recovery.shutil, "copy2", boom)

    d = _guard(tmp_path).evaluate_file_edit(str(f), tool_name="Edit").decision
    assert d.decision == "ESCALATE"
    assert "readable" in " ".join(d.next_steps), (
        "a copy failure lost the advice that does apply to it")
    assert "DEMO_CLI_MAX_SNAPSHOT" not in d.reason, "named a cap that did not fire"


def test_a_capture_that_succeeds_is_unaffected(tmp_path, monkeypatch):
    """The notes channel must stay silent when there is nothing to say."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "app.py"
    f.write_text("payload")
    r = _guard(tmp_path).evaluate_file_edit(str(f), tool_name="Edit")
    assert r.decision.decision == "REVERSIBLE"
    assert "cap" not in r.decision.reason


# ------------------------------------------------------------------ door 3

def test_the_checkpoint_has_its_own_reason_for_the_file_cap(tree):
    """THE DEFECT. Against HEAD this was copy_failed - "copy did not complete"
    about a copy that was refused before it started."""
    root, _ = tree
    res = checkpoint.capture(Config(project_root=str(root),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.entry is None
    assert res.skipped == checkpoint.TOO_MANY_FILES, (
        f"a file-cap refusal was reported as {res.skipped!r}")


def test_that_checkpoint_reason_names_the_files_knob(tree):
    root, _ = tree
    text = checkpoint.reason_text(checkpoint.TOO_MANY_FILES,
                                  Config(project_root=str(root)))
    assert "DEMO_CLI_MAX_SNAPSHOT_FILES" in text
    assert "2 files" in text


def test_the_byte_cap_still_reports_too_large(tmp_path, monkeypatch):
    """Replacing _dir_size with _walk_cost must not move the byte verdict."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0.001")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "big.bin").write_bytes(b"x" * 20_000)
    res = checkpoint.capture(Config(project_root=str(tmp_path),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.skipped == checkpoint.TOO_LARGE


def test_a_workspace_inside_both_budgets_still_checkpoints(tmp_path, monkeypatch):
    """The walk now short-circuits on either budget; neither may fire here."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)")
    res = checkpoint.capture(Config(project_root=str(tmp_path),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.ok and res.skipped is None
