"""Whole-workspace checkpointing: the answer to "I cannot tell WHAT you will
destroy."

When a command mutates something and no target can be resolved from its text -
`rm $(cat list.txt)`, `rm $TARGET` with the assignment out of reach - the guard
escalates. That is honest, and it is also the branch that gets a tool
uninstalled. Checkpointing offers the other answer: preserve everything the
command could destroy, and if that cannot be done honestly, escalate exactly as
before.

The tests below are as much about what it REFUSES as what it captures. A
checkpoint that did not complete must never be reported as a recovery, and a
surface a directory copy cannot recover - a remote database, a force-pushed
branch - must not be offered one.

Runs on both platforms.
"""
import os

import pytest

from demo_cli import checkpoint, recovery
from demo_cli.config import Config
from demo_cli.guard import Guard


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A project with history, regenerable output, and something worth losing."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main")
    (tmp_path / "node_modules" / "left-pad").mkdir(parents=True)
    (tmp_path / "node_modules" / "left-pad" / "index.js").write_text("x" * 500)
    (tmp_path / "src" / "__pycache__").mkdir(parents=True)
    (tmp_path / "src" / "__pycache__" / "a.pyc").write_text("junk")
    (tmp_path / "src" / "app.py").write_text("print(1)")
    (tmp_path / "notes.txt").write_text("irreplaceable")
    (tmp_path / "list.txt").write_text("notes.txt\n")
    return tmp_path


def guard(root, **ck):
    return Guard(Config(mode="enforce", project_root=str(root), checkpoint=ck))


def contents(snapdir):
    return {os.path.relpath(os.path.join(d, f), snapdir).replace(os.sep, "/")
            for d, _, fs in os.walk(snapdir) for f in fs}


# --------------------------------------------------------------------------
# Off unless asked
# --------------------------------------------------------------------------

def test_checkpointing_is_off_by_default(workspace):
    """Copying a workspace before a command is a real cost. A guard that
    becomes slow without being asked is a guard that gets uninstalled."""
    r = guard(workspace).evaluate("rm $(cat list.txt)", agent_id="t", session_id="t")
    assert r.receipt.decision == "ESCALATE"
    assert not r.receipt.recovery_point


def test_enabling_it_turns_that_escalation_into_a_recovery(workspace):
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert r.receipt.decision == "REVERSIBLE"
    assert r.receipt.recovery_point.endswith(".snapdir")


# --------------------------------------------------------------------------
# What goes into the copy
# --------------------------------------------------------------------------

def test_git_is_included_because_nothing_else_holds_it(workspace):
    """recovery.IGNORED_DIRS omits .git from ordinary snapshots, which is right
    for a targeted capture. A checkpoint claims "everything you could destroy
    is preserved", and a script that deletes .git falsifies that. History is
    the one thing in a workspace that cannot be rebuilt from the rest of it.
    """
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert ".git/HEAD" in contents(r.receipt.recovery_point)


@pytest.mark.parametrize("regenerable", ["node_modules", "__pycache__"])
def test_regenerable_output_is_excluded(workspace, regenerable):
    """The rule is "can this be rebuilt from what the checkpoint DOES hold?".
    node_modules comes back from package.json; .pyc files from the .py files."""
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert not any(regenerable in p for p in contents(r.receipt.recovery_point))


def test_the_working_tree_is_captured(workspace):
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    got = contents(r.receipt.recovery_point)
    assert {"notes.txt", "src/app.py"} <= got


def test_the_checkpoint_ignore_set_is_derived_not_retyped():
    """recovery.py warns that three copies of this list had already drifted
    apart. The difference here is deliberate, so it is expressed AS a
    difference rather than as a second hand-written list."""
    assert checkpoint.CHECKPOINT_IGNORE == recovery.IGNORED_DIRS - {".git"}
    assert ".git" not in checkpoint.CHECKPOINT_IGNORE


# --------------------------------------------------------------------------
# Never a first choice
# --------------------------------------------------------------------------

def test_a_resolvable_target_still_gets_a_precise_snapshot(workspace):
    """The checkpoint is the fallback. Copying the whole workspace on top of a
    perfectly good one-file snapshot would be pure waste."""
    r = guard(workspace, enabled=True).evaluate("rm notes.txt",
                                                agent_id="t", session_id="t")
    assert r.receipt.decision == "REVERSIBLE"
    assert not r.receipt.recovery_point.endswith(".snapdir")


def test_a_read_is_never_checkpointed(workspace):
    r = guard(workspace, enabled=True).evaluate("ls", agent_id="t", session_id="t")
    assert not r.receipt.recovery_point


def test_a_nonrecoverable_surface_is_never_offered_a_checkpoint(workspace):
    """THE condition that matters most. `git push --force` destroys history on
    a server; copying the local working tree recovers none of it. Letting a
    checkpoint stand in for that recovery would be exactly the lie this tool
    exists to prevent."""
    r = guard(workspace, enabled=True).evaluate("git push --force",
                                                agent_id="t", session_id="t")
    assert r.receipt.decision == "ESCALATE"
    assert not r.receipt.recovery_point


# --------------------------------------------------------------------------
# Refuse rather than lie
# --------------------------------------------------------------------------

def test_a_workspace_over_the_cap_is_refused(workspace, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0.00001")   # ~10 bytes: below the fixture
    res = checkpoint.capture(Config(project_root=str(workspace),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.skipped == checkpoint.TOO_LARGE
    assert res.entry is None


def test_the_size_check_measures_what_the_copy_will_include(tmp_path):
    """If the measurement skips a directory the copy then includes, the cap
    bounds nothing. Before this was parameterised, _dir_size held a hardcoded
    list that excluded .git - so a 3 MB repository measured as 0 MB and the
    "256 MB cap" would have copied it regardless."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "pack").write_text("x" * (2 * 1024 * 1024))
    cap = 1 * 1024 * 1024
    assert recovery._dir_size(tmp_path, cap) < cap, "default ignore skips .git"
    assert recovery._dir_size(tmp_path, cap, checkpoint.CHECKPOINT_IGNORE) > cap


def test_the_home_directory_is_refused_however_small_it_measures():
    res = checkpoint.capture(Config(project_root=os.path.expanduser("~"),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.skipped == checkpoint.TOO_BROAD


def test_a_missing_project_root_is_refused():
    res = checkpoint.capture(Config(project_root=os.path.join("nowhere", "at", "all"),
                                    checkpoint={"enabled": True}), "rm $T")
    assert res.skipped == checkpoint.NO_ROOT


def test_a_refusal_leaves_the_escalation_exactly_as_it_was(workspace, monkeypatch):
    """The module can only ever turn an escalation into a recovery. It must
    never turn a refusal into an allow on the strength of a partial copy."""
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0.00001")   # ~10 bytes: below the fixture
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert r.receipt.decision == "ESCALATE"
    assert not r.receipt.recovery_point


def test_a_refusal_explains_itself_actionably(workspace, monkeypatch):
    monkeypatch.setenv("DEMO_CLI_MAX_SNAPSHOT_MB", "0.00001")   # ~10 bytes: below the fixture
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert "DEMO_CLI_MAX_SNAPSHOT_MB" in r.receipt.reason


# --------------------------------------------------------------------------
# Saying that the recovery is coarse
# --------------------------------------------------------------------------

def test_the_receipt_says_the_recovery_is_a_coarse_checkpoint(workspace):
    """Undo on a checkpoint restores the ENTIRE tree, rolling back unrelated
    edits made afterwards. Someone reading the receipt has to be able to tell
    that from a one-file snapshot."""
    r = guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                                agent_id="t", session_id="t")
    assert "checkpoint" in r.receipt.reason.lower()
    assert "coarse" in r.receipt.reason.lower()


def test_a_checkpoint_is_an_ordinary_recovery_entry(workspace):
    """undo, log, diff and verify must need no special case for these - the
    same property snapshot_bytes was built for on the WinFsp side."""
    guard(workspace, enabled=True).evaluate("rm $(cat list.txt)",
                                            agent_id="t", session_id="t")
    entries = recovery.load_entries(str(workspace / ".demo_cli" / "recovery"))
    assert len(entries) == 1
    assert set(entries[0]) == {"id", "kind", "target", "recovery_point", "ts", "action"}
    assert entries[0]["kind"] == "dir"


def test_undo_restores_the_workspace_from_a_checkpoint(workspace):
    """End to end: destroy something the guard could not name, and get it back."""
    g = guard(workspace, enabled=True)
    r = g.evaluate("rm $(cat list.txt)", agent_id="t", session_id="t")
    (workspace / "notes.txt").unlink()          # the command runs for real
    (workspace / "src" / "app.py").unlink()

    entry = recovery.load_entries(str(workspace / ".demo_cli" / "recovery"))[0]
    assert recovery.restore_entry(entry) is True
    assert (workspace / "notes.txt").read_text() == "irreplaceable"
    assert (workspace / "src" / "app.py").read_text() == "print(1)"


# --------------------------------------------------------------------------
# should_checkpoint, directly
# --------------------------------------------------------------------------

def test_should_checkpoint_requires_the_feature_to_be_on():
    from demo_cli.classify import Classification
    c = Classification(is_destructive=True)
    assert not checkpoint.should_checkpoint(c, None, Config())
    assert checkpoint.should_checkpoint(c, None, Config(checkpoint={"enabled": True}))


def test_should_checkpoint_declines_when_a_snapshot_already_exists():
    from demo_cli.classify import Classification
    c = Classification(is_destructive=True)
    cfg = Config(checkpoint={"enabled": True})
    assert not checkpoint.should_checkpoint(c, None, cfg, recovery_captured=True)
