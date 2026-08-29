"""A leftover mount point must not be permanent.

Found on the first real reboot test, 2026-08-29. The logon task refused with
"still exists and is not empty" on every boot, and the only way back was
`rmdir` by hand. Two separate defects, and both are covered here:

  1. `demo_cli doctor` CREATED the mount point. Its workspace-writable check
     called os.makedirs(<project>/.demo_cli), which creates the parents too -
     and on a protected Windows project the parent IS the mount point.
  2. `demo_cli mount` then refused on mere existence, so an empty leftover
     that held none of the user's bytes blocked the guard forever.

Both run on Linux: the judgement is plain path logic, and the fourth
platform-shaped test assumption in this project would have been to gate them
behind skipif(os.name != "nt").
"""
import os

import pytest

from demo_cli import config as config_mod
from demo_cli.config import Config
from demo_cli.fsmount import clear_mountpoint, mountpoint_obstruction


# --------------------------------------------------------------------------
# mountpoint_obstruction - what may be cleared, and what may not
# --------------------------------------------------------------------------

def test_missing_path_is_no_obstruction(tmp_path):
    assert mountpoint_obstruction(str(tmp_path / "nope")) is None


def test_empty_directory_is_no_obstruction(tmp_path):
    d = tmp_path / "mnt"
    d.mkdir()
    assert mountpoint_obstruction(str(d)) is None


def test_empty_workspace_leftover_is_no_obstruction(tmp_path):
    """THE REGRESSION. Exactly the state found after the reboot: the mount
    point exists, holding nothing but an empty .demo_cli that doctor made."""
    d = tmp_path / "mnt"
    (d / ".demo_cli").mkdir(parents=True)
    assert mountpoint_obstruction(str(d)) is None


def test_symlink_is_no_obstruction(tmp_path):
    """A dangling reparse point on Windows; a symlink is the closest thing
    testable here. Removing a link removes nothing - the bytes are in the
    backing directory."""
    target = tmp_path / "backing"
    target.mkdir()
    link = tmp_path / "mnt"
    link.symlink_to(target, target_is_directory=True)
    assert mountpoint_obstruction(str(link)) is None


def test_dangling_symlink_is_no_obstruction(tmp_path):
    link = tmp_path / "mnt"
    link.symlink_to(tmp_path / "gone", target_is_directory=True)
    assert mountpoint_obstruction(str(link)) is None


def test_user_files_are_an_obstruction(tmp_path):
    d = tmp_path / "mnt"
    d.mkdir()
    (d / "notes.txt").write_text("irreplaceable")
    reason = mountpoint_obstruction(str(d))
    assert reason and "notes.txt" in reason


def test_workspace_with_receipts_is_an_obstruction(tmp_path):
    """Not merely a leftover: receipts and recovery points are the evidence
    the whole tool exists to produce. Empty is the only safe case."""
    d = tmp_path / "mnt"
    (d / ".demo_cli").mkdir(parents=True)
    (d / ".demo_cli" / "receipts.jsonl").write_text("{}\n")
    reason = mountpoint_obstruction(str(d))
    assert reason and ".demo_cli" in reason


def test_file_is_an_obstruction(tmp_path):
    f = tmp_path / "mnt"
    f.write_text("x")
    reason = mountpoint_obstruction(str(f))
    assert reason and "file" in reason


def test_obstruction_message_is_truncated(tmp_path):
    d = tmp_path / "mnt"
    d.mkdir()
    for i in range(9):
        (d / f"f{i}.txt").write_text("x")
    reason = mountpoint_obstruction(str(d))
    assert reason and "..." in reason


def test_custom_workspace_dir_is_honoured(tmp_path):
    """A project that renamed [workspace] dir must get the same treatment -
    otherwise its own leftover reads as somebody's work."""
    d = tmp_path / "mnt"
    (d / ".guard").mkdir(parents=True)
    assert mountpoint_obstruction(str(d), workspace_dir=".guard") is None
    assert mountpoint_obstruction(str(d), workspace_dir=".demo_cli")


# --------------------------------------------------------------------------
# clear_mountpoint - removes exactly what was cleared, and no more
# --------------------------------------------------------------------------

def test_clear_missing_is_a_noop(tmp_path):
    assert clear_mountpoint(str(tmp_path / "nope")) is False


def test_clear_empty_directory(tmp_path):
    d = tmp_path / "mnt"
    d.mkdir()
    assert clear_mountpoint(str(d)) is True
    assert not d.exists()


def test_clear_removes_empty_workspace_leftover(tmp_path):
    d = tmp_path / "mnt"
    (d / ".demo_cli").mkdir(parents=True)
    assert clear_mountpoint(str(d)) is True
    assert not d.exists()


def test_clear_symlink_leaves_the_target_alone(tmp_path):
    """The junction case. Removing the pointer must not touch the bytes."""
    target = tmp_path / "backing"
    target.mkdir()
    (target / "notes.txt").write_text("irreplaceable")
    link = tmp_path / "mnt"
    link.symlink_to(target, target_is_directory=True)

    assert clear_mountpoint(str(link)) is True
    assert not link.exists()
    assert (target / "notes.txt").read_text() == "irreplaceable"


def test_clear_refuses_loudly_if_the_judgement_were_wrong(tmp_path):
    """rmdir, never rmtree. If mountpoint_obstruction ever let something
    through, this must raise rather than delete a tree."""
    d = tmp_path / "mnt"
    d.mkdir()
    (d / "notes.txt").write_text("irreplaceable")
    with pytest.raises(OSError):
        clear_mountpoint(str(d))
    assert (d / "notes.txt").exists()


# --------------------------------------------------------------------------
# ensure_workspace - never conjure the project root
# --------------------------------------------------------------------------

def test_ensure_workspace_creates_under_an_existing_root(tmp_path):
    cfg = Config(project_root=str(tmp_path))
    assert config_mod.ensure_workspace(cfg) is None
    assert os.path.isdir(cfg.workspace)


def test_ensure_workspace_refuses_a_missing_root(tmp_path):
    """THE OTHER HALF OF THE REGRESSION. An unmounted protected project has no
    root; makedirs would invent it, and the guard could never remount."""
    root = tmp_path / "unmounted"
    cfg = Config(project_root=str(root))
    reason = config_mod.ensure_workspace(cfg)
    assert reason and "does not exist" in reason
    assert not root.exists()


def test_ensure_workspace_refuses_when_the_root_is_a_file(tmp_path):
    f = tmp_path / "root"
    f.write_text("x")
    cfg = Config(project_root=str(f))
    assert config_mod.ensure_workspace(cfg) is not None


def test_ensure_workspace_is_idempotent(tmp_path):
    cfg = Config(project_root=str(tmp_path))
    assert config_mod.ensure_workspace(cfg) is None
    assert config_mod.ensure_workspace(cfg) is None
