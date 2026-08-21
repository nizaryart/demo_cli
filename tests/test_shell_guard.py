"""Finding #010: shell-guard false-positives that only surface in the real
Claude Code `!`-mode path (an `eval '<cmd>' < /dev/null` wrapper + live
filesystem state). Locks in the two fixes so they cannot regress.
"""
import io
import os

from demo_cli.cli import cmd_guard_shell
from demo_cli.guard import Guard
from demo_cli.config import Config


class _Args:
    def __init__(self, argv):
        self.argv = argv
        self.no_color = True


def _guard_shell_rc(command_tokens, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".demo_cli.toml").write_text('mode = "enforce"\n')
    return cmd_guard_shell(_Args(command_tokens))


def _decision(cmd, root):
    cfg = Config(project_root=str(root), mode="enforce")
    return Guard(config=cfg, mode="enforce").evaluate(cmd).decision.decision


# --- #010a: the !-mode `eval '...' < /dev/null` wrapper must be unwrapped ------

def test_eval_wrapper_create_new_file_is_allowed(tmp_path, monkeypatch):
    # `! printf KEEP > canary.txt` arrives wrapped; creating a new file -> exit 0
    rc = _guard_shell_rc(["eval 'printf KEEP > canary.txt' < /dev/null"], tmp_path, monkeypatch)
    assert rc == 0


def test_eval_wrapper_inner_rm_is_evaluated_not_opaque(tmp_path, monkeypatch):
    # The wrapper must be unwrapped so the inner `rm` is judged as a filesystem
    # op (an existing in-project dir is recoverable -> snapshot, rc 0), NOT
    # false-blocked as opaque `eval` execution.
    (tmp_path / "victimdir").mkdir()
    rc = _guard_shell_rc(["eval 'rm -rf victimdir' < /dev/null"], tmp_path, monkeypatch)
    assert rc == 0
    from demo_cli.config import load_config
    from demo_cli import recovery
    monkeypatch.chdir(tmp_path)
    assert recovery.load_entries(load_config(start=str(tmp_path)).recovery_dir), \
        "inner rm should have been snapshotted, not opaque-blocked"


def test_eval_wrapper_unrecoverable_inner_is_blocked(tmp_path, monkeypatch):
    # mkfs is non-recoverable -> the unwrapped inner command must BLOCK (rc 1).
    rc = _guard_shell_rc(["eval 'mkfs.ext4 /dev/sdX' < /dev/null"], tmp_path, monkeypatch)
    assert rc == 1


def test_eval_is_not_treated_as_opaque_exec_in_wrapper(tmp_path, monkeypatch):
    # the bare-eval opaque-exec rule must not fire on the !-mode wrapper itself
    (tmp_path / "keep.txt").write_text("K")
    rc = _guard_shell_rc(["eval 'ls keep.txt' < /dev/null"], tmp_path, monkeypatch)
    assert rc == 0


# --- #010b: redirect to a non-existent file is creation, not truncation --------

def test_redirect_to_new_file_not_destructive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _decision("printf x > brandnew.txt", tmp_path) == "ALLOW"


def test_redirect_to_existing_file_still_snapshots(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "exists.txt").write_text("OLD")
    assert _decision("echo new > exists.txt", tmp_path) == "REVERSIBLE"
