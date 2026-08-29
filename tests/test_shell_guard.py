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


# --------------------------------------------------------------------------
# The escape hatches
#
# On 2026-08-25 a syntax error committed to cli.py made demo_cli unimportable.
# This trap runs on EVERY command in EVERY bash, it read the resulting non-zero
# exit as "the guard refused", and every command in every shell began failing -
# including the ones needed to repair the file. The recovery path was the one
# thing that could not be done from a shell.
#
# Our own failures fail OPEN. That is already the rule inside guard-shell; a
# package that will not import is the same class of failure, only earlier.
# --------------------------------------------------------------------------
import shutil as _shutil
import subprocess as _subprocess

import pytest as _pytest

from demo_cli.cli import _SHELL_GUARD_SNIPPET


def _bash_for_this_platform():
    """A bash that is running on THE PLATFORM UNDER TEST - or None.

    shutil.which("bash") on Windows finds C:\\Windows\\System32\\bash.exe,
    which is WSL. That is a LINUX kernel, a Linux filesystem and a Linux PATH.
    These tests were therefore not testing Windows at all: they crossed into a
    different operating system and reported the result as a Windows failure
    (found 2026-08-29).

    Worse, the crossing hid itself. Inside WSL the fixture's stub sits at a
    Windows path that means nothing, so `command -v demo_cli` finds nothing,
    the snippet's own gate never opens, and NO TRAP IS INSTALLED. A guard that
    never loaded is indistinguishable from a guard correctly switched off - so
    test_the_kill_switch_turns_the_guard_off PASSED, on a shell where the
    guard could not possibly have run. A false pass is worse than a failure.

    Measured on the machine, same command through each shell:

        C:\\Windows\\System32\\bash.exe   Linux ... WSL2      demo_cli: not found
        C:\\Program Files\\Git\\bin\\bash  MINGW64_NT ... Msys  /c/users/pc/.local/bin/demo_cli

    Git Bash is also the one that matters: Claude Code's Bash tool on Windows
    is Git Bash, so it is where !-mode actually runs.
    """
    if os.name != "nt":
        return _shutil.which("bash")

    for candidate in (r"C:\Program Files\Git\bin\bash.exe",
                      r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if os.path.exists(candidate):
            return candidate
    git = _shutil.which("git")          # ...\Git\cmd\git.exe -> ...\Git\bin\bash.exe
    if git:
        cand = os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe")
        if os.path.exists(cand):
            return cand
    found = _shutil.which("bash")
    if found and "system32" not in found.lower():
        return found
    return None                          # WSL only: not a Windows bash


BASH = _bash_for_this_platform()


def _write_sh(path, body):
    """newline="\n", always.

    Python on Windows writes \r\n by default, and a CRLF shebang makes the
    interpreter name "/bin/sh\r" - a file that does not exist. The script is
    read by a POSIX shell, so it gets POSIX line endings whatever host wrote
    it.
    """
    with open(path, "w", newline="\n") as f:
        f.write(body)
    return path


def _fake_demo_cli(directory, body):
    path = _write_sh(os.path.join(directory, "demo_cli"), body)
    os.chmod(path, 0o755)
    return path


@_pytest.fixture
def guarded_shell(tmp_path):
    """A real bash with the real snippet installed, and a stub demo_cli."""
    binn = tmp_path / "bin"
    binn.mkdir()
    script = _write_sh(str(tmp_path / "guard.sh"), _SHELL_GUARD_SNIPPET)

    def run(stub_body, env_extra=None):
        _fake_demo_cli(str(binn), stub_body)
        env = dict(os.environ)
        env["PATH"] = f"{binn}{os.pathsep}" + env["PATH"]
        env["BASH_ENV"] = str(script)
        env.update(env_extra or {})
        return _subprocess.run([BASH, "-c", "rm -f /tmp/nonexistent-xyz; echo RAN"],
                               capture_output=True, text=True, env=env, timeout=30)
    return run


BROKEN = '#!/bin/sh\necho "SyntaxError: broken" >&2\nexit 1\n'
BLOCKS = '#!/bin/sh\nif [ "$1" = "--version" ]; then echo 0.0; exit 0; fi\nexit 1\n'
ALLOWS = '#!/bin/sh\nexit 0\n'


@_pytest.mark.skipif(BASH is None, reason="no bash for this platform "
                                          "(WSL's bash is not Windows)")
def test_a_broken_demo_cli_does_not_lock_the_shell(guarded_shell):
    """THE regression test. Every invocation fails, as it did when the package
    would not import - and the command must still run."""
    r = guarded_shell(BROKEN)
    assert "RAN" in r.stdout, "a broken guard must not block the shell"
    assert "not working" in r.stderr, "and it must say why"


@_pytest.mark.skipif(BASH is None, reason="no bash for this platform "
                                          "(WSL's bash is not Windows)")
def test_a_working_guard_still_blocks(guarded_shell):
    """The escape hatch must not become a hole: a guard that runs and refuses
    is still a refusal."""
    r = guarded_shell(BLOCKS)
    assert "RAN" not in r.stdout
    assert "blocked" in r.stderr


@_pytest.mark.skipif(BASH is None, reason="no bash for this platform "
                                          "(WSL's bash is not Windows)")
def test_the_kill_switch_turns_the_guard_off(guarded_shell):
    """`export` is a builtin matching no pattern in the pre-filter, so this
    still works from a shell that is otherwise stuck."""
    r = guarded_shell(BLOCKS, {"DEMO_CLI_DISABLE": "1"})
    assert "RAN" in r.stdout
    assert "blocked" not in r.stderr


@_pytest.mark.skipif(BASH is None, reason="no bash for this platform "
                                          "(WSL's bash is not Windows)")
def test_an_allowing_guard_lets_the_command_through(guarded_shell):
    r = guarded_shell(ALLOWS)
    assert "RAN" in r.stdout


def test_the_snippet_carries_both_escape_hatches():
    assert "DEMO_CLI_DISABLE" in _SHELL_GUARD_SNIPPET
    assert "--version" in _SHELL_GUARD_SNIPPET, "the broken-vs-refused probe"
