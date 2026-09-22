"""Subprocess-level end-to-end integration tests for demo_cli.

Executes demo_cli as an external OS subprocess from scratch in clean,
isolated directories, validating the full operator lifecycle:
init -> target add -> check -> log -> receipt -> verify -> undo -> completion.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import pytest


SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def run_cli(
    args: List[str],
    cwd: Path | str,
    env: Optional[dict] = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute demo_cli as a real external OS subprocess."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    full_env["PYTHONPATH"] = SRC_DIR
    full_env.pop("DEMO_CLI_DISABLE", None)
    full_env["NO_COLOR"] = "1"

    cmd = [sys.executable, "-m", "demo_cli.cli", *args]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=full_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"CLI subprocess failed with code {proc.returncode}:\n"
            f"Command: {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}"
        )
    return proc


def test_e2e_full_operator_lifecycle(tmp_path: Path):
    """Execute the full end-to-end user journey as external OS subprocesses."""
    # 1. Initialize starter configuration
    init_res = run_cli(["init", "--mode", "enforce"], cwd=tmp_path)
    assert init_res.returncode == 0
    config_file = tmp_path / ".demo_cli.toml"
    assert config_file.exists(), ".demo_cli.toml was not created by `demo_cli init`"
    assert 'mode = "enforce"' in config_file.read_text(encoding="utf-8")

    # 2. Add target rule and list active targets
    target_res = run_cli(
        ["target", "add", "*.sqlite", "--env", "production", "--recovery", "snapshot"],
        cwd=tmp_path,
    )
    assert target_res.returncode == 0
    assert "*.sqlite" in config_file.read_text(encoding="utf-8")

    list_res = run_cli(["target", "list"], cwd=tmp_path)
    assert list_res.returncode == 0
    assert "*.sqlite" in list_res.stdout
    assert "production" in list_res.stdout

    # 3. Create a target database file
    db_file = tmp_path / "prod.sqlite"
    original_payload = b"SQLITE_FORMAT_3_MOCK_DATABASE_PAYLOAD_E2E_VERIFICATION"
    db_file.write_bytes(original_payload)

    # 4. Run pre-execution safety check on destructive command
    check_res = run_cli(["check", "rm prod.sqlite", "--mode", "enforce"], cwd=tmp_path)
    assert check_res.returncode == 0
    assert "REVERSIBLE" in check_res.stdout or "SAFE" in check_res.stdout
    assert "prod.sqlite" in check_res.stdout

    # 5. Inspect captured recovery points via log
    log_res = run_cli(["log"], cwd=tmp_path)
    assert log_res.returncode == 0
    assert "recovery log" in log_res.stdout
    assert "prod.sqlite" in log_res.stdout or "file" in log_res.stdout

    # 6. Inspect audit receipts
    rc_list_res = run_cli(["receipt", "--list"], cwd=tmp_path)
    assert rc_list_res.returncode == 0
    assert "receipts" in rc_list_res.stdout

    rc_share_res = run_cli(["receipt", "--share"], cwd=tmp_path)
    assert rc_share_res.returncode == 0
    assert "RECEIPT" in rc_share_res.stdout or "PROOF" in rc_share_res.stdout or "hash" in rc_share_res.stdout

    # 7. Verify hash chain integrity
    verify_res = run_cli(["verify"], cwd=tmp_path)
    assert verify_res.returncode == 0
    assert "VERIFIED" in verify_res.stdout

    # 8. Simulate destructive agent action
    db_file.unlink()
    assert not db_file.exists(), "Target file must be absent before undo"

    # 9. Perform undo / rollback
    undo_res = run_cli(["undo"], cwd=tmp_path)
    assert undo_res.returncode == 0
    assert "RESTORED" in undo_res.stdout
    assert db_file.exists(), "Target file was not restored by `demo_cli undo`"
    assert db_file.read_bytes() == original_payload, "Restored content does not match original bytes"

    # 10. Verify shell completion generation works from subprocess
    bash_comp = run_cli(["completion", "bash"], cwd=tmp_path)
    assert bash_comp.returncode == 0
    assert "complete -F _demo_cli_completion demo_cli" in bash_comp.stdout

    zsh_comp = run_cli(["completion", "zsh"], cwd=tmp_path)
    assert zsh_comp.returncode == 0
    assert "#compdef demo_cli" in zsh_comp.stdout


def test_e2e_help_and_version_flags(tmp_path: Path):
    """Verify help and version flags render properly without leaks."""
    # --help
    help_res = run_cli(["--help"], cwd=tmp_path)
    assert help_res.returncode == 0
    assert "usage: demo_cli [-h] [--version] COMMAND ..." in help_res.stdout
    assert "_teardown-admin" not in help_res.stdout
    assert "_register-task" not in help_res.stdout
    assert "==SUPPRESS==" not in help_res.stdout
    assert "completion" in help_res.stdout
    assert "check" in help_res.stdout

    # --version
    ver_res = run_cli(["--version"], cwd=tmp_path)
    assert ver_res.returncode == 0
    assert "demo_cli 1.7.0" in ver_res.stdout or "demo_cli 1.7.0" in ver_res.stderr

    # completion --help
    comp_help = run_cli(["completion", "--help"], cwd=tmp_path)
    assert comp_help.returncode == 0
    assert "--install" in comp_help.stdout


def test_e2e_safe_command_evaluation(tmp_path: Path):
    """Verify safe read-only commands evaluate to ALLOW cleanly."""
    res = run_cli(["check", "ls -la"], cwd=tmp_path)
    assert res.returncode == 0
    assert "SAFE" in res.stdout or "ALLOW" in res.stdout


def test_e2e_invalid_subcommand_handling(tmp_path: Path):
    """Verify non-existent subcommand returns code 2 with standard error message."""
    proc = run_cli(["nonexistent-command-xyz"], cwd=tmp_path, check=False)
    assert proc.returncode != 0
    assert "invalid choice" in proc.stderr or "invalid choice" in proc.stdout
