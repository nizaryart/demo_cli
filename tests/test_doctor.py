"""Tests for doctor diagnostics module and CLI re-exports."""
import json
import os
import pytest

from demo_cli import cli
from demo_cli import doctor
from demo_cli.config import Config


def test_doctor_reexports_in_cli():
    """Verify that all doctor symbols are identically re-exported in cli for backward compatibility."""
    exported_symbols = [
        "_HOSTS",
        "_our_entries",
        "_read_host_config",
        "_hook_installed",
        "_compare_entries",
        "_expected_entries",
        "_hook_check_rows",
        "_host_hook_audit",
        "_host_hook_status",
        "_hook_selftest",
        "_SELFTEST_PAYLOADS",
        "_any_hook_installed",
        "_mount_checks",
        "cmd_doctor",
    ]
    for sym in exported_symbols:
        assert hasattr(doctor, sym), f"doctor missing {sym}"
        assert hasattr(cli, sym), f"cli missing re-export {sym}"
        assert getattr(cli, sym) is getattr(doctor, sym), f"mismatch for {sym}"


def test_our_entries_extraction():
    data = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "demo_cli hook"},
                        {"type": "command", "command": "other_tool"},
                    ],
                },
                {"non_dict": 123},
            ]
        }
    }
    entries = doctor._our_entries(data, "PreToolUse", "demo_cli hook", nested=True)
    assert len(entries) == 1
    matcher, handler = entries[0]
    assert matcher == "Bash"
    assert handler["command"] == "demo_cli hook"

    # Flat entries (e.g. Cursor)
    flat_data = {
        "hooks": {
            "beforeShellExecution": [
                {"command": "demo_cli hook-cursor", "failClosed": True}
            ]
        }
    }
    flat_entries = doctor._our_entries(flat_data, "beforeShellExecution", "demo_cli hook-cursor", nested=False)
    assert len(flat_entries) == 1
    assert flat_entries[0][0] is None
    assert flat_entries[0][1]["command"] == "demo_cli hook-cursor"


def test_compare_entries():
    installed = [("Bash", {"type": "command", "command": "demo_cli hook", "timeout": 30})]
    expected = [("Bash", {"type": "command", "command": "demo_cli hook", "timeout": 30})]
    stale, inert = doctor._compare_entries(installed, expected, nested=True)
    assert stale == []
    assert inert == []

    # Missing type in nested hook causes inert
    installed_inert = [("Bash", {"command": "demo_cli hook"})]
    stale, inert = doctor._compare_entries(installed_inert, expected, nested=True)
    assert any("no \"type\"" in item for item in inert)

    # Missing timeout causes stale
    installed_stale = [("Bash", {"type": "command", "command": "demo_cli hook", "timeout": 10})]
    stale, inert = doctor._compare_entries(installed_stale, expected, nested=True)
    assert any("timeout" in item for item in stale)


def test_read_host_config_nonexistent(tmp_path):
    missing_file = str(tmp_path / "nonexistent.json")
    assert doctor._read_host_config(missing_file) is None


def test_read_host_config_valid_and_invalid(tmp_path):
    valid_file = tmp_path / "valid.json"
    valid_file.write_text('{"status": "ok"}', encoding="utf-8-sig")
    assert doctor._read_host_config(str(valid_file)) == {"status": "ok"}

    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("invalid json content", encoding="utf-8")
    assert doctor._read_host_config(str(invalid_file)) is None


def test_doctor_detects_fsguard_activity(tmp_path, capsys):
    """Doctor must detect activity from the filesystem guard (in receipts-fs.jsonl)."""
    from types import SimpleNamespace
    from demo_cli.receipts import CHAIN_FS, Receipt, append_receipt
    cfg = Config(project_root=str(tmp_path))
    append_receipt(cfg.receipts_path, Receipt(
        action_raw="[fs] delete test.py",
        action_type="filesystem",
        target_environment="dev",
        decision="REVERSIBLE",
        reason="Snapshotted",
        mode="enforce-fs",
        agent_id="fsguard",
        chain=CHAIN_FS,
    ))
    doctor.cmd_doctor(SimpleNamespace(root=str(tmp_path)))
    out = capsys.readouterr().out
    assert "ACTIVE (agent receipts)" in out
    assert "fsguard" in out



