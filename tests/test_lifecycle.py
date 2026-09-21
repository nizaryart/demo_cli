"""Tests for lifecycle management module and CLI re-exports."""
import os
import pytest

from demo_cli import cli
from demo_cli import lifecycle
from demo_cli.config import Config


def test_lifecycle_reexports_in_cli():
    """Verify that all lifecycle symbols are identically re-exported in cli for backward compatibility."""
    exported_symbols = [
        "CONFIG_TEMPLATE",
        "_CONFIG_TEMPLATE",
        "WAIT_MOUNT",
        "WAIT_UNMOUNT",
        "_show_plan",
        "_step",
        "_protected_children",
        "_install_hook_for",
        "_remove_hooks",
        "_strip_hook_entries",
        "_wait_until",
        "_teardown_admin_steps",
        "_teardown_needs_admin",
        "cmd_teardown_admin",
        "_show_step",
        "cmd_teardown",
        "cmd_register_task",
        "cmd_setup",
    ]
    for sym in exported_symbols:
        assert hasattr(lifecycle, sym), f"lifecycle missing {sym}"
        assert hasattr(cli, sym), f"cli missing re-export {sym}"
        assert getattr(cli, sym) is getattr(lifecycle, sym), f"mismatch for {sym}"


def test_wait_until_immediate_and_timeout():
    # Immediate true
    assert lifecycle._wait_until(lambda: True, timeout=1.0) is True

    # Immediate false on timeout
    assert lifecycle._wait_until(lambda: False, timeout=0.05, interval=0.01) is False

    # Check with exception suppression
    calls = []
    def flaky_check():
        calls.append(1)
        if len(calls) < 3:
            raise ValueError("not ready yet")
        return True

    assert lifecycle._wait_until(flaky_check, timeout=1.0, interval=0.01) is True


def test_strip_hook_entries_nested():
    data = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "demo_cli hook"},
                        {"type": "command", "command": "keep_this_hook"},
                    ],
                }
            ]
        }
    }
    changed = lifecycle._strip_hook_entries(data, "PreToolUse", "demo_cli hook")
    assert changed is True
    inner_hooks = data["hooks"]["PreToolUse"][0]["hooks"]
    assert len(inner_hooks) == 1
    assert inner_hooks[0]["command"] == "keep_this_hook"


def test_strip_hook_entries_flat():
    data = {
        "hooks": {
            "beforeShellExecution": [
                {"command": "demo_cli hook-cursor"},
                {"command": "other_vendor_tool"},
            ]
        }
    }
    changed = lifecycle._strip_hook_entries(data, "beforeShellExecution", "demo_cli hook-cursor")
    assert changed is True
    remaining = data["hooks"]["beforeShellExecution"]
    assert len(remaining) == 1
    assert remaining[0]["command"] == "other_vendor_tool"


def test_protected_children_detection(tmp_path):
    # Nonexistent directory returns empty
    assert lifecycle._protected_children(str(tmp_path / "nonexistent")) == []

    # Directory with no backing returns empty
    assert lifecycle._protected_children(str(tmp_path)) == []

    # Create dummy backing directory (e.g. proj.demo_cli_backing)
    from demo_cli.protect import BACKING_SUFFIX
    backing_dir = tmp_path / f"my_project{BACKING_SUFFIX}"
    backing_dir.mkdir()

    found = lifecycle._protected_children(str(tmp_path))
    assert found == [str(tmp_path / "my_project")]


def test_config_template_is_valid_toml_and_fully_functional(tmp_path):
    """Verify CONFIG_TEMPLATE parses as valid TOML both as-is and with all commented sections enabled."""
    from demo_cli.config import load_config

    # 1. As-is template
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text(lifecycle.CONFIG_TEMPLATE, encoding="utf-8")
    cfg = load_config(start=str(tmp_path))
    assert cfg.config_error is None
    assert cfg.mode == "shadow"
    assert cfg.workspace_dir == ".demo_cli"

    # 2. Fully uncommented template
    uncommented_lines = []
    for line in lifecycle.CONFIG_TEMPLATE.splitlines():
        if line.startswith("# Docs:") or line.startswith("# Tip:") or line.startswith("# demo_cli configuration") or line.startswith("# Declare"):
            continue
        if line.startswith("# "):
            uncommented_lines.append(line[2:])
        else:
            uncommented_lines.append(line)

    uncommented_toml = "\n".join(uncommented_lines)
    cfg_file.write_text(uncommented_toml, encoding="utf-8")
    cfg2 = load_config(start=str(tmp_path))
    assert cfg2.config_error is None
    assert cfg2.mode == "shadow"
    assert cfg2.egress.get("port") == 8080
    assert cfg2.egress.get("mode") == "shadow"
    assert cfg2.cloak.get("enabled") is True
    assert "ANTHROPIC_API_KEY" in cfg2.env_policy.get("preserve", [])
    assert "GEMINI_API_KEY" in cfg2.env_policy.get("preserve", [])
    assert cfg2.checkpoint.get("enabled") is False
    assert len(cfg2.targets) == 1
    assert cfg2.targets[0].match == "production"
    assert cfg2.targets[0].env == "production"

