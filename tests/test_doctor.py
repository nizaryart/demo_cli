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
        "_egress_checks",
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


def test_egress_checks_quiet_when_tool_missing_and_closed(monkeypatch, tmp_path):
    """When mitmdump is absent and port is closed, doctor suppresses egress checks."""
    import shutil
    from demo_cli import guarded
    cfg = Config(project_root=str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr(guarded, "port_open", lambda port: False)

    checks = doctor._egress_checks(cfg)
    assert checks == []


def test_egress_checks_listener_states(monkeypatch, tmp_path):
    """Doctor correctly reports listening and non-listening states."""
    import shutil
    from demo_cli import guarded
    cfg = Config(project_root=str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/mitmdump" if cmd == "mitmdump" else None)

    # 1. Listening
    monkeypatch.setattr(guarded, "port_open", lambda port: True)
    checks = doctor._egress_checks(cfg)
    proxy_check = next(c for c in checks if c[1] == "egress proxy")
    assert proxy_check[0] == "ok"
    assert "listening on :8080" in proxy_check[2]

    # 2. Not running
    monkeypatch.setattr(guarded, "port_open", lambda port: False)
    checks = doctor._egress_checks(cfg)
    proxy_check = next(c for c in checks if c[1] == "egress proxy")
    assert proxy_check[0] == "warn"
    assert "not running on :8080" in proxy_check[2]


def test_egress_checks_ca_bundle_states(monkeypatch, tmp_path):
    """Doctor reports generated and missing CA certificate bundles."""
    import shutil
    from demo_cli import guarded
    cfg = Config(project_root=str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/mitmdump")
    monkeypatch.setattr(guarded, "port_open", lambda port: True)

    # Missing CA
    monkeypatch.setattr(guarded, "ca_bundle", lambda: str(tmp_path / "nonexistent.pem"))
    checks = doctor._egress_checks(cfg)
    ca_check = next(c for c in checks if c[1] == "egress CA")
    assert ca_check[0] == "warn"
    assert "not generated yet" in ca_check[2]

    # Present CA
    ca_file = tmp_path / "mitmproxy-ca-cert.pem"
    ca_file.write_text("CERT DATA")
    monkeypatch.setattr(guarded, "ca_bundle", lambda: str(ca_file))
    checks = doctor._egress_checks(cfg)
    ca_check = next(c for c in checks if c[1] == "egress CA")
    assert ca_check[0] == "ok"
    assert str(ca_file) in ca_check[2]


def test_egress_checks_no_proxy_audit(monkeypatch, tmp_path):
    """Doctor audits shell NO_PROXY to verify model endpoints are protected."""
    import shutil
    from demo_cli import guarded
    cfg = Config(project_root=str(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/mitmdump")
    monkeypatch.setattr(guarded, "port_open", lambda port: True)

    # Case 1: No HTTPS_PROXY set
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    checks = doctor._egress_checks(cfg)
    np_check = next(c for c in checks if c[1] == "egress NO_PROXY")
    assert np_check[0] == "ok"
    assert "defaults protect" in np_check[2]

    # Case 2: HTTPS_PROXY set, NO_PROXY missing endpoints
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("NO_PROXY", "")
    checks = doctor._egress_checks(cfg)
    np_check = next(c for c in checks if c[1] == "egress NO_PROXY")
    assert np_check[0] == "warn"
    assert "api.anthropic.com" in np_check[2]

    # Case 3: HTTPS_PROXY set, NO_PROXY correctly bypassing
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,api.anthropic.com,api.openai.com")
    checks = doctor._egress_checks(cfg)
    np_check = next(c for c in checks if c[1] == "egress NO_PROXY")
    assert np_check[0] == "ok"
    assert "configured in shell" in np_check[2]


def test_egress_checks_policy_reflection(monkeypatch, tmp_path):
    """Doctor reflects configured [egress] policy details."""
    import shutil
    from demo_cli import guarded
    cfg = Config(project_root=str(tmp_path))
    cfg.egress = {
        "port": 8888,
        "mode": "audit",
        "strict_unknown_hosts": True,
        "saas_hosts": ["github.com", "slack.com"],
    }
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/mitmdump")
    monkeypatch.setattr(guarded, "port_open", lambda port: True)

    checks = doctor._egress_checks(cfg)
    proxy_check = next(c for c in checks if c[1] == "egress proxy")
    assert "listening on :8888" in proxy_check[2]

    policy_check = next(c for c in checks if c[1] == "egress policy")
    assert policy_check[0] == "ok"
    assert "mode=audit" in policy_check[2]
    assert "strict_unknown=true" in policy_check[2]
    assert "2 SaaS host(s)" in policy_check[2]




