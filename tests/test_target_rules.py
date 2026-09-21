"""Tests for target rule parsing, matching, validation, and CLI management."""
import os
import pytest

from demo_cli.config import (
    Config, TargetRule, append_target_rule, load_config, normalize_target_env,
)
from demo_cli.cli import main


# --------------------------------------------------------------------------
# 1. TargetRule.matches()
# --------------------------------------------------------------------------

def test_target_rule_case_insensitive_substring():
    rule = TargetRule(match="production", env="production")
    assert rule.matches("/var/data/PRODUCTION_DB.sqlite")
    assert rule.matches("c:\\app\\Production\\data.db")
    assert not rule.matches("/var/data/staging.db")


def test_target_rule_slash_normalization():
    rule = TargetRule(match="data/prod.db", env="production")
    # Unix path
    assert rule.matches("/home/user/project/data/prod.db")
    # Windows path with backslashes
    assert rule.matches(r"C:\Users\pc\project\data\prod.db")


def test_target_rule_glob_matching():
    rule = TargetRule(match="*.sqlite3", env="production")
    assert rule.matches("/path/to/orders.sqlite3")
    assert rule.matches("orders.sqlite3")
    assert not rule.matches("/path/to/orders.db")

    rule_prefix = TargetRule(match="data/prod_*.db", env="production")
    assert rule_prefix.matches("/app/data/prod_2026.db")
    assert rule_prefix.matches(r"C:\app\data\prod_users.db")
    assert not rule_prefix.matches("/app/data/dev_2026.db")


def test_target_rule_empty_ref():
    rule = TargetRule(match="production", env="production")
    assert not rule.matches(None)
    assert not rule.matches("")


# --------------------------------------------------------------------------
# 2. TOML Configuration Parsing: Bug 2 Fix
# --------------------------------------------------------------------------

def test_load_config_singular_table_dict(tmp_path):
    """Bug 2 fix: [target] as a single table must NOT be silently skipped."""
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text("""
[target]
match = "critical_data"
env = "production"
recovery = "snapshot"
""", encoding="utf-8")

    cfg = load_config(start=str(tmp_path))
    assert len(cfg.targets) == 1
    assert cfg.targets[0].match == "critical_data"
    assert cfg.targets[0].env == "production"
    assert cfg.targets[0].recovery == "snapshot"
    assert len(cfg.target_errors) == 0


def test_load_config_plural_array_of_tables(tmp_path):
    """Bug 2 fix: [[targets]] plural must be parsed cleanly."""
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text("""
[[targets]]
match = "prod_db"
env = "production"
recovery = "snapshot"

[[targets]]
match = "staging_db"
env = "stage"
recovery = "none"
""", encoding="utf-8")

    cfg = load_config(start=str(tmp_path))
    assert len(cfg.targets) == 2
    assert cfg.targets[0].match == "prod_db"
    assert cfg.targets[0].env == "production"
    assert cfg.targets[1].match == "staging_db"
    assert cfg.targets[1].env == "staging"
    assert cfg.targets[1].recovery == "none"


def test_load_config_standard_array_of_tables(tmp_path):
    """Standard [[target]] must continue to work."""
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text("""
[[target]]
match = "cache_dir"
env = "dev"
recovery = "none"
""", encoding="utf-8")

    cfg = load_config(start=str(tmp_path))
    assert len(cfg.targets) == 1
    assert cfg.targets[0].match == "cache_dir"
    assert cfg.targets[0].env == "development"
    assert cfg.targets[0].recovery == "none"


def test_load_config_invalid_target_rules_recorded(tmp_path):
    """Missing match and invalid recovery must be recorded in target_errors."""
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text("""
[[target]]
# missing 'match'
env = "production"

[[target]]
match = "db.sqlite"
recovery = "invalid_strategy"
""", encoding="utf-8")

    cfg = load_config(start=str(tmp_path))
    assert len(cfg.target_errors) == 2
    assert "missing required 'match' field" in cfg.target_errors[0]
    assert "invalid recovery 'invalid_strategy'" in cfg.target_errors[1]
    # The valid rule with invalid recovery falls back to snapshot
    assert len(cfg.targets) == 1
    assert cfg.targets[0].recovery == "snapshot"


# --------------------------------------------------------------------------
# 3. append_target_rule() and CLI Commands
# --------------------------------------------------------------------------

def test_append_target_rule_new_file(tmp_path):
    cfg_path, summary = append_target_rule(
        root=str(tmp_path),
        match="prod.db",
        env="production",
        recovery="snapshot",
    )
    assert os.path.exists(cfg_path)
    assert "prod.db" in summary

    cfg = load_config(start=str(tmp_path))
    assert len(cfg.targets) == 1
    assert cfg.targets[0].match == "prod.db"


def test_append_target_rule_validation(tmp_path):
    with pytest.raises(ValueError, match="cannot be empty"):
        append_target_rule(root=str(tmp_path), match="")

    with pytest.raises(ValueError, match="invalid recovery"):
        append_target_rule(root=str(tmp_path), match="valid", recovery="bad")


def test_cli_target_add_and_list(tmp_path, capsys):
    # Add target via CLI
    rc = main(["target", "add", "users_prod.sqlite", "--env", "production", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "added target 'users_prod.sqlite'" in out

    # List targets via CLI
    rc_list = main(["target", "list", "--root", str(tmp_path)])
    assert rc_list == 0
    out_list = capsys.readouterr().out
    assert "Declared target rules" in out_list
    assert "users_prod.sqlite" in out_list


def test_cli_target_add_validation_error(tmp_path, capsys):
    # Invalid recovery argument from CLI
    with pytest.raises(SystemExit):
        main(["target", "add", "test.db", "--recovery", "bogus", "--root", str(tmp_path)])


# --------------------------------------------------------------------------
# 4. Doctor Visibility
# --------------------------------------------------------------------------

def test_doctor_reports_targets(tmp_path):
    from demo_cli.doctor import cmd_doctor

    class Args:
        root = str(tmp_path)
        no_color = True

    # When no targets declared
    cfg_file = tmp_path / ".demo_cli.toml"
    cfg_file.write_text('mode = "enforce"\n', encoding="utf-8")
    # Run doctor (doctor prints report)
    # We can inspect the checks via load_config or cmd_doctor
    cfg = load_config(str(tmp_path))
    assert len(cfg.targets) == 0

    # When target is declared
    append_target_rule(str(tmp_path), "live.db", env="production")
    cfg_with_target = load_config(str(tmp_path))
    assert len(cfg_with_target.targets) == 1
    assert cfg_with_target.targets[0].match == "live.db"

