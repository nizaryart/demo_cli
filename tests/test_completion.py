"""Tests for shell tab-completion generation, environment detection, and installation."""
import os
import pytest
from unittest.mock import patch

from demo_cli.cli import build_parser
from demo_cli.completion import (
    extract_cli_metadata,
    generate_completion,
    generate_bash_completion,
    generate_zsh_completion,
    generate_fish_completion,
    generate_powershell_completion,
    detect_shell,
    install_completion,
    SUPPORTED_SHELLS,
)


def test_extract_cli_metadata_includes_public_commands_and_excludes_hidden():
    parser = build_parser()
    spec = extract_cli_metadata(parser)
    cmds = spec["commands"]

    # Public commands must be present
    for expected in ("check", "undo", "diff", "log", "verify", "receipt", "doctor", "init", "target", "completion"):
        assert expected in cmds, f"Expected '{expected}' in completion metadata"

    # Hidden maintenance commands must NOT be present
    for hidden in ("_teardown-admin", "_register-task"):
        assert hidden not in cmds, f"Hidden command '{hidden}' leaked into completion metadata"

    # Choices must be captured
    check_choices = cmds["check"]["choices"]
    assert "--mode" in check_choices
    assert set(check_choices["--mode"]) == {"shadow", "enforce"}

    # Target subcommands
    assert "add" in cmds["target"]["subcommands"]
    assert "list" in cmds["target"]["subcommands"]


def test_generate_bash_completion():
    parser = build_parser()
    script = generate_completion("bash", parser=parser)

    assert "# bash completion for demo_cli" in script
    assert "complete -F _demo_cli_completion demo_cli" in script
    assert "check" in script
    assert "doctor" in script
    assert "shadow enforce" in script
    assert "_teardown-admin" not in script


def test_generate_zsh_completion():
    parser = build_parser()
    script = generate_completion("zsh", parser=parser)

    assert "#compdef demo_cli" in script
    assert "_demo_cli" in script
    assert "check:evaluate one command before it runs" in script
    assert "_arguments" in script
    assert "_teardown-admin" not in script


def test_generate_fish_completion():
    parser = build_parser()
    script = generate_completion("fish", parser=parser)

    assert "# fish completion for demo_cli" in script
    assert 'complete -c demo_cli -n "__fish_use_subcommand" -a "check"' in script
    assert 'complete -c demo_cli -n "__fish_seen_subcommand_from check"' in script
    assert "_teardown-admin" not in script


def test_generate_powershell_completion():
    parser = build_parser()
    script = generate_completion("powershell", parser=parser)

    assert "Register-ArgumentCompleter" in script
    assert "demo_cli" in script
    assert "'check'" in script
    assert "_teardown-admin" not in script


def test_generate_completion_invalid_shell_raises():
    with pytest.raises(ValueError, match="Unsupported shell"):
        generate_completion("unsupported_shell_xyz")


def test_detect_shell_env_detection():
    # In CI
    with patch.dict(os.environ, {"CI": "true"}):
        assert detect_shell() is None

    with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
        assert detect_shell() is None

    # Normal shells
    with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": "", "SHELL": "/bin/zsh"}):
        if os.name != "nt":
            assert detect_shell() == "zsh"

    with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": "", "SHELL": "/usr/bin/fish"}):
        if os.name != "nt":
            assert detect_shell() == "fish"

    with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": "", "SHELL": "/bin/bash"}):
        if os.name != "nt":
            assert detect_shell() == "bash"


def test_install_completion_in_isolated_dir(tmp_path):
    parser = build_parser()

    # Bash
    ok, msg = install_completion(shell="bash", home_dir=str(tmp_path), parser=parser)
    assert ok
    bash_file = tmp_path / ".local" / "share" / "bash-completion" / "completions" / "demo_cli"
    assert bash_file.exists()
    assert "complete -F _demo_cli_completion demo_cli" in bash_file.read_text()

    # Fish
    ok, msg = install_completion(shell="fish", home_dir=str(tmp_path), parser=parser)
    assert ok
    fish_file = tmp_path / ".config" / "fish" / "completions" / "demo_cli.fish"
    assert fish_file.exists()
    assert "# fish completion for demo_cli" in fish_file.read_text()

    # Zsh
    ok, msg = install_completion(shell="zsh", home_dir=str(tmp_path), parser=parser)
    assert ok
    zsh_file = tmp_path / ".zfunc" / "_demo_cli"
    assert zsh_file.exists()
    assert "#compdef demo_cli" in zsh_file.read_text()

    # PowerShell
    ok, msg = install_completion(shell="powershell", home_dir=str(tmp_path), parser=parser)
    assert ok


def test_cli_completion_subcommand_stdout(capsys):
    parser = build_parser()
    args = parser.parse_args(["completion", "bash"])
    ret = args.func(args)
    assert ret == 0
    out = capsys.readouterr().out
    assert "# bash completion for demo_cli" in out


def test_cli_completion_subcommand_install(tmp_path, capsys):
    parser = build_parser()
    args = parser.parse_args(["completion", "bash", "--install"])

    # Redirect home to tmp_path
    with patch("os.path.expanduser", return_value=str(tmp_path)):
        ret = args.func(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "Installed Bash completion" in out

