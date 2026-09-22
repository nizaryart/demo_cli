"""Tests for CLI packaging hygiene and help output polish."""
import argparse
from demo_cli.cli import build_parser


def test_cli_help_renders_clean_usage_without_leaking_hidden_commands():
    """`demo_cli --help` should use a clean COMMAND metavar and not leak

    internal maintenance commands or '==SUPPRESS==' placeholders into help text.
    """
    parser = build_parser()
    help_text = parser.format_help()

    # Clean usage banner
    assert "usage: demo_cli [-h] [--version] COMMAND ..." in help_text

    # Internal maintenance commands are completely excluded from help
    assert "_teardown-admin" not in help_text
    assert "_register-task" not in help_text
    assert "==SUPPRESS==" not in help_text

    # Standard commands are advertised
    for cmd in ("check", "undo", "log", "receipt", "verify", "doctor", "init"):
        assert cmd in help_text


def test_hidden_commands_still_parse_correctly():
    """Hidden commands must still be recognized and parsed with full fidelity."""
    parser = build_parser()

    # _teardown-admin
    args_td = parser.parse_args(["_teardown-admin", "my_proj", "--report", "/tmp/report.json"])
    assert args_td.cmd == "_teardown-admin"
    assert args_td.project == "my_proj"
    assert args_td.report == "/tmp/report.json"
    assert callable(args_td.func)

    # _register-task
    args_rt = parser.parse_args(["_register-task", "my_proj"])
    assert args_rt.cmd == "_register-task"
    assert args_rt.project == "my_proj"
    assert callable(args_rt.func)
