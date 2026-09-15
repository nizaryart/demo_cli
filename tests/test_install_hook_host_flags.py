"""Every host install-hook supports is nameable on the command line.

Codex and Cursor had a flag; Claude Code was reachable only as the bare form,
so `install-hook --claude` failed with a usage dump listing every subcommand.
That also made the bare form - the one that writes host config with no host
named in the command - the only way to reach the default.
"""
import pytest

from demo_cli.cli import build_parser


def _parse(*argv):
    return build_parser().parse_args(["install-hook", *argv])


def test_claude_is_nameable():
    assert _parse("--claude").claude is True


def test_claude_is_still_the_default():
    a = _parse()
    assert a.claude is False and a.codex is False and a.cursor is False


def test_every_host_flag_parses():
    assert _parse("--codex").codex is True
    assert _parse("--cursor").cursor is True


def test_two_hosts_at_once_is_refused():
    # Without the mutually exclusive group, --claude --codex parsed fine and
    # cmd_install_hook silently took the codex branch: the command named two
    # hosts and one of them was ignored without a word.
    for pair in (("--claude", "--codex"), ("--claude", "--cursor"),
                 ("--codex", "--cursor")):
        with pytest.raises(SystemExit):
            _parse(*pair)


def test_print_does_not_need_a_host():
    assert _parse("--print").print is True
