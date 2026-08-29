"""Teardown must be one command, and must not look like it worked when it did not.

Tearing down `demo` on 2026-08-29 took THREE invocations across two shells, and
still left the logon task registered and Ready - so it would have fired at every
logon, mounting a backing that had just been moved away. Two separate defects:

  1. `demo_cli teardown demo` run one directory up resolved to a path that did
     not exist and printed four "nothing to do" steps. Individually true, and
     collectively a lie: it reads as "torn down" while the real project is
     still mounted and its backing still locked. "Installed but inert",
     inverted - uninstalled but still running.

  2. "could not remove the logon task" - four words, no cause, no remedy, and
     a zero exit code, while step 1 above named the pid, the reason and the
     exact command. The one step that silently left something behind was the
     one that explained nothing.
"""
import json
import os

import pytest

from demo_cli import cli
from demo_cli.config import Config


class _Args:
    def __init__(self, project, yes=True):
        self.project, self.yes, self.no_color, self.root = project, yes, True, None


# --------------------------------------------------------------------------
# a wrong target is not a clean teardown
# --------------------------------------------------------------------------

def test_a_path_that_does_not_exist_is_refused(tmp_path, capsys):
    rc = cli.cmd_teardown(_Args(str(tmp_path / "nope")))
    out = capsys.readouterr().out
    assert rc == 1, "four 'nothing to do' lines is not success"
    assert "does not exist" in out
    assert "absolute path" in out, "name the likely mistake"


def test_a_real_but_untouched_project_still_tears_down(tmp_path, capsys):
    """The refusal must not fire on a project that simply has nothing left -
    teardown has to work on a machine in any state, including a half-done one."""
    (tmp_path / "proj").mkdir()
    rc = cli.cmd_teardown(_Args(str(tmp_path / "proj")))
    assert rc == 0
    assert "does not exist" not in capsys.readouterr().out


# --------------------------------------------------------------------------
# every failing step says why, and the command fails
# --------------------------------------------------------------------------

def test_steps_are_returned_as_data_not_printed(tmp_path):
    """They run in an elevated child whose console closes with it, so the
    parent has to be able to render them. Same reason mount.log exists."""
    project = str(tmp_path / "proj")
    os.makedirs(project)
    steps = cli._teardown_admin_steps(project, Config(project_root=project))
    assert steps and all({"n", "ok", "text"} <= set(x) for x in steps)
    assert all(isinstance(x["ok"], bool) for x in steps)


def test_a_failed_step_carries_a_remedy(tmp_path, capsys):
    """The rule step 2 broke: a step that leaves something behind must say
    what, and what to type."""
    cli._show_step({"n": 2, "ok": False, "text": "could not remove the logon task",
                    "detail": ["it is still registered"],
                    "remedy": 'schtasks /delete /tn "x" /f'})
    out = capsys.readouterr().out
    assert "could not remove" in out
    assert "still registered" in out
    assert "schtasks /delete" in out


def test_a_failure_makes_the_command_fail(tmp_path, capsys, monkeypatch):
    project = str(tmp_path / "proj")
    os.makedirs(project)
    monkeypatch.setattr(cli, "_teardown_admin_steps",
                        lambda p, c: [{"n": 2, "ok": False, "text": "could not remove the logon task"}])
    rc = cli.cmd_teardown(_Args(project))
    out = capsys.readouterr().out
    assert rc == 1, "a teardown with a failed step must not exit 0"
    assert "did not complete" in out
    assert "audit trail" not in out, "do not sign off cheerfully on a failure"


def test_a_clean_teardown_still_says_where_the_receipts_are(tmp_path, capsys):
    project = str(tmp_path / "proj")
    os.makedirs(project)
    assert cli.cmd_teardown(_Args(project)) == 0
    assert "audit trail" in capsys.readouterr().out


# --------------------------------------------------------------------------
# the elevated half reports back
# --------------------------------------------------------------------------

def test_the_admin_half_writes_a_readable_report(tmp_path):
    project = str(tmp_path / "proj")
    os.makedirs(project)
    report = str(tmp_path / "r.json")

    class A:
        pass
    a = A()
    a.project, a.report, a.root, a.no_color = project, report, None, True
    rc = cli.cmd_teardown_admin(a)
    with open(report) as f:
        steps = json.load(f)
    assert rc == 0 and steps
    assert all("text" in x for x in steps)
