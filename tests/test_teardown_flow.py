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


# --------------------------------------------------------------------------
# A clean teardown must leave a clean doctor.
#
# On 2026-09-02 teardown ran perfectly - guard stopped, task removed, files
# moved back, hooks removed, one UAC prompt - and `doctor` immediately
# afterwards reported:
#
#   [x] filesystem guard  RECORDED BUT NOT RUNNING - pid 18792 is gone, so
#                         C:\Users\pc\Desktop\labubu is unguarded while the
#                         record says otherwise
#   [!] backing locked    cannot tell for C:\Users\pc\Desktop\labubu.real
#
# Both were false. Nothing was unguarded, because nothing was protected, and
# the backing it named no longer existed. The cause was one stale mount.json:
# step 1 clears it THROUGH the mount while the guard is being killed, that
# unlink fails, and mountstate.clear swallows the error - so the record rode
# back inside .demo_cli when the files were restored.
#
# A correct teardown that ends in a red FAIL teaches people to ignore doctor.
# --------------------------------------------------------------------------

def test_teardown_removes_the_mount_record_it_leaves_behind(tmp_path):
    """The stale record must not survive the move-back."""
    from demo_cli import protect as protect_mod
    from demo_cli.config import load_config

    project = str(tmp_path / "proj")
    backing = protect_mod.backing_for(project)
    os.makedirs(os.path.join(backing, ".demo_cli"))
    with open(os.path.join(backing, ".demo_cli", "mount.json"), "w") as f:
        json.dump({"pid": 18792, "mountpoint": project, "backing": backing,
                   "host": os.name}, f)

    cli._teardown_admin_steps(project, load_config(project))

    # Wherever the files ended up, no mount.json may be left claiming a guard.
    for root in (project, backing):
        leftover = os.path.join(root, ".demo_cli", "mount.json")
        assert not os.path.exists(leftover), f"stale record survived at {leftover}"


def test_a_stale_record_on_an_unprotected_project_is_a_warning_not_a_failure(tmp_path, monkeypatch):
    """The distinction the old code missed.

    backing present + pid gone -> the project IS protected and unguarded. fail.
    backing absent  + pid gone -> torn down, record left behind. warn.

    Collapsing the second into the first is what put a red FAIL on a correct
    teardown; collapsing the first into the second would hide a genuinely
    unguarded project, so both directions matter.
    """
    import shutil
    orig_which = shutil.which
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/demo_cli" if cmd == "demo_cli" else orig_which(cmd))

    project = str(tmp_path / "proj")
    os.makedirs(os.path.join(project, ".demo_cli"))
    with open(os.path.join(project, ".demo_cli", "mount.json"), "w") as f:
        json.dump({"pid": 999999, "mountpoint": project, "host": os.name}, f)

    class A:
        root, no_color, port = project, True, 8080
    rc = cli.cmd_doctor(A())

    from demo_cli.config import load_config
    from demo_cli import mountstate
    st = mountstate.status(load_config(project))
    assert st.stale, "precondition: the record must look stale"
    assert rc == 0, "a torn-down project must not fail doctor"

