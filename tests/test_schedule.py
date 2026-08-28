"""The logon task that brings the filesystem guard back after a reboot.

Shutting down ends the user session, so the mount dies like any other process.
The FILES are safe - Stage 2 writes straight through - but C:\\project stops
existing, and the next session is unprotected while looking normal. A logon
task removes "I forgot to mount after rebooting" as a possible state.

Naming and the command shape are testable anywhere; schtasks itself is not.
"""
import os

import pytest

from demo_cli import schedule


def test_the_task_name_is_readable_in_task_scheduler():
    name = schedule.task_name(os.path.join("C:", "Users", "pc", "lab"))
    assert name.startswith(schedule.TASK_PREFIX)


def test_path_separators_never_reach_the_task_name():
    r"""Backslash is the FOLDER separator in the task namespace, so a raw path
    would create nested folders and a task nobody can find again."""
    name = schedule.task_name(os.path.join("C:", "Users", "pc", "lab"))
    assert "\\" not in name and "/" not in name


def test_two_projects_get_two_tasks():
    a = schedule.task_name(os.path.join("C:", "one"))
    b = schedule.task_name(os.path.join("C:", "two"))
    assert a != b


def test_the_same_project_is_always_the_same_task():
    """Or setup would stack duplicate tasks on every run."""
    p = os.path.join("C:", "Users", "pc", "lab")
    assert schedule.task_name(p) == schedule.task_name(p + os.sep)


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_it_is_inert_off_windows():
    assert schedule.available() is False
    assert schedule.register("/tmp/p", "/tmp/p.real") is False
    assert schedule.status("/tmp/p").exists is False


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_removing_a_task_that_is_not_there_is_not_a_failure():
    """teardown must never refuse to continue because a step was already
    done - it has to work on a half-broken machine."""
    assert schedule.unregister("/tmp/never-registered") in (True, False)
