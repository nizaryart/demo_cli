"""Is the filesystem guard running right now?

"Installed but inert" has been the dangerous state four separate times in this
project - a Codex config in a shape Codex ignored, a UTF-8 BOM that disabled
the guard, a doctor that only knew one host, and now a mount that is not
running. Each time the tool looked installed and protected nothing.

A mount is the worst of the four, because when it stops, the directory it was
serving simply is not there any more and nothing else in `doctor` would
notice. So the tests below care most about the states that could produce a
FALSE ALL-CLEAR, in either direction:

  * a record whose process is gone must never read as running
  * a state that cannot be determined must read as "I do not know", never as
    a confident yes or no
"""
import json
import os
import time

import pytest

from demo_cli import mountstate as M
from demo_cli.config import Config


@pytest.fixture
def cfg(tmp_path):
    return Config(project_root=str(tmp_path))


# --------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------

def test_nothing_recorded_reads_as_not_running(cfg):
    st = M.status(cfg)
    assert st.recorded is False
    assert st.running is False
    assert st.stale is False, "never started is not the same as died"


def test_a_live_mount_is_reported_running(cfg, tmp_path):
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount), str(tmp_path / "real"))
    st = M.status(cfg)
    assert st.recorded and st.running is True
    assert st.mountpoint == str(mount)
    assert st.pid == os.getpid()


def test_the_backing_directory_is_remembered(cfg, tmp_path):
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount), str(tmp_path / "real"))
    assert M.status(cfg).backing == str(tmp_path / "real")


def test_an_in_memory_mount_records_no_backing(cfg, tmp_path):
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount))
    assert M.status(cfg).backing is None


def test_clearing_removes_the_record(cfg, tmp_path):
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount))
    M.clear(cfg)
    assert M.status(cfg).recorded is False


def test_clearing_when_there_is_nothing_is_not_an_error(cfg):
    M.clear(cfg)


# --------------------------------------------------------------------------
# The dangerous state: a record whose process is gone
# --------------------------------------------------------------------------

def test_a_dead_pid_is_stale_not_running(cfg, tmp_path):
    """THE case this module exists for. The user started a guard, believes it
    is running, and is not protected. doctor reports this as a hard fail."""
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, 999_999_998, str(mount))
    st = M.status(cfg)
    assert st.running is False
    assert st.stale is True


def test_a_live_pid_whose_mount_point_vanished_is_not_running(cfg, tmp_path):
    """PIDs are reused, so liveness alone is not proof. A filesystem that died
    without cleaning up leaves the record behind and the path gone."""
    M.write(cfg, os.getpid(), str(tmp_path / "never-existed"))
    assert M.status(cfg).running is False


# --------------------------------------------------------------------------
# "I do not know" must stay distinct from "no"
# --------------------------------------------------------------------------

def test_a_record_from_another_platform_is_undetermined(cfg, tmp_path):
    """A Windows PID means nothing to a Linux kernel. Checking it anyway would
    give a confident wrong answer in one direction or the other."""
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount))
    path = M.state_path(cfg)
    data = json.load(open(path))
    data["host"] = "posix" if os.name == "nt" else "nt"
    json.dump(data, open(path, "w"))

    st = M.status(cfg)
    assert st.recorded is True
    assert st.running is None
    assert st.stale is False, "unknown must not be reported as died"


def test_a_corrupt_state_file_reads_as_no_record(cfg):
    """Never as running. A file we cannot parse tells us nothing, and the safe
    reading of nothing is 'no guard'."""
    os.makedirs(cfg.workspace, exist_ok=True)
    open(M.state_path(cfg), "w").write("{not json")
    assert M.status(cfg).recorded is False


def test_a_state_file_that_is_not_an_object_reads_as_no_record(cfg):
    os.makedirs(cfg.workspace, exist_ok=True)
    open(M.state_path(cfg), "w").write("[1, 2, 3]")
    assert M.status(cfg).recorded is False


# --------------------------------------------------------------------------
# pid_alive on its own
# --------------------------------------------------------------------------

def test_our_own_process_is_alive():
    assert M.pid_alive(os.getpid()) is True


def test_an_impossible_pid_is_not_alive():
    assert M.pid_alive(999_999_998) is False


@pytest.mark.parametrize("pid", [0, -1, None])
def test_a_nonsense_pid_is_not_alive(pid):
    assert M.pid_alive(pid) is False


# --------------------------------------------------------------------------
# Age, and the log the detached mount writes to
# --------------------------------------------------------------------------

def test_age_is_reported_in_minutes(cfg, tmp_path):
    mount = tmp_path / "guarded"
    mount.mkdir()
    M.write(cfg, os.getpid(), str(mount))
    path = M.state_path(cfg)
    data = json.load(open(path))
    data["started"] = time.time() - 3600
    json.dump(data, open(path, "w"))
    assert M.status(cfg).age_minutes == 60


def test_the_log_path_is_inside_the_workspace(cfg):
    """A detached mount has no terminal, and the [fs] lines are the only
    channel carrying recovery-point ids. They have to land somewhere findable
    and somewhere doctor can point at."""
    assert M.log_path(cfg).startswith(cfg.workspace)
    assert M.log_path(cfg).endswith("mount.log")


def test_status_always_reports_where_the_log_would_be(cfg):
    """Even with no record - that is where to look for why nothing started."""
    assert M.status(cfg).log == M.log_path(cfg)
