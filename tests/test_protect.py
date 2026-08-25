"""`demo_cli protect` - relocating a project so its path can become the mount.

This command MOVES SOMEBODY'S PROJECT, so most of these tests are about what it
REFUSES. A half-finished relocation is a person's work in a directory they
cannot find, and every refusal below is a case where proceeding would either
fail partway or quietly do something nobody asked for.

The relocation and every check run on any platform; only the ACL is
Windows-only. That split is deliberate and matches fsguard/fspassthrough: the
decisions are testable where the work is done.
"""
import os

import pytest

from demo_cli import protect as P


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "project"
    (p / "src").mkdir(parents=True)
    (p / "src" / "app.py").write_text("print(1)")
    (p / "notes.txt").write_text("irreplaceable")
    return p


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

def test_the_backing_directory_is_a_suffixed_sibling(tmp_path):
    """A suffix rather than something hidden elsewhere: whoever finds it should
    be able to tell what it belongs to, a year later, with the tool gone."""
    assert P.backing_for(str(tmp_path / "project")) == \
        str(tmp_path / "project") + ".real"


def test_a_trailing_separator_does_not_change_the_name(tmp_path):
    assert P.backing_for(str(tmp_path / "project") + os.sep) == \
        P.backing_for(str(tmp_path / "project"))


# --------------------------------------------------------------------------
# What it refuses
# --------------------------------------------------------------------------

def test_a_missing_project_is_refused(tmp_path):
    plan = P.plan_protect(str(tmp_path / "nothing"))
    assert not plan.ok


def test_a_file_is_not_a_project(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert not P.plan_protect(str(f)).ok


def test_the_home_directory_is_refused():
    plan = P.plan_protect(os.path.expanduser("~"))
    assert not plan.ok
    assert any("home" in p.lower() for p in plan.problems)


def test_a_drive_root_is_refused():
    root = os.path.abspath(os.sep)
    plan = P.plan_protect(root)
    assert not plan.ok


def test_an_existing_backing_directory_is_refused_rather_than_merged(project):
    """Merging two trees is how work disappears silently. Refuse and say so."""
    os.mkdir(P.backing_for(str(project)))
    plan = P.plan_protect(str(project))
    assert not plan.ok
    assert any("merge" in p.lower() for p in plan.problems)


def test_a_backing_inside_the_project_is_refused(project):
    """The filesystem would be storing its own contents through itself."""
    plan = P.plan_protect(str(project), backing=str(project / "inside"))
    assert not plan.ok


def test_a_refused_plan_moves_nothing(project):
    os.mkdir(P.backing_for(str(project)))
    plan = P.plan_protect(str(project))
    with pytest.raises(ValueError):
        P.protect(plan)
    assert (project / "notes.txt").exists(), "the project must be untouched"


# --------------------------------------------------------------------------
# What it warns about
# --------------------------------------------------------------------------

def test_running_unelevated_warns_that_nothing_will_be_locked(project, monkeypatch):
    """The whole point of the lock is that the backing directory is otherwise
    writable by anything - which was demonstrated live, with an ordinary
    Remove-Item deleting it out from under a running mount."""
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    plan = P.plan_protect(str(project), lock=True)
    assert plan.ok
    assert any("bypass" in w.lower() for w in plan.warnings)


def test_an_elevated_plan_does_not_warn_about_the_lock(project, monkeypatch):
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    plan = P.plan_protect(str(project), lock=True)
    assert not any("bypass" in w.lower() for w in plan.warnings)


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_off_windows_it_says_nothing_will_mount(project):
    plan = P.plan_protect(str(project))
    assert any("demo_cli run" in w for w in plan.warnings), \
        "point them at the layer that DOES work on their platform"


# --------------------------------------------------------------------------
# The move itself
# --------------------------------------------------------------------------

def test_protect_vacates_the_project_path(project, monkeypatch):
    """The path has to be free: an NTFS reparse point only goes on an empty or
    missing directory, and WinFsp creates the mount point itself."""
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    plan = P.plan_protect(str(project))
    P.protect(plan)
    assert not os.path.exists(plan.source)
    assert os.path.isdir(plan.backing)


def test_protect_preserves_the_whole_tree(project, monkeypatch):
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    plan = P.plan_protect(str(project))
    P.protect(plan)
    assert open(os.path.join(plan.backing, "notes.txt")).read() == "irreplaceable"
    assert open(os.path.join(plan.backing, "src", "app.py")).read() == "print(1)"


def test_the_mount_point_is_the_original_path(project):
    """The reason to relocate at all: every path, IDE config and habit keeps
    working. A drive letter would change all of them permanently."""
    plan = P.plan_protect(str(project))
    assert plan.mountpoint == plan.source


# --------------------------------------------------------------------------
# Getting back out
# --------------------------------------------------------------------------

def test_protect_then_unprotect_is_a_round_trip(project, monkeypatch):
    """Nobody should run a command that relocates their project without a way
    back - and a way back that only works when everything is healthy is not
    one."""
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    original = str(project)
    P.protect(P.plan_protect(original))
    P.unprotect(P.plan_unprotect(original))
    assert open(os.path.join(original, "notes.txt")).read() == "irreplaceable"
    assert open(os.path.join(original, "src", "app.py")).read() == "print(1)"
    assert not os.path.exists(P.backing_for(original))


def test_unprotect_refuses_when_the_project_path_is_occupied(project, monkeypatch):
    """A live mount occupies that path as a reparse point. Renaming over it
    would either fail or, worse, bury the mount."""
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    original = str(project)
    P.protect(P.plan_protect(original))
    os.mkdir(original)                       # stands in for a live mount
    plan = P.plan_unprotect(original)
    assert not plan.ok
    assert any("unmount" in p.lower() for p in plan.problems)


def test_unprotect_refuses_when_there_is_nothing_to_restore(tmp_path):
    assert not P.plan_unprotect(str(tmp_path / "never-protected")).ok


# --------------------------------------------------------------------------
# The lock, off Windows
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_locking_is_a_no_op_off_windows(tmp_path):
    assert P.lock_directory(str(tmp_path)) is False
    assert P.unlock_directory(str(tmp_path)) is False


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_lock_state_is_unknown_rather_than_false_off_windows(tmp_path):
    """"I cannot tell" and "it is open" are different answers. doctor must
    never report the second when it means the first."""
    assert P.is_locked(str(tmp_path)) is None


def test_the_acl_uses_sids_not_localised_names():
    """"Administrators" is localised - on a French or Arabic Windows the name
    differs and icacls fails with a message nobody would connect to a locale."""
    assert "*S-1-5-18" in P._ACL_PRINCIPALS         # SYSTEM
    assert "*S-1-5-32-544" in P._ACL_PRINCIPALS     # Administrators
