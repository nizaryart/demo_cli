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

def test_a_failed_unlock_is_reported_not_swallowed(project, monkeypatch):
    """unprotect appended the "unlocked" line only on success and carried on
    otherwise, so a project came home still Administrators-only with its owner
    shut out and nothing in the output to explain it. Observed live on the
    round-trip test 2026-08-25.

    is_locked IS STUBBED HERE, and it has to be. Without that this test read
    the real ACL of a real temp directory, which answers None on Linux and
    False on Windows - so it passed on Linux through the exit-code fallback
    and failed on Windows, where the honest answer is that the directory is
    not locked (2026-09-10). "The unlock command failed" and "the directory
    is still locked" are different facts, and only the second one is worth
    alarming the user about.
    """
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "unlock_directory", lambda _: P.ResetOutcome(False))
    monkeypatch.setattr(P, "lock_directory", lambda _: P.ResetOutcome(True))
    monkeypatch.setattr(P, "is_locked", lambda _: True)      # it really is
    original = str(project)
    P.protect(P.plan_protect(original))
    steps = P.unprotect(P.plan_unprotect(original))
    assert any("COULD NOT UNLOCK" in s for s in steps)


def test_an_unlock_command_that_failed_on_an_unlocked_directory_is_not_an_alarm(
        project, monkeypatch):
    """The other half. icacls can exit non-zero having had nothing to do -
    unlocking a directory that was never locked, most obviously. Telling the
    user their project is Administrators-only when the ACL says otherwise is
    a false alarm about the one subject this tool must be exact on.

    The filesystem is the authority. That is finding #14 pointed the other
    way round, and it is why the exit code is only a FALLBACK.
    """
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "unlock_directory", lambda _: P.ResetOutcome(False))
    monkeypatch.setattr(P, "lock_directory", lambda _: P.ResetOutcome(True))
    monkeypatch.setattr(P, "is_locked", lambda _: False)     # it is not
    original = str(project)
    P.protect(P.plan_protect(original))
    steps = P.unprotect(P.plan_unprotect(original))
    assert not any("COULD NOT UNLOCK" in s for s in steps), steps
    assert any(s.startswith("unlocked") for s in steps), steps


def test_an_unelevated_unprotect_says_the_acl_was_left_alone(project, monkeypatch):
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    original = str(project)
    P.protect(P.plan_protect(original))
    steps = P.unprotect(P.plan_unprotect(original))
    assert any("not elevated" in s for s in steps)


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
@pytest.mark.skipif(os.name == "nt", reason="these two WRITE an ACL on Windows")
def test_locking_is_a_no_op_off_windows(tmp_path):
    """The skipif is not tidiness. lock_directory and unlock_directory MUTATE
    the directory they are given, and this one has no stub in front of it - so
    on an elevated Windows run it was handing a real icacls a real temp
    directory and asserting the result was False. It passed there, for a
    reason I have not established; the point is that a test named
    off_windows should not have been running on Windows to find out."""
    assert P.lock_directory(str(tmp_path)).ok is False
    assert P.unlock_directory(str(tmp_path)).ok is False


@pytest.mark.skipif(os.name == "nt", reason="checks the non-Windows path")
def test_lock_state_is_unknown_rather_than_false_off_windows(tmp_path):
    """"I cannot tell" and "it is open" are different answers. doctor must
    never report the second when it means the first."""
    assert P.is_locked(str(tmp_path)) is None


def test_the_french_machine_that_broke_name_matching_needs_no_special_case():
    """The bug that started all of this, and why it cannot recur.

    is_locked's first version looked for "BUILTIN\\Users" and $USERNAME. The
    development machine is French and reports "BUILTIN\\Administrateurs", so
    that version called a locked directory UNLOCKED.

    Its replacement counted entries and matched rights strings, on the correct
    observation that "(OI)(CI)(F)" is not localised. That was still reading a
    RENDERING of the ACL, and it broke three ways (see judge_lock).

    The check now names SIDs, which no locale renames - so this test needs no
    French fixture at all. There is nothing left for a language to change.
    """
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is True


def test_the_lock_this_tool_used_to_apply_is_not_a_lock():
    """Two ACEs, exactly as shipped until 2026-09-10. On hardware, unelevated:

        icacls ptest.real /grant "pc:(OI)(CI)F"  ->  Successfully processed 1
        cmd /c move ptest.real gone.real         ->  1 dir(s) moved

    os.rename preserves ownership, and an owner holds WRITE_DAC implicitly.
    Without the OWNER RIGHTS entry to override it, removing every ACE removes
    nothing - so this must read as unlocked, not as a lock of an older shape.
    """
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is False


def test_a_directory_the_user_can_still_reach_is_not_locked():
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI),
            P.Ace("S-1-5-21-1-2-3-1001", True, P._FULL_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is False


def test_an_entry_inherited_from_the_parent_still_grants_access():
    """The count-based check asked how MANY entries there were. An inherited
    one made an open directory reach the expected number."""
    # Otherwise correct, INCLUDING owner rights - so only the inherited entry
    # can be what makes this False. Without that the test would still pass
    # with the outsider rule deleted.
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI),
            P.Ace("S-1-5-32-545", True, P._FULL_CONTROL,       # BUILTIN\Users
                  P._OI | P._CI | P._INHERITED, inherited=True)]
    assert P.judge_lock(aces) is False


def test_a_deny_entry_is_not_read_as_the_grant_it_contains():
    """icacls prints a deny as `(DENY)(OI)(CI)(F)`, which CONTAINS the exact
    substring the old check searched for. A directory denied to everybody read
    as locked. Masks and an ACE type cannot be confused that way."""
    aces = [P.Ace(P.SYSTEM_SID, False, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, False, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is False


def test_owner_rights_granted_more_than_read_control_is_worse_than_absent():
    """(RC) is the entire point: it REPLACES the owner's implicit rights. An
    OWNER RIGHTS entry granting full control hands them back explicitly."""
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._FULL_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is False


def test_a_grant_children_do_not_inherit_is_not_a_lock():
    """lock_directory grants on the directory and RESETS the children so they
    inherit it. Without (OI)(CI) the children inherit nothing and are left
    with the empty DACL of 2026-08-25 - unreadable by anyone at all."""
    aces = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, 0),
            P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, 0),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, 0)]
    assert P.judge_lock(aces) is False


def test_an_inherit_only_entry_does_not_lock_the_directory_it_sits_on():
    """INHERIT_ONLY seeds children and grants nothing here, so it can neither
    lock nor unlock the thing being judged."""
    locked = [P.Ace(P.SYSTEM_SID, True, P._FULL_CONTROL, P._OI | P._CI),
              P.Ace(P.ADMINS_SID, True, P._FULL_CONTROL, P._OI | P._CI),
              P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI)]
    intruder = P.Ace("S-1-5-21-1-2-3-1001", True, P._FULL_CONTROL,
                     P._OI | P._CI | P._INHERIT_ONLY)
    assert P.judge_lock(locked + [intruder]) is True


def test_full_control_spelled_as_generic_all_is_still_full_control():
    aces = [P.Ace(P.SYSTEM_SID, True, P._GENERIC_ALL, P._OI | P._CI),
            P.Ace(P.ADMINS_SID, True, P._GENERIC_ALL, P._OI | P._CI),
            P.Ace(P.OWNER_RIGHTS_SID, True, P._READ_CONTROL, P._OI | P._CI)]
    assert P.judge_lock(aces) is True


def test_an_empty_dacl_is_not_a_lock():
    """Nobody can reach it, including the guard. That is the directory of
    2026-08-25 that only takeown recovered, and it needs attention, not a
    green line."""
    assert P.judge_lock([]) is False


def test_a_dacl_that_could_not_be_read_is_unknown_not_open():
    assert P.judge_lock(None) is None


def test_the_lock_is_three_entries_and_the_third_is_owner_rights():
    """Pins the shape lock_directory applies against the shape judge_lock
    demands, so the two cannot drift apart."""
    assert [sid for sid, _ in P._LOCK_ACL] == [P.SYSTEM_SID, P.ADMINS_SID,
                                               P.OWNER_RIGHTS_SID]
    assert dict(P._LOCK_ACL)[P.OWNER_RIGHTS_SID] == "(OI)(CI)(RC)"
    assert P.OWNER_RIGHTS_SID == "S-1-3-4"


def test_icacls_reporting_failures_is_not_a_success(monkeypatch):
    """icacls with /C exits 0 having failed on every file. That is how the
    one-pass lock reported success while leaving a directory of unreadable
    files, so the count is checked as well as the exit code."""
    import subprocess
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a, 0, "Successfully processed 0 files; Failed processing 7 files", ""))
    assert P._run(["icacls", "x"]) is False


def test_the_acl_uses_sids_not_localised_names():
    """"Administrators" is localised - on a French or Arabic Windows the name
    differs and icacls fails with a message nobody would connect to a locale."""
    assert "*S-1-5-18" in P._ACL_PRINCIPALS         # SYSTEM
    assert "*S-1-5-32-544" in P._ACL_PRINCIPALS     # Administrators


# --------------------------------------------------------------------------
# Finding a protected project you are standing next to
#
# Both setup and teardown default to the current directory, and the guarded
# thing is very often one level down. Run from `lab`, teardown looked for
# `lab.real`, found nothing, and reported "project was not protected" while
# myproj.real sat right there. Observed 2026-08-28.
# --------------------------------------------------------------------------

def test_a_protected_child_is_found_by_its_backing(tmp_path):
    """Searched by BACKING, not by project. When the mount is not running the
    project path does not exist at all - it is a reparse point served by a
    dead process - so scanning for projects finds nothing precisely when the
    answer is most needed."""
    from demo_cli.cli import _protected_children
    (tmp_path / "myproj.real").mkdir()
    (tmp_path / "unrelated").mkdir()
    found = _protected_children(str(tmp_path))
    assert found == [str(tmp_path / "myproj")]


def test_a_project_that_still_exists_is_also_found(tmp_path):
    from demo_cli.cli import _protected_children
    (tmp_path / "myproj").mkdir()
    (tmp_path / "myproj.real").mkdir()
    assert _protected_children(str(tmp_path)) == [str(tmp_path / "myproj")]


def test_an_ordinary_directory_is_not_reported_as_protected(tmp_path):
    from demo_cli.cli import _protected_children
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    assert _protected_children(str(tmp_path)) == []


def test_several_protected_projects_are_all_listed(tmp_path):
    from demo_cli.cli import _protected_children
    for name in ("alpha.real", "beta.real"):
        (tmp_path / name).mkdir()
    found = _protected_children(str(tmp_path))
    assert [os.path.basename(p) for p in found] == ["alpha", "beta"]


def test_an_unreadable_directory_is_not_an_error(tmp_path):
    from demo_cli.cli import _protected_children
    assert _protected_children(str(tmp_path / "does-not-exist")) == []


import contextlib as _contextlib


@_contextlib.contextmanager
def _rename_blocked(directory):
    """Make renaming `directory` fail - on either platform.

    os.chmod DOES NOT RESTRICT DIRECTORIES ON WINDOWS. It only toggles the
    read-only bit, the rename went through, and both tests using it failed
    with "DID NOT RAISE" on the first real Windows run (2026-08-29). That is
    the sixth platform-shaped test assumption in this project, and once again
    the production code was correct - only the test's idea of the platform
    was wrong.

    The Windows mechanism here is the real one from the field: a process
    holding an open handle on a directory makes Windows refuse to rename it.
    That is precisely the WinError 32 `demo_cli setup` hit live on 2026-08-28,
    so the test now REPRODUCES the observed failure instead of simulating it.

    Share mode 0 - no sharing at all - so the rename's own open fails. The
    restype declaration is not decoration: an undeclared restype truncates a
    64-bit HANDLE to 32 bits, which cost three separate bugs earlier in this
    project.
    """
    directory = str(directory)
    if os.name != "nt":
        parent = os.path.dirname(directory)
        mode = os.stat(parent).st_mode
        os.chmod(parent, 0o555)
        try:
            yield
        finally:
            os.chmod(parent, mode)
        return

    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000     # required to open a DIRECTORY
    INVALID = wintypes.HANDLE(-1).value

    handle = kernel32.CreateFileW(directory, GENERIC_READ, 0, None,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                                  None)
    if handle == INVALID:
        pytest.skip(f"could not hold {directory} open "
                    f"(WinError {ctypes.get_last_error()})")
    try:
        yield
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def test_unprotect_reports_a_blocked_rename_instead_of_raising(tmp_path):
    """The way out must never end in a traceback.

    From an unelevated shell the backing is still locked to Administrators, so
    os.rename fails with WinError 5 - and the first version let that escape as
    an unhandled PermissionError out of `demo_cli teardown`, the one command
    somebody runs when things are already wrong. Observed live 2026-08-28.
    """
    backing = tmp_path / "proj.real"
    backing.mkdir()
    (backing / "notes.txt").write_text("irreplaceable")
    plan = P.plan_unprotect(str(tmp_path / "proj"))
    assert plan.ok

    with _rename_blocked(backing):
        with pytest.raises(PermissionError) as exc:
            P.unprotect(plan)
        message = str(exc.value)
        assert "Administrator" in message, "say how to fix it"
        assert "intact" in message, "say the files are safe"
        assert str(backing) in message, "say WHERE they are"
    assert (backing / "notes.txt").read_text() == "irreplaceable"


def test_standing_inside_the_project_is_refused_before_the_uac_prompt(tmp_path, monkeypatch):
    """A process's current directory holds an open handle on it, and Windows
    refuses to rename a directory anything has open.

    Running `demo_cli setup` from inside the project is the natural thing to
    do, and it failed with WinError 32 AFTER the UAC prompt - so the first the
    user knew of it was a traceback out of an elevated process they could not
    see. Observed live 2026-08-28. Checking here costs a message instead of a
    password.
    """
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    monkeypatch.chdir(project)
    plan = P.plan_protect(str(project))
    assert not plan.ok
    assert any("standing inside" in p for p in plan.problems)


def test_a_subdirectory_of_the_project_is_also_refused(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    (project / "src").mkdir(parents=True)
    monkeypatch.chdir(project / "src")
    assert not P.plan_protect(str(project)).ok


def test_standing_beside_the_project_is_fine(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    assert P.plan_protect(str(project)).ok


def test_a_blocked_relocate_names_the_likely_cause(tmp_path):
    """'The process cannot access the file' does not tell anyone that their
    own shell is the process."""
    from demo_cli.fspassthrough import Backing
    source = tmp_path / "proj"
    source.mkdir()
    with _rename_blocked(source):
        with pytest.raises((PermissionError, OSError)) as exc:
            Backing.relocate(str(source), str(tmp_path / "proj.real"))
        assert "Nothing was moved" in str(exc.value)
    assert source.exists()


# --------------------------------------------------------------------------
# The relock repair path (2026-09-05). Gated on Windows, so what is testable
# here is that it stays out of the way everywhere else.
# --------------------------------------------------------------------------

def test_relock_target_is_windows_only(tmp_path):
    """The whole mechanism is an NTFS ACL. On POSIX it must return None so
    cmd_protect takes the ordinary path and nothing changes."""
    import os
    from demo_cli.cli import _relock_target

    proj = tmp_path / "proj"
    proj.mkdir()
    (tmp_path / "proj.real").mkdir()
    result = _relock_target(str(proj), None)
    if os.name != "nt":
        assert result is None


def test_relock_refuses_without_a_mount_record_naming_that_backing(tmp_path):
    """A false positive would apply an Administrators-only ACL to a directory
    that merely happens to be called X.real - locking somebody's data away.
    Evidence must be demo_cli's own mount record, never the name."""
    from demo_cli.cli import _relock_target

    proj = tmp_path / "proj"
    proj.mkdir()
    (tmp_path / "proj.real").mkdir()          # a stranger's directory
    assert _relock_target(str(proj), None) is None


def test_relock_reports_an_outcome_even_when_the_work_happened_elevated():
    """ShellExecuteExW hands the elevated child its own console, which closes
    on exit - so anything it printed is unrecoverable. The parent must state
    the outcome from its own observation, never by relaying the child.

    Structural, because the elevation path cannot run in a test: what is
    pinned is that the non-elevated branch ends in an is_locked() check rather
    than a bare `return rc`.
    """
    import inspect
    from demo_cli import cli

    src = inspect.getsource(cli.cmd_protect)
    branch = src.split("if not protect_mod.is_elevated():", 1)[1]
    branch = branch.split("protect_mod.lock_directory", 1)[0]
    assert "is_locked" in branch, \
        "the parent returns the child's exit code without checking the result"
