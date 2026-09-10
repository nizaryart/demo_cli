"""What the lock APPLIES, and what is believed about whether it worked.

Two findings from the 2026-09-09 review, plus the hardware result of
2026-09-10 that changed the definition of a lock:

  #5   is_locked counted ACEs and matched rights substrings   -> judge_lock
  #14  protect() claimed a lock on lock_directory's say-so

judge_lock's own rules are pinned in test_protect.py. This file covers the
two ends of it: the icacls call that creates the ACL, and every caller that
decides what to tell the user about it.
"""
import inspect
import os

import pytest

from demo_cli import protect as P


# ------------------------------------------------- what lock_directory asks

def _captured(monkeypatch):
    seen = []
    monkeypatch.setattr(P.os, "name", "nt")
    monkeypatch.setattr(P, "_icacls_present", lambda: True)
    monkeypatch.setattr(P, "_run", lambda args: seen.append(list(args)) or True)
    monkeypatch.setattr(P, "_reset_children", lambda p: True)
    return seen


def test_the_lock_grants_owner_rights_as_well(monkeypatch):
    """The entry the first three weeks of this feature were missing. Without
    it the owner keeps WRITE_DAC implicitly and grants themselves back in -
    verified on hardware, no UAC prompt."""
    seen = _captured(monkeypatch)
    assert P.lock_directory(r"C:\lab\p.real") is True
    args = seen[0]
    assert "/grant:r" in args
    assert "*S-1-3-4:(OI)(CI)(RC)" in args


def test_the_lock_still_grants_system_and_administrators(monkeypatch):
    seen = _captured(monkeypatch)
    P.lock_directory(r"C:\lab\p.real")
    args = seen[0]
    assert "*S-1-5-18:(OI)(CI)F" in args
    assert "*S-1-5-32-544:(OI)(CI)F" in args


def test_inheritance_is_stripped_before_anything_is_granted(monkeypatch):
    """An inherited entry for BUILTIN\\Users survives every grant, so the
    order is not cosmetic."""
    seen = _captured(monkeypatch)
    P.lock_directory(r"C:\lab\p.real")
    args = seen[0]
    assert args.index("/inheritance:r") < args.index("/grant:r")


def test_the_grant_is_one_call_on_the_directory_and_not_a_tree_walk(monkeypatch):
    """(OI)(CI) are container-inheritance flags: meaningless on a file. /T
    applied them to every child, icacls rejected them per file, and /C
    swallowed it - leaving every pre-existing file with an EMPTY DACL
    (2026-08-25). Children are made to INHERIT instead."""
    seen = _captured(monkeypatch)
    P.lock_directory(r"C:\lab\p.real")
    assert len(seen) == 1
    assert "/T" not in seen[0]
    assert "/C" not in seen[0]


def test_what_is_granted_is_exactly_what_is_judged(monkeypatch):
    """The write path and the read path must not drift. Every SID
    lock_directory grants is one judge_lock accepts, and vice versa."""
    seen = _captured(monkeypatch)
    P.lock_directory(r"C:\lab\p.real")
    granted = {a.split(":", 1)[0].lstrip("*") for a in seen[0]
               if a.startswith("*S-")}
    assert granted == {P.SYSTEM_SID, P.ADMINS_SID, P.OWNER_RIGHTS_SID}


# ------------------------------------------- what protect() then believes

def _plan(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    return P.Plan(source=str(src), backing=str(tmp_path / "proj.real"),
                  mountpoint=str(src), will_lock=True)


def _stub(monkeypatch, locked, lock_returns=True):
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P.Backing, "relocate", staticmethod(lambda a, b: None))
    monkeypatch.setattr(P, "lock_directory", lambda p: lock_returns)
    monkeypatch.setattr(P, "is_locked", lambda p: locked)


def test_a_lock_is_claimed_only_when_the_filesystem_agrees(tmp_path, monkeypatch):
    _stub(monkeypatch, locked=True)
    assert any("locked" in d and "COULD NOT" not in d
               for d in P.protect(_plan(tmp_path)))


def test_icacls_exiting_zero_is_not_a_lock(tmp_path, monkeypatch):
    """icacls has exited 0 on a grant it did not apply. This is the whole of
    finding #14: the claim of protection must not rest on a self-report."""
    _stub(monkeypatch, locked=False, lock_returns=True)
    assert any("COULD NOT LOCK" in d for d in P.protect(_plan(tmp_path)))


def test_icacls_failing_is_not_the_last_word_either(tmp_path, monkeypatch):
    """The other direction. If the ACL is right, it is right - a non-zero
    exit from a command that nonetheless did the job is not a reason to tell
    the user their project is exposed."""
    _stub(monkeypatch, locked=True, lock_returns=False)
    done = P.protect(_plan(tmp_path))
    assert any("locked" in d and "COULD NOT" not in d for d in done)


def test_an_unreadable_acl_is_reported_as_unknown_not_as_unlocked(tmp_path, monkeypatch):
    """"I could not check" and "it is open" are different sentences."""
    _stub(monkeypatch, locked=None)
    done = P.protect(_plan(tmp_path))
    assert any("COULD NOT VERIFY" in d for d in done)
    assert not any("COULD NOT LOCK" in d for d in done)


def test_nothing_is_claimed_when_the_plan_did_not_ask_for_a_lock(tmp_path, monkeypatch):
    _stub(monkeypatch, locked=False)
    plan = _plan(tmp_path)
    plan.will_lock = False
    assert not any("LOCK" in d.upper() for d in P.protect(plan))


# ------------------------------------------------ and what the CLI prints

def _relock_branch():
    from demo_cli import cli
    src = inspect.getsource(cli.cmd_protect)
    return src.split("Re-applying the lock", 1)[1].split("plan = protect_mod.plan_protect", 1)[0]


def test_the_cli_separates_cannot_tell_from_not_locked():
    """Both relock paths - elevated child and direct - read the ACL back.
    Neither may print None as either outcome."""
    branch = _relock_branch()
    assert branch.count("state is True") == 2
    assert branch.count("state is False") == 2
    assert "could not be read" in branch


def test_the_cli_never_compares_is_locked_to_false_directly():
    """`is_locked(x) is not True` and `is_locked(x) is False` differ by
    exactly the case this whole three-state exists for."""
    from demo_cli import cli
    src = inspect.getsource(cli.cmd_protect)
    assert "is_locked(relock) is not True" not in src
    assert "not protect_mod.is_locked" not in src


def test_a_wide_open_null_dacl_is_not_mistaken_for_an_empty_one():
    """_read_dacl turns a NULL DACL into an explicit Everyone/full entry,
    because "no entries" would otherwise read as the tightest lock possible
    when it is the loosest."""
    assert P.judge_lock([P.Ace(P.EVERYONE_SID, True, P._FULL_CONTROL,
                               P._OI | P._CI)]) is False
    src = inspect.getsource(P._read_dacl)
    assert "EVERYONE_SID" in src


def test_the_acl_is_read_through_the_api_and_not_by_parsing_output():
    """icacls prints principals in the console's language and flattens a mask
    into a rights string. Both of those were the bug."""
    src = inspect.getsource(P._read_dacl)
    assert "GetNamedSecurityInfoW" in src
    assert "ConvertSidToStringSidW" in src
    assert "_ICACLS" not in src
    assert "_ICACLS" not in inspect.getsource(P.is_locked)


@pytest.mark.skipif(os.name == "nt", reason="there is a real DACL to read here")
def test_reading_an_acl_off_windows_is_unknown(tmp_path):
    assert P._read_dacl(str(tmp_path)) is None
    assert P.is_locked(str(tmp_path)) is None


# --------------------------------------------------------------------------
# The probe itself, against a real DACL.
#
# THESE DID NOT EXIST WHEN _read_dacl WAS FIRST WRITTEN, and the suite was
# green on Windows anyway: every other test in this file feeds judge_lock a
# hand-built list, and the only test that touched the probe asserted it
# returns None - which it does off Windows, where none of this code runs.
# A probe returning garbage would have passed 1058 tests (2026-09-10).

@pytest.mark.skipif(os.name != "nt", reason="needs a Windows ACL")
def test_the_probe_returns_real_entries_for_a_real_directory(tmp_path):
    aces = P._read_dacl(str(tmp_path))
    assert aces, "no entries for a directory that certainly has some"
    for a in aces:
        assert a.sid.startswith("S-1-"), a
        assert a.mask, a
        assert isinstance(a.allow, bool)


@pytest.mark.skipif(os.name != "nt", reason="needs a Windows ACL")
def test_an_ordinary_directory_does_not_read_as_locked(tmp_path):
    """The failure that would matter most: a probe whose output happens to
    satisfy judge_lock would report every directory on the machine as
    protected."""
    assert P.is_locked(str(tmp_path)) is False


@pytest.mark.skipif(os.name != "nt", reason="needs icacls")
def test_the_probe_agrees_with_icacls_on_the_same_directory(tmp_path):
    """Cross-check against the thing this replaced.

    The masks and offsets in _read_dacl are hand-written struct arithmetic:
    ACE_HEADER is four bytes, the mask is the next four, the SID starts at
    eight. Every one of those is a number I could have got wrong, and a wrong
    one still yields plausible-looking output. icacls is an independent
    reading of the same ACL, so if the two agree on how many entries there
    are and which are inherited, the arithmetic is right.
    """
    import subprocess
    r = subprocess.run([P._ICACLS, str(tmp_path)], capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0, r.stderr

    lines = [l for l in (r.stdout or "").splitlines()
             if ":" in l and not l.startswith(("Successfully", "Failed"))]
    aces = P._read_dacl(str(tmp_path))
    assert aces is not None
    assert len(aces) == len(lines), f"{aces}\n{r.stdout}"

    # (I) is how icacls prints an inherited entry.
    assert sum(1 for a in aces if a.inherited) == sum(1 for l in lines if "(I)" in l)
    # (F) is full control - the mask judge_lock's rule 2 tests for.
    assert sum(1 for a in aces if a.mask & P._FULL_CONTROL == P._FULL_CONTROL) \
        == sum(1 for l in lines if "(F)" in l)


# --------------------------------------------------------------------------
# The window between the rename and the icacls call
#
# Findings #4 and #9. Neither is about whether the lock is right; both are
# about WHEN it is absent. `<project>.real` is derivable from the project's
# own path, so an agent does not need to win a race it cannot see - it can
# watch for that name to appear. protect left it there unlocked for as long
# as icacls takes on a tree, and unprotect put it back there unlocked for the
# same span on the way out.
#
# A same-volume rename preserves the DACL (hardware, 2026-09-10), so the fix
# is ordering and nothing else.

def _order(monkeypatch, *, locked=True, relocate_fails=False):
    calls = []
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "lock_directory",
                        lambda p: calls.append(("lock", p)) or True)
    monkeypatch.setattr(P, "unlock_directory",
                        lambda p: calls.append(("unlock", p)) or True)
    monkeypatch.setattr(P, "is_locked", lambda p: locked)

    def _move(a, b):
        calls.append(("move", a, b))
        if relocate_fails:
            raise PermissionError("something holds it open")
    monkeypatch.setattr(P.Backing, "relocate", staticmethod(_move))
    monkeypatch.setattr(P.os, "rename", lambda a, b: calls.append(("move", a, b)))
    return calls


def test_the_backing_is_locked_before_it_ever_has_that_name(tmp_path, monkeypatch):
    calls = _order(monkeypatch)
    plan = _plan(tmp_path)
    P.protect(plan)
    assert [c[0] for c in calls] == ["lock", "move"], calls
    # locked at the ORIGINAL path - the whole point
    assert calls[0][1] == plan.source


def test_a_move_that_fails_does_not_leave_the_project_locked(tmp_path, monkeypatch):
    """Somebody's project locked to Administrators, at its original path,
    because the step after the lock failed - worse than the failure."""
    calls = _order(monkeypatch, relocate_fails=True)
    plan = _plan(tmp_path)
    with pytest.raises(PermissionError):
        P.protect(plan)
    assert [c[0] for c in calls] == ["lock", "move", "unlock"], calls
    assert calls[-1][1] == plan.source


def test_a_lock_that_did_not_take_is_undone_before_the_move(tmp_path, monkeypatch):
    """icacls can strip inheritance and then fail on the grant. Moving that
    tree hands the user a project with an ACL nobody asked for."""
    calls = _order(monkeypatch, locked=False)
    plan = _plan(tmp_path)
    P.protect(plan)
    assert [c[0] for c in calls] == ["lock", "unlock", "move"], calls


def test_the_lock_is_verified_at_the_destination_not_the_source(tmp_path, monkeypatch):
    """Reading it back after the move also checks the assumption the whole
    ordering rests on: that the rename carried the DACL with it."""
    seen = []
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "lock_directory", lambda p: True)
    monkeypatch.setattr(P, "unlock_directory", lambda p: True)
    monkeypatch.setattr(P, "is_locked", lambda p: seen.append(p) or True)
    monkeypatch.setattr(P.Backing, "relocate", staticmethod(lambda a, b: None))
    plan = _plan(tmp_path)
    P.protect(plan)
    assert seen[-1] == plan.backing


def test_unprotect_moves_it_home_before_unlocking_it(tmp_path, monkeypatch):
    """The mirror. The only moment it is unlocked, it is already home under
    the name the user chose - not sitting at .real."""
    calls = _order(monkeypatch, locked=False)
    plan = P.Plan(source=str(tmp_path / "proj"), backing=str(tmp_path / "proj.real"),
                  mountpoint=str(tmp_path / "proj"), will_lock=True)
    P.unprotect(plan)
    assert [c[0] for c in calls] == ["move", "unlock"], calls
    assert calls[1][1] == plan.source          # unlocked at its FINAL path


def test_unprotect_reports_a_lock_that_survived(tmp_path, monkeypatch):
    calls = _order(monkeypatch, locked=True)
    plan = P.Plan(source=str(tmp_path / "proj"), backing=str(tmp_path / "proj.real"),
                  mountpoint=str(tmp_path / "proj"), will_lock=True)
    done = P.unprotect(plan)
    assert any("COULD NOT UNLOCK" in d for d in done), done


def test_unprotect_falls_back_to_the_exit_code_when_it_cannot_check(tmp_path, monkeypatch):
    """is_locked answers None on every non-Windows machine. "I could not
    check" must not become "unlocked"."""
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "is_locked", lambda p: None)
    monkeypatch.setattr(P.os, "rename", lambda a, b: None)
    plan = P.Plan(source=str(tmp_path / "proj"), backing=str(tmp_path / "proj.real"),
                  mountpoint=str(tmp_path / "proj"), will_lock=True)

    monkeypatch.setattr(P, "unlock_directory", lambda p: False)
    assert any("COULD NOT UNLOCK" in d for d in P.unprotect(plan))
    monkeypatch.setattr(P, "unlock_directory", lambda p: True)
    assert any(d.startswith("unlocked") for d in P.unprotect(plan))
