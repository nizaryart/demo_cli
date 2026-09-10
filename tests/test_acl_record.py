r"""The permissions a project had before it was protected.

Finding #12. unlock_directory ends in `icacls /reset`, which restores the
PARENT's inheritable ACEs - not the ACL that was there. For an ordinary
project those are the same thing. For a project with permissions of its own
they are not, and the difference always runs one way: wider. A directory
reachable only by its owner came back reachable by Administrators and SYSTEM
too, and protect/unprotect is advertised as a round trip.

The SDDL read and write are Windows-only. Everything that DECIDES - what is
worth recording, which paths may be written to, what is reported - is pure
and runs here.
"""
import json
import os

import pytest

from demo_cli import protect as P

F = P._FULL_CONTROL
OICI = P._OI | P._CI


def _ace(sid, inherited=False, mask=F, flags=OICI):
    return P.Ace(sid, True, mask, flags | (P._INHERITED if inherited else 0),
                 inherited)


# ------------------------------------------------- what is worth recording

def test_an_ordinary_project_records_nothing():
    """Every ACE inherited: /reset reproduces this exactly, so there is
    nothing to store and nothing changes for the normal case."""
    aces = [_ace(P.SYSTEM_SID, inherited=True),
            _ace(P.ADMINS_SID, inherited=True),
            _ace("S-1-5-21-1-2-3-1001", inherited=True)]
    assert P.has_custom_acl(aces) is False


def test_one_explicit_ace_is_worth_recording():
    """This is the lab15 shape: inheritance off, one explicit entry. /reset
    would replace it with three inherited ones."""
    assert P.has_custom_acl([_ace("S-1-5-21-1-2-3-1001")]) is True


def test_an_explicit_ace_among_inherited_ones_is_worth_recording():
    aces = [_ace(P.SYSTEM_SID, inherited=True),
            _ace("S-1-5-21-1-2-3-1001")]
    assert P.has_custom_acl(aces) is True


def test_an_empty_dacl_is_worth_recording():
    """A deliberate "nobody". /reset would turn it into "whatever the parent
    says", which is the widening this record exists to stop."""
    assert P.has_custom_acl([]) is True


def test_an_unreadable_acl_is_not_recorded_as_anything():
    """We cannot record what we cannot read. Guessing would put a lie in the
    record rather than a hole in it."""
    assert P.has_custom_acl(None) is False


# ------------------------------------------------- what may be written to

def test_a_relative_path_inside_the_project_is_allowed(tmp_path):
    (tmp_path / "sub").mkdir()
    assert P.safe_member(str(tmp_path), os.path.join("sub", "f.txt")) == \
        str(tmp_path / "sub" / "f.txt")


def test_a_path_that_climbs_out_is_refused(tmp_path):
    """unprotect applies these while elevated, so this would be an arbitrary
    ACL write as Administrator."""
    assert P.safe_member(str(tmp_path), os.path.join("..", "..", "Windows")) is None


def test_an_absolute_path_is_refused(tmp_path):
    assert P.safe_member(str(tmp_path), os.sep + "etc") is None


def test_a_windows_absolute_path_is_refused_on_any_platform(tmp_path):
    r"""C:\Windows is not absolute to posixpath, and the record is written on
    one machine and read on the same one - but a check that only works on the
    platform the attack does not come from is not a check."""
    assert P.safe_member(str(tmp_path), r"C:\Windows\System32") is None
    assert P.safe_member(str(tmp_path), r"\\server\share") is None


def test_the_root_itself_is_not_a_member(tmp_path):
    assert P.safe_member(str(tmp_path), ".") is None


def test_an_empty_name_is_refused(tmp_path):
    assert P.safe_member(str(tmp_path), "") is None


def test_a_symlink_that_leaves_the_project_is_refused(tmp_path):
    """The record holds names; a link can be planted after it is written."""
    (tmp_path / "proj").mkdir()
    (tmp_path / "outside").mkdir()
    (tmp_path / "proj" / "link").symlink_to(tmp_path / "outside",
                                            target_is_directory=True)
    assert P.safe_member(str(tmp_path / "proj"), os.path.join("link", "x")) is None


# --------------------------------------------------------- storing it

def test_the_record_round_trips(tmp_path):
    rec = {"a.txt": "D:P(A;;FA;;;BA)", os.path.join("sub", "b"): "D:(A;;FA;;;SY)"}
    assert P.write_acl_record(str(tmp_path), rec) is True
    back, problem = P.read_acl_record(str(tmp_path))
    assert problem == ""
    assert back == rec


def test_no_record_is_not_a_problem(tmp_path):
    """A project protected before this existed. Silence is correct."""
    assert P.read_acl_record(str(tmp_path)) == (None, "")


def test_a_corrupt_record_is_reported_rather_than_ignored(tmp_path):
    """Silently falling back to /reset is exactly how permissions went
    missing without anyone noticing."""
    (tmp_path / P.ACL_RECORD_NAME).write_text("{not json", encoding="utf-8")
    record, problem = P.read_acl_record(str(tmp_path))
    assert record is None
    assert "NOT restored" in problem


def test_a_record_of_the_wrong_shape_is_reported(tmp_path):
    (tmp_path / P.ACL_RECORD_NAME).write_text(
        json.dumps({"version": 1, "acls": ["a", "b"]}), encoding="utf-8")
    record, problem = P.read_acl_record(str(tmp_path))
    assert record is None and problem


def test_a_planted_symlink_at_the_record_path_is_not_written_through(tmp_path):
    """open(path, "w") on a symlink truncates its TARGET, and this runs
    elevated. Same defect as the fixed elevated-log path in finding #8."""
    target = tmp_path / "precious.txt"
    target.write_text("do not lose me", encoding="utf-8")
    root = tmp_path / "proj"
    root.mkdir()
    (root / P.ACL_RECORD_NAME).symlink_to(target)

    assert P.write_acl_record(str(root), {"a": "D:"}) is True
    assert target.read_text(encoding="utf-8") == "do not lose me"
    assert not os.path.islink(root / P.ACL_RECORD_NAME)


# --------------------------------------------------------- putting it back

def test_what_is_applied_is_what_was_recorded(tmp_path, monkeypatch):
    applied = []
    monkeypatch.setattr(P, "_apply_sddl",
                        lambda p, s: applied.append((p, s)) or True)
    monkeypatch.setattr(P, "_sddl_of", lambda p: applied[-1][1])
    (tmp_path / "a.txt").write_text("x")
    done, failed = P.restore_custom_acls(str(tmp_path), {"a.txt": "D:P(A;;FA;;;BA)"})
    assert done == 1 and failed == []
    assert applied == [(str(tmp_path / "a.txt"), "D:P(A;;FA;;;BA)")]


def test_an_entry_that_no_longer_exists_is_not_a_failure(tmp_path, monkeypatch):
    """Files change while a project is protected. There is nothing to restore
    a permission onto, and that is not an error."""
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: True)
    done, failed = P.restore_custom_acls(str(tmp_path), {"gone.txt": "D:"})
    assert done == 0 and failed == []


def test_an_entry_outside_the_project_is_refused_and_reported(tmp_path, monkeypatch):
    applied = []
    monkeypatch.setattr(P, "_apply_sddl",
                        lambda p, s: applied.append(p) or True)
    done, failed = P.restore_custom_acls(
        str(tmp_path), {os.path.join("..", "elsewhere"): "D:"})
    assert applied == []
    assert done == 0
    assert failed and "outside the project" in failed[0]


def test_an_entry_that_became_a_link_is_refused(tmp_path, monkeypatch):
    """icacls and SetNamedSecurityInfo both follow a link to its target."""
    applied = []
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: applied.append(p) or True)
    (tmp_path / "outside.txt").write_text("x")
    (tmp_path / "a.txt").symlink_to(tmp_path / "outside.txt")
    done, failed = P.restore_custom_acls(str(tmp_path), {"a.txt": "D:"})
    assert applied == [] and done == 0
    assert failed and "became a link" in failed[0]


def test_a_result_that_does_not_match_the_record_is_a_failure(tmp_path, monkeypatch):
    """SetNamedSecurityInfoW returning success is not evidence that this
    file's permissions are the ones it had. Finding #14, pointed the other
    way: a claim of restoration needs the same evidence as a claim of
    protection."""
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: True)
    monkeypatch.setattr(P, "_sddl_of", lambda p: "D:P(A;;FA;;;WD)")   # Everyone
    (tmp_path / "a.txt").write_text("x")
    done, failed = P.restore_custom_acls(str(tmp_path), {"a.txt": "D:P(A;;FA;;;BA)"})
    assert done == 0
    assert failed and "does not match" in failed[0]


def test_a_result_that_cannot_be_read_back_is_not_counted_as_restored(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: True)
    monkeypatch.setattr(P, "_sddl_of", lambda p: None)
    (tmp_path / "a.txt").write_text("x")
    done, failed = P.restore_custom_acls(str(tmp_path), {"a.txt": "D:P(A;;FA;;;BA)"})
    assert done == 0
    assert failed and "could not be read back" in failed[0]


def test_the_auto_inherited_bit_does_not_count_as_a_mismatch(tmp_path, monkeypatch):
    """Windows sets AI when it re-runs auto-inheritance and offers no way to
    decline (measured on hardware 2026-09-10). It records that the ACL went
    through the inheritance machinery and changes nobody's access, so it must
    not be reported as a failed restore."""
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: True)
    monkeypatch.setattr(P, "_sddl_of",
                        lambda p: "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)")
    (tmp_path / "a.txt").write_text("x")
    done, failed = P.restore_custom_acls(
        str(tmp_path), {"a.txt": "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"})
    assert done == 1 and failed == []


def test_shape_ignores_the_auto_inherited_bit_and_nothing_else():
    same = ("D:(A;OICIID;FA;;;SY)", "D:AI(A;OICIID;FA;;;SY)")
    assert P.dacl_shape(same[0]) == P.dacl_shape(same[1])
    # but a changed principal, mask or protection is a different shape
    assert P.dacl_shape("D:(A;;FA;;;SY)") != P.dacl_shape("D:(A;;FA;;;BA)")
    assert P.dacl_shape("D:(A;;FA;;;SY)") != P.dacl_shape("D:(A;;FR;;;SY)")
    assert P.dacl_shape("D:P(A;;FA;;;SY)") != P.dacl_shape("D:(A;;FA;;;SY)")


def test_a_failed_apply_is_counted_not_swallowed(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_apply_sddl", lambda p, s: False)
    (tmp_path / "a.txt").write_text("x")
    done, failed = P.restore_custom_acls(str(tmp_path), {"a.txt": "D:"})
    assert done == 0 and failed == ["a.txt"]


# ------------------------------------------------------- the SDDL flags

def test_a_protected_acl_is_recognised_as_protected():
    """Restoring a protected ACL as unprotected lets the parent's ACEs back
    in - which is the exact loss this record exists to prevent."""
    assert P._sddl_is_protected("D:PAI(A;OICI;FA;;;BA)") is True
    assert P._sddl_is_protected("D:P(A;OICI;FA;;;BA)") is True


def test_an_inheriting_acl_is_not_recognised_as_protected():
    assert P._sddl_is_protected("D:AI(A;OICIID;FA;;;BA)") is False
    assert P._sddl_is_protected("D:(A;OICI;FA;;;BA)") is False


@pytest.mark.skipif(os.name == "nt", reason="there is a real descriptor here")
def test_the_sddl_calls_are_inert_off_windows(tmp_path):
    assert P._sddl_of(str(tmp_path)) is None
    assert P._apply_sddl(str(tmp_path), "D:P(A;;FA;;;BA)") is False
    assert P.capture_custom_acls(str(tmp_path)) == {}


@pytest.mark.skipif(os.name != "nt", reason="needs a real security descriptor")
def test_a_recorded_descriptor_goes_back_exactly(tmp_path):
    """The only test that exercises _sddl_of and _apply_sddl TOGETHER.

    Everything else in this file stubs them, so the whole record layer could
    be correct around two functions that do not work. Capture, change,
    restore, compare - which is exactly what protect and unprotect do to a
    project, at the size of one directory.

    The intermediate state grants OWNER RIGHTS full control, so the account
    running the test keeps access even if this fails halfway. A test that
    leaves a directory nobody can delete is how the Windows suite crashed in
    its own teardown on 2026-09-10.
    """
    d = tmp_path / "sub"
    d.mkdir()
    original = P._sddl_of(str(d))
    assert original and original.startswith("D:"), original
    try:
        assert P._apply_sddl(str(d), "D:P(A;OICI;FA;;;OW)") is True
        assert P._sddl_of(str(d)) != original
    finally:
        assert P._apply_sddl(str(d), original) is True
    # Compared at the level the round trip is actually true: the entries, and
    # whether inheritance is blocked. Windows sets the AI control bit when it
    # re-runs auto-inheritance and offers no way to decline - see dacl_shape.
    # Everything that decides access is compared exactly.
    assert P.dacl_shape(P._sddl_of(str(d))) == P.dacl_shape(original)


@pytest.mark.skipif(os.name != "nt", reason="needs a real security descriptor")
def test_an_entry_with_only_inherited_permissions_is_not_recorded(tmp_path):
    """The claim that an ordinary project costs nothing, on real ACLs rather
    than on hand-built Ace lists."""
    d = tmp_path / "sub"
    d.mkdir()
    (d / "plain.txt").write_text("x")
    assert P.has_custom_acl(P._read_dacl(str(d / "plain.txt"))) is False
    assert P.capture_custom_acls(str(d)) == {}


# --------------------------------------------------------------------------
# Where it sits in protect and unprotect
#
# The ordering IS the fix. Capturing after the lock records our own ACL;
# restoring before the /reset has it immediately overwritten. Neither shows
# up in a unit test of the pieces.

def _plan(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    return P.Plan(source=str(src), backing=str(tmp_path / "proj.real"),
                  mountpoint=str(src), will_lock=True)


def _seq(monkeypatch, *, record=None, locked=True):
    calls = []
    monkeypatch.setattr(P, "is_elevated", lambda: True)
    monkeypatch.setattr(P, "is_locked", lambda p: locked)
    monkeypatch.setattr(P, "lock_directory",
                        lambda p: calls.append("lock") or True)
    monkeypatch.setattr(P, "unlock_directory",
                        lambda p: calls.append("unlock") or True)
    monkeypatch.setattr(P, "capture_custom_acls",
                        lambda p: calls.append("capture") or dict(record or {}))
    monkeypatch.setattr(P, "write_acl_record",
                        lambda p, r: calls.append("write") or True)
    monkeypatch.setattr(P.Backing, "relocate",
                        staticmethod(lambda a, b: calls.append("move")))
    monkeypatch.setattr(P.os, "rename", lambda a, b: calls.append("move"))
    return calls


def test_the_permissions_are_captured_before_the_lock_replaces_them(tmp_path, monkeypatch):
    """lock_directory gives every entry an explicit ACL of our own making.
    Capture after it and the record is a photograph of the lock."""
    calls = _seq(monkeypatch, record={"a.txt": "D:P(A;;FA;;;BA)"})
    P.protect(_plan(tmp_path))
    assert calls.index("capture") < calls.index("lock"), calls


def test_the_record_is_written_only_into_a_locked_directory(tmp_path, monkeypatch):
    """unprotect applies it while elevated, so anything that can write it can
    write an ACL as Administrator."""
    calls = _seq(monkeypatch, record={"a.txt": "D:P(A;;FA;;;BA)"})
    P.protect(_plan(tmp_path))
    assert calls == ["capture", "lock", "move", "write"], calls


def test_nothing_is_written_when_the_lock_did_not_take(tmp_path, monkeypatch):
    calls = _seq(monkeypatch, record={"a.txt": "D:"}, locked=False)
    P.protect(_plan(tmp_path))
    assert "write" not in calls, calls


def test_an_ordinary_project_writes_no_record_at_all(tmp_path, monkeypatch):
    calls = _seq(monkeypatch, record={})
    done = P.protect(_plan(tmp_path))
    assert "write" not in calls, calls
    assert not any("recorded" in d for d in done), done


def test_protect_says_how_many_it_recorded(tmp_path, monkeypatch):
    _seq(monkeypatch, record={"a.txt": "D:", "b.txt": "D:"})
    done = P.protect(_plan(tmp_path))
    assert any("recorded the permissions of 2 entries" in d for d in done), done


def test_a_record_that_could_not_be_stored_is_not_passed_over(tmp_path, monkeypatch):
    _seq(monkeypatch, record={"a.txt": "D:"})
    monkeypatch.setattr(P, "write_acl_record", lambda p, r: False)
    done = P.protect(_plan(tmp_path))
    assert any("COULD NOT RECORD" in d for d in done), done


def test_unprotect_reads_before_the_reset_and_restores_after_it(tmp_path, monkeypatch):
    """/reset overwrites the ACL of every entry the record names - including
    the record's own - so it has to be read first and applied last."""
    calls = _seq(monkeypatch, locked=False)
    monkeypatch.setattr(P, "read_acl_record",
                        lambda p: calls.append("read") or ({"a.txt": "D:"}, ""))
    monkeypatch.setattr(P, "restore_custom_acls",
                        lambda p, r: calls.append("restore") or (1, []))
    plan = _plan(tmp_path)
    P.unprotect(plan)
    assert calls == ["move", "read", "unlock", "restore"], calls


def test_unprotect_says_how_many_it_restored(tmp_path, monkeypatch):
    _seq(monkeypatch, locked=False)
    monkeypatch.setattr(P, "read_acl_record", lambda p: ({"a.txt": "D:"}, ""))
    monkeypatch.setattr(P, "restore_custom_acls", lambda p, r: (1, []))
    done = P.unprotect(_plan(tmp_path))
    assert any("restored the permissions of 1 entry" in d for d in done), done


def test_entries_that_could_not_be_restored_are_named(tmp_path, monkeypatch):
    _seq(monkeypatch, locked=False)
    monkeypatch.setattr(P, "read_acl_record", lambda p: ({"a.txt": "D:"}, ""))
    monkeypatch.setattr(P, "restore_custom_acls", lambda p, r: (0, ["a.txt"]))
    done = P.unprotect(_plan(tmp_path))
    assert any("COULD NOT RESTORE" in d and "a.txt" in d for d in done), done


def test_a_corrupt_record_stops_the_restore_and_says_so(tmp_path, monkeypatch):
    calls = _seq(monkeypatch, locked=False)
    monkeypatch.setattr(P, "read_acl_record",
                        lambda p: (None, "the record could not be read; NOT restored"))
    monkeypatch.setattr(P, "restore_custom_acls",
                        lambda p, r: calls.append("restore") or (0, []))
    done = P.unprotect(_plan(tmp_path))
    assert "restore" not in calls, calls
    assert any("NOT restored" in d for d in done), done


def test_the_record_does_not_stay_in_the_restored_project(tmp_path, monkeypatch):
    """It is demo_cli's bookkeeping, not the user's file."""
    _seq(monkeypatch, locked=False)
    plan = _plan(tmp_path)
    # Written directly: _seq stubs write_acl_record, so calling it here would
    # record a call and create no file.
    with open(os.path.join(plan.source, P.ACL_RECORD_NAME), "w",
              encoding="utf-8") as f:
        json.dump({"version": 1, "acls": {"a.txt": "D:"}}, f)
    monkeypatch.setattr(P, "restore_custom_acls", lambda p, r: (1, []))
    assert os.path.exists(os.path.join(plan.source, P.ACL_RECORD_NAME))
    P.unprotect(plan)
    assert not os.path.exists(os.path.join(plan.source, P.ACL_RECORD_NAME))


def test_an_unelevated_unprotect_touches_no_record(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(P, "is_elevated", lambda: False)
    monkeypatch.setattr(P.os, "rename", lambda a, b: None)
    monkeypatch.setattr(P, "read_acl_record",
                        lambda p: calls.append("read") or (None, ""))
    P.unprotect(_plan(tmp_path))
    assert calls == [], "an unelevated run cannot apply an ACL and must not try"


# --------------------------------------------------------------------------
# The capture walk
#
# _read_dacl and _sddl_of are the only Windows-only parts; stub those and the
# walk itself runs anywhere. It had an `if os.name != "nt": return {}` at the
# top, which made every line below it unreachable here - and a revert that
# deleted its reparse-point check broke nothing at all.

@pytest.fixture
def fake_acls(monkeypatch):
    """Every entry has a custom ACL, and the SDDL names the path."""
    monkeypatch.setattr(P, "_read_dacl", lambda p: [_ace("S-1-5-21-1-2-3-1001")])
    monkeypatch.setattr(P, "_sddl_of", lambda p: "D:P(A;;FA;;;" + os.path.basename(p) + ")")


def test_the_capture_walks_the_whole_tree(tmp_path, fake_acls):
    (tmp_path / "sub" / "deep").mkdir(parents=True)
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub" / "b.txt").write_text("b")
    (tmp_path / "sub" / "deep" / "c.txt").write_text("c")
    got = P.capture_custom_acls(str(tmp_path))
    assert set(got) == {"a.txt", "sub", os.path.join("sub", "b.txt"),
                        os.path.join("sub", "deep"),
                        os.path.join("sub", "deep", "c.txt")}


def test_the_capture_records_relative_paths(tmp_path, fake_acls):
    """Absolute paths in the record would defeat the containment check on the
    way back out, which is the only thing standing between a lying record and
    an elevated ACL write."""
    (tmp_path / "a.txt").write_text("a")
    for rel in P.capture_custom_acls(str(tmp_path)):
        assert not os.path.isabs(rel), rel


def test_the_capture_never_records_a_link(tmp_path, fake_acls):
    """A junction's ACL belongs to its target, which is not part of this
    project - and restoring it later would write outside the tree."""
    (tmp_path / "proj").mkdir()
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("x")
    (tmp_path / "proj" / "a.txt").write_text("a")
    (tmp_path / "proj" / "link").symlink_to(tmp_path / "outside",
                                            target_is_directory=True)
    got = P.capture_custom_acls(str(tmp_path / "proj"))
    assert "a.txt" in got
    assert "link" not in got
    assert not any("secret" in k for k in got), got


def test_the_capture_does_not_descend_through_a_link(tmp_path, fake_acls):
    (tmp_path / "proj").mkdir()
    (tmp_path / "outside" / "inner").mkdir(parents=True)
    (tmp_path / "proj" / "link").symlink_to(tmp_path / "outside",
                                            target_is_directory=True)
    assert P.capture_custom_acls(str(tmp_path / "proj")) == {}


def test_an_entry_whose_acl_cannot_be_read_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_read_dacl", lambda p: None)
    monkeypatch.setattr(P, "_sddl_of", lambda p: "D:P(A;;FA;;;BA)")
    (tmp_path / "a.txt").write_text("a")
    assert P.capture_custom_acls(str(tmp_path)) == {}


def test_an_entry_with_no_sddl_is_skipped(tmp_path, monkeypatch):
    """has_custom_acl said yes and the read then failed. A record with a hole
    in it beats a record with a lie in it."""
    monkeypatch.setattr(P, "_read_dacl", lambda p: [_ace("S-1-5-21-1-2-3-1001")])
    monkeypatch.setattr(P, "_sddl_of", lambda p: None)
    (tmp_path / "a.txt").write_text("a")
    assert P.capture_custom_acls(str(tmp_path)) == {}


def test_an_unreadable_subdirectory_does_not_stop_the_walk(tmp_path, monkeypatch, fake_acls):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("a")
    real = os.listdir
    monkeypatch.setattr(P.os, "listdir",
                        lambda p: (_ for _ in ()).throw(PermissionError())
                        if str(p).endswith("sub") else real(p))
    assert "a.txt" in P.capture_custom_acls(str(tmp_path))
