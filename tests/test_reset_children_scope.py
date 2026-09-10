r"""_reset_children must never leave the project.

Finding #11. `icacls <dir>\* /reset /T /Q` was one call, and /T is icacls's
own recursion - which follows reparse points. One junction inside the project
and an ELEVATED icacls resets ACLs on files that were never part of it. It
runs during unprotect as well, which is the moment a user is least expecting
damage.

Every test here builds a real tree with real symlinks and records exactly
which paths icacls was asked to touch. The assertion that matters is always
the same: nothing outside the project is ever named.
"""
import os

import pytest

from demo_cli import protect as P


@pytest.fixture
def icacls(monkeypatch):
    """Records the arguments instead of running anything."""
    seen = []
    monkeypatch.setattr(P, "_run", lambda args: seen.append(list(args)) or True)
    return seen


# icacls switches, listed rather than detected. Detecting them by a leading
# "/" is what made the first version of this helper return an empty list on
# Linux, where every absolute path begins with one - and three tests that
# assert a path is NOT present passed against nothing at all.
_SWITCHES = {"/reset", "/T", "/Q", "/C", "/inheritance:r", "/inheritance:e"}


def _named(seen):
    """Every path icacls was pointed at, with the trailing wildcard removed."""
    out = []
    for args in seen:
        for a in args[1:]:
            if a in _SWITCHES or a.startswith("/grant"):
                continue
            out.append(a[:-2] if a.endswith(os.sep + "*") else a)
    assert out, "the helper matched nothing; it is filtering out the paths"
    return out


def _tree(root):
    (root / "proj" / "sub").mkdir(parents=True)
    (root / "proj" / "a.txt").write_text("a")
    (root / "proj" / "sub" / "b.txt").write_text("b")
    (root / "outside").mkdir()
    (root / "outside" / "secret.txt").write_text("not yours")
    return root / "proj"


# ------------------------------------------------------- the clean tree

def test_a_tree_with_no_links_still_takes_one_call(tmp_path, icacls):
    """Correctness must not cost every user a slow protect. With nothing in
    the tree to follow, /T is provably safe and stays."""
    proj = _tree(tmp_path)
    assert P._reset_children(str(proj)).ok is True
    assert len(icacls) == 1
    assert "/T" in icacls[0]


def test_an_empty_directory_asks_for_nothing(tmp_path, icacls):
    d = tmp_path / "empty"
    d.mkdir()
    assert P._reset_children(str(d)).ok is True
    assert icacls == []


# ------------------------------------------------------- the linked tree

def test_a_link_out_of_the_project_stops_icacls_recursing(tmp_path, icacls):
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    assert not any("/T" in args for args in icacls), icacls


def test_nothing_outside_the_project_is_ever_named(tmp_path, icacls):
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    outside = str(tmp_path / "outside")
    for named in _named(icacls):
        assert not os.path.realpath(named).startswith(os.path.realpath(outside)), named


def test_the_link_itself_is_never_named(tmp_path, icacls):
    """icacls follows a link it is pointed at, so naming the link IS naming
    the target. A wildcard would have matched it."""
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    assert str(proj / "link") not in _named(icacls)


def test_the_real_children_are_still_reset(tmp_path, icacls):
    """Refusing to touch anything would also pass the tests above. The files
    that ARE in the project must still inherit the new ACL."""
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    named = _named(icacls)
    assert str(proj / "a.txt") in named
    assert str(proj / "sub") in named
    assert str(proj / "sub" / "b.txt") in named or \
        os.path.join(str(proj / "sub"), "*") in [
            a for args in icacls for a in args[1:]]


def test_a_link_deep_in_the_tree_is_found_too(tmp_path, icacls):
    """The scan is the whole tree, not the top of it."""
    proj = _tree(tmp_path)
    (proj / "sub" / "deep").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    assert not any("/T" in args for args in icacls), icacls
    assert str(proj / "sub" / "deep") not in _named(icacls)


def test_a_symlinked_file_is_left_alone(tmp_path, icacls):
    """Not only directories. icacls on a file symlink resets the target."""
    proj = _tree(tmp_path)
    (proj / "flink").symlink_to(tmp_path / "outside" / "secret.txt")
    P._reset_children(str(proj))
    named = _named(icacls)
    assert str(proj / "flink") not in named
    assert str(tmp_path / "outside" / "secret.txt") not in named
    assert str(proj / "a.txt") in named


def test_a_directory_containing_a_link_names_its_children_one_by_one(tmp_path, icacls):
    """Inside a directory that holds a link there is no safe wildcard, so the
    entries have to be named individually."""
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    P._reset_children(str(proj))
    top = [args for args in icacls
           if any(a.startswith(str(proj)) and os.path.dirname(a) == str(proj)
                  for a in args[1:])]
    assert top and not any(a.endswith("*") for args in top for a in args[1:])


def test_a_clean_subdirectory_under_a_dirty_one_still_uses_a_wildcard(tmp_path, icacls):
    """The careful path is per DIRECTORY, not per file everywhere. A
    subdirectory with no link in it costs one call, not one per entry."""
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    for i in range(5):
        (proj / "sub" / f"f{i}.txt").write_text("x")
    P._reset_children(str(proj))
    wildcards = [a for args in icacls for a in args[1:] if a.endswith("*")]
    assert os.path.join(str(proj / "sub"), "*") in wildcards


# ------------------------------------------------------- failure reporting

def test_a_child_that_fails_makes_the_whole_thing_false(tmp_path, monkeypatch):
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    monkeypatch.setattr(P, "_run", lambda args: False)
    assert P._reset_children(str(proj)).ok is False


def test_an_unreadable_subtree_is_not_handed_to_icacls_recursion(tmp_path, monkeypatch, icacls):
    """A directory that cannot be listed cannot be checked for links either,
    so /T must not be trusted with the tree that contains it."""
    proj = _tree(tmp_path)
    real = os.listdir

    def _blind(p):
        if p.endswith("sub"):
            raise PermissionError("nope")
        return real(p)
    monkeypatch.setattr(P.os, "listdir", _blind)
    P._reset_children(str(proj))
    assert not any("/T" in args for args in icacls), icacls


def test_an_entry_that_cannot_be_stated_is_treated_as_a_link(tmp_path):
    """Unknown means do not touch."""
    missing = str(tmp_path / "gone")
    assert P._is_reparse_point(missing) is True


def test_a_plain_directory_is_not_a_reparse_point(tmp_path):
    assert P._is_reparse_point(str(tmp_path)) is False


# --------------------------------------------------------------------------
# The junction, which is the whole reason #11 was invisible
#
# On Windows a junction is NOT a symlink. os.path.islink has answered False
# for them, os.path.isdir answers True, and os.stat follows them - so to
# every check except the reparse attribute a junction is indistinguishable
# from an ordinary subdirectory. Linux has no junctions, so the attribute is
# simulated; without these two tests, replacing the attribute check with
# os.path.islink breaks nothing on Linux and reopens the finding on Windows.

def _windows_stat(real, attrs):
    class _St:
        st_file_attributes = attrs

        def __getattr__(self, name):
            return getattr(real, name)
    return _St()


def test_a_junction_is_caught_by_the_attribute_not_by_islink(tmp_path, monkeypatch):
    import stat as _stat
    d = tmp_path / "plain"
    d.mkdir()
    real = os.lstat(str(d))
    monkeypatch.setattr(P.os, "lstat", lambda p: _windows_stat(
        real, _stat.FILE_ATTRIBUTE_REPARSE_POINT | _stat.FILE_ATTRIBUTE_DIRECTORY))

    assert not os.path.islink(str(d)), "islink would have to be lying for this to be a fair test"
    assert P._is_reparse_point(str(d)) is True


def test_an_ordinary_windows_directory_is_not_treated_as_a_link(tmp_path, monkeypatch):
    """The other direction: the attribute check must not make everything on
    Windows look like a junction, or nothing would ever be reset."""
    import stat as _stat
    d = tmp_path / "plain"
    d.mkdir()
    real = os.lstat(str(d))
    monkeypatch.setattr(P.os, "lstat", lambda p: _windows_stat(
        real, _stat.FILE_ATTRIBUTE_DIRECTORY))
    assert P._is_reparse_point(str(d)) is False


def test_the_scan_uses_the_attribute_too(tmp_path, monkeypatch):
    """_reparse_points_under decides whether icacls's own /T can be trusted,
    so it has to see junctions as well."""
    import stat as _stat
    proj = _tree(tmp_path)
    real = os.lstat(str(proj / "sub"))
    orig = os.lstat

    def _fake(p):
        if str(p) == str(proj / "sub"):
            return _windows_stat(real, _stat.FILE_ATTRIBUTE_REPARSE_POINT
                                 | _stat.FILE_ATTRIBUTE_DIRECTORY)
        return orig(p)
    monkeypatch.setattr(P.os, "lstat", _fake)
    assert str(proj / "sub") in P._reparse_points_under(str(proj))


# --------------------------------------------------------------------------
# What the reset REPORTS
#
# Finding #3. icacls without /C stops at the first error, so a tree could come
# back with some children reset and some not - and every one of those outcomes
# reported the same word: False. The caller said "COULD NOT LOCK", which is
# wrong in both directions. It is not true that nothing was locked, and it
# hides the only part that matters: which entries are not covered, because
# those are the bypass routes.

def _fail_on(monkeypatch, needle):
    r"""A fake icacls that refuses any entry whose path contains `needle`.

    IT HAS TO MODEL THE RECURSION. The first version just looked at the
    arguments, so `icacls <dir>\* /reset /T` - which never names the file it
    is about to choke on - came back SUCCESS, and three tests about partial
    failure passed against an outcome that had no failures in it. The point
    of /T is that it walks; a fake that does not walk is testing nothing.
    """
    seen = []

    def _under(d):
        for base, dirs, files in os.walk(d):
            for n in dirs + files:
                yield os.path.join(base, n)

    def _run(args):
        seen.append(list(args))
        target = args[1]
        if target.endswith(os.sep + "*"):
            d = target[:-2]
            if "/T" in args:
                return not any(needle in p for p in _under(d))
            try:
                return not any(needle in n for n in os.listdir(d))
            except OSError:
                return False
        return needle not in target

    monkeypatch.setattr(P, "_run", _run)
    return seen


def test_a_partial_failure_is_not_reported_as_a_total_one(tmp_path, monkeypatch):
    proj = _tree(tmp_path)
    _fail_on(monkeypatch, "b.txt")
    out = P._reset_children(str(proj))
    assert out.ok is False
    assert len(out.failed) == 1
    assert out.failed[0].endswith("b.txt"), out.failed


def test_the_entries_that_failed_are_named(tmp_path, monkeypatch):
    """A count says something is wrong. The names say what to go and look at."""
    proj = _tree(tmp_path)
    (proj / "c.txt").write_text("c")
    _fail_on(monkeypatch, ".txt")
    out = P._reset_children(str(proj))
    assert {os.path.basename(f) for f in out.failed} == {"a.txt", "b.txt", "c.txt"}


def test_a_wildcard_that_fails_is_retried_one_by_one_to_find_out_which(tmp_path, monkeypatch):
    """/T stops somewhere and will not say where. One bool for a whole tree
    IS the finding, so the careful walk is paid for once something is already
    wrong - and the user gets names instead of a shrug."""
    proj = _tree(tmp_path)
    seen = _fail_on(monkeypatch, "b.txt")
    out = P._reset_children(str(proj))
    assert any("/T" in args for args in seen), "the fast path should be tried first"
    assert out.failed and all("/T" not in f for f in out.failed)
    assert out.failed[0].endswith("b.txt")


def test_a_tree_that_resets_cleanly_reports_nothing_to_look_at(tmp_path, icacls):
    proj = _tree(tmp_path)
    out = P._reset_children(str(proj))
    assert out.ok is True
    assert out.failed == [] and out.links == []


def test_links_are_reported_without_being_called_failures(tmp_path, icacls):
    """Skipping them was right (finding #11). An entry the lock does not
    cover is still worth naming."""
    proj = _tree(tmp_path)
    (proj / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    out = P._reset_children(str(proj))
    assert out.ok is True
    assert out.failed == []
    assert [os.path.basename(l) for l in out.links] == ["link"]


def test_an_unreadable_directory_is_named_rather_than_counted(tmp_path, monkeypatch, icacls):
    proj = _tree(tmp_path)
    real = os.listdir
    monkeypatch.setattr(P.os, "listdir",
                        lambda p: (_ for _ in ()).throw(PermissionError())
                        if str(p).endswith("sub") else real(p))
    out = P._reset_children(str(proj))
    assert out.ok is False
    assert any(f.endswith("sub") for f in out.failed), out.failed


def test_the_outcome_is_still_usable_as_a_yes_or_no(tmp_path, icacls):
    """Callers that only want to know whether it worked keep working."""
    proj = _tree(tmp_path)
    assert bool(P._reset_children(str(proj))) is True
    assert bool(P.ResetOutcome(False)) is False


def test_a_lock_whose_grant_failed_names_the_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(P.os, "name", "nt")
    monkeypatch.setattr(P, "_icacls_present", lambda: True)
    monkeypatch.setattr(P, "_run", lambda args: False)
    out = P.lock_directory(str(tmp_path))
    assert out.ok is False
    assert out.failed == [str(tmp_path)]
