"""Filesystem correctness for the Stage 2 passthrough.

This suite exists because of a change in what failure MEANS. Stage 1 kept
files in a Python dict, so its worst case was losing scratch data. Stage 2
writes somebody's real files, and a filesystem that is subtly wrong corrupts
work without announcing itself.

So the rule for this module is: it does not get pointed at anything anyone
cares about until this file is green. Everything here is ordinary Python I/O
against an ordinary directory, so it runs on Linux where the work is done -
the same split that let fsguard's 39 tests run off Windows.

Two things are tested harder than the rest, because they are where a
filesystem hurts people:

  * CONTAINMENT. Every virtual path must land inside the backing directory. A
    guard that can be talked into writing to C:\\Windows by a '..' is not a
    guard, and "the caller would never send that" is not an argument when a
    confused or malicious agent is the threat model.
  * BYTE EXACTNESS. Write it, read it back, and get the same bytes - at
    offsets, past the end, across truncation, with empty and binary content.
"""
import os
import threading

import pytest

from demo_cli.fspassthrough import (Attrs, Backing, PathEscape,
                                    is_directory_not_empty, normalize)


@pytest.fixture
def backing(tmp_path):
    root = tmp_path / "project.real"
    root.mkdir()
    return Backing(str(root))


# --------------------------------------------------------------------------
# Path normalisation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (r"\notes.txt", "notes.txt"),
    (r"\src\app.py", "src/app.py"),
    ("\\", ""),
    ("", ""),
    (None, ""),
    (r"\a\b\c.txt", "a/b/c.txt"),
    ("/already/posix", "already/posix"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_the_root_resolves_to_the_backing_directory(backing):
    assert backing.resolve("\\") == backing.root
    assert backing.resolve(None) == backing.root


# --------------------------------------------------------------------------
# CONTAINMENT - the security property this module owns
# --------------------------------------------------------------------------

@pytest.mark.parametrize("attack", [
    r"\..\outside.txt",
    r"\..\..\etc\passwd",
    r"\src\..\..\outside.txt",
    r"\a\b\..\..\..\x",
    "../outside.txt",
])
def test_traversal_is_refused(backing, attack):
    with pytest.raises(PathEscape):
        backing.resolve(attack)


@pytest.mark.parametrize("attack", [
    r"\C:\Windows\System32\drivers\etc\hosts",
    r"\D:\secrets",
])
def test_a_drive_qualified_component_is_refused(backing, attack):
    """os.path.join discards everything before an absolute component, so
    without this check the join would quietly produce a path with no relation
    to the backing directory at all.

    os.path.isabs('C:') is False on Linux, which is why the drive-letter shape
    is tested for separately - the check has to hold on the platform the
    developer sits on, not only on the one it defends.
    """
    with pytest.raises(PathEscape):
        backing.resolve(attack)


def test_a_leading_slash_run_is_contained_not_an_escape(backing):
    """`\\/etc/passwd` LOOKS like an absolute Unix path and is not one: leading
    separators are stripped, leaving the relative `etc/passwd`, which lands
    inside the backing directory like any other name. Refusing it would be
    superstition - containment is what matters, not resemblance."""
    resolved = backing.resolve(r"\/etc/passwd")
    assert resolved.startswith(backing.root)
    assert resolved.endswith(os.path.join("etc", "passwd"))


def test_a_dotdot_that_stays_inside_is_still_refused(backing):
    """`src/../notes.txt` is harmless once resolved, and is refused anyway.
    Structural rejection beats reasoning about which traversals are safe -
    the reasoning is where the holes come from."""
    with pytest.raises(PathEscape):
        backing.resolve(r"\src\..\notes.txt")


def test_a_single_dot_is_not_traversal(backing):
    """'.' cannot leave a directory, so refusing it would only break callers."""
    assert backing.resolve(r"\.\notes.txt").endswith("notes.txt")


def test_exists_returns_false_for_an_escaping_path_rather_than_raising(backing):
    """Probing must not become a way to find out what is outside."""
    assert backing.exists(r"\..\..\etc\passwd") is False
    assert backing.is_dir(r"\..\..") is False


def test_a_filename_that_merely_contains_dots_is_fine(backing):
    backing.make_file(r"\..hidden")
    backing.make_file(r"\a..b.txt")
    assert set(backing.listdir("\\")) == {"..hidden", "a..b.txt"}


# --------------------------------------------------------------------------
# Create, read, write - byte exactness
# --------------------------------------------------------------------------

def test_a_new_file_is_empty(backing):
    backing.make_file(r"\notes.txt")
    assert backing.read_all(r"\notes.txt") == b""
    assert backing.attrs(r"\notes.txt").size == 0


def test_creating_over_an_existing_file_is_refused(backing):
    """'x' not 'w'. A create that silently truncates would destroy data BELOW
    the level the guard inspects, with no hook able to see it happen."""
    backing.make_file(r"\notes.txt")
    with pytest.raises(FileExistsError):
        backing.make_file(r"\notes.txt")


@pytest.mark.parametrize("data", [
    pytest.param(b"hello", id="ascii"),
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00\x01\x02\xff\xfe", id="binary-with-nuls"),
    pytest.param(b"line one\r\nline two\r\n", id="crlf"),
    # Explicit id, not the default repr. pytest puts the test id in
    # PYTEST_CURRENT_TEST, and Windows caps an environment variable at
    # 32767 characters - so 100 KB of bytes in the id made this ERROR at
    # SETUP on Windows while passing on Linux. Found 2026-08-25.
    pytest.param(bytes(range(256)) * 400, id="100kb-all-byte-values"),
])
def test_write_then_read_returns_the_same_bytes(backing, data):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        assert backing.write_at(fd, data, 0) == len(data)
    finally:
        os.close(fd)
    assert backing.read_all(r"\f.bin") == data


def test_writing_at_an_offset_leaves_earlier_bytes_alone(backing):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"AAAABBBB", 0)
        backing.write_at(fd, b"CC", 4)
    finally:
        os.close(fd)
    assert backing.read_all(r"\f.bin") == b"AAAACCBB"


def test_writing_past_the_end_zero_fills_the_gap(backing):
    """Standard POSIX and Win32 behaviour. A filesystem that does not do this
    silently changes what an application reads back."""
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"X", 8)
    finally:
        os.close(fd)
    assert backing.read_all(r"\f.bin") == b"\x00" * 8 + b"X"


def test_reading_at_an_offset(backing):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"0123456789", 0)
        assert backing.read_at(fd, 3, 4) == b"3456"
    finally:
        os.close(fd)


def test_reading_past_the_end_returns_what_exists(backing):
    """A short read at end-of-file is normal, not an error."""
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"abc", 0)
        assert backing.read_at(fd, 1, 100) == b"bc"
        assert backing.read_at(fd, 50, 10) == b""
    finally:
        os.close(fd)


def test_truncating_discards_the_tail_and_keeps_the_head(backing):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"0123456789", 0)
        backing.set_size_fd(fd, 4)
        assert backing.size_of_fd(fd) == 4
    finally:
        os.close(fd)
    assert backing.read_all(r"\f.bin") == b"0123"


def test_growing_by_set_size_zero_fills(backing):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.write_at(fd, b"ab", 0)
        backing.set_size_fd(fd, 5)
    finally:
        os.close(fd)
    assert backing.read_all(r"\f.bin") == b"ab\x00\x00\x00"


def test_opening_read_only_refuses_a_write(backing):
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin", write=False)
    try:
        with pytest.raises(OSError):
            backing.write_at(fd, b"x", 0)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# Directories
# --------------------------------------------------------------------------

def test_directories_nest(backing):
    backing.make_dir(r"\src")
    backing.make_dir(r"\src\util")
    backing.make_file(r"\src\util\a.py")
    assert backing.listdir(r"\src\util") == ["a.py"]
    assert backing.is_dir(r"\src\util")


def test_listing_is_sorted(backing):
    """WinFsp pages through a directory with a marker. An unstable order makes
    entries appear twice or vanish between pages, and that only shows up on
    big directories - i.e. in production."""
    for name in ["zebra.txt", "apple.txt", "Mango.txt", "banana.txt"]:
        backing.make_file("\\" + name)
    assert backing.listdir("\\") == sorted(backing.listdir("\\"))


def test_a_directory_reports_size_zero(backing):
    """A directory's on-disk size differs per filesystem and means nothing to
    the caller. Reporting 0 makes the mount look the same everywhere."""
    backing.make_dir(r"\src")
    assert backing.attrs(r"\src") == Attrs(is_dir=True, size=0,
                                           ctime=backing.attrs(r"\src").ctime,
                                           atime=backing.attrs(r"\src").atime,
                                           mtime=backing.attrs(r"\src").mtime,
                                           readonly=backing.attrs(r"\src").readonly)


def test_listing_a_large_directory_is_complete(backing):
    for i in range(500):
        backing.make_file(f"\\f{i:04d}.txt")
    assert len(backing.listdir("\\")) == 500


# --------------------------------------------------------------------------
# Delete
# --------------------------------------------------------------------------

def test_removing_a_file(backing):
    backing.make_file(r"\gone.txt")
    backing.remove(r"\gone.txt")
    assert not backing.exists(r"\gone.txt")


def test_removing_an_empty_directory(backing):
    backing.make_dir(r"\empty")
    backing.remove(r"\empty")
    assert not backing.exists(r"\empty")


def test_removing_a_NON_empty_directory_is_refused(backing):
    """Windows deletes a tree leaf-first, so every file arrives as its own
    operation and every one gets its own verdict from fsguard. A recursive
    delete here would destroy files the guard never saw."""
    backing.make_dir(r"\tree")
    backing.make_file(r"\tree\a.txt")
    with pytest.raises(OSError):
        backing.remove(r"\tree")
    assert backing.exists(r"\tree\a.txt")


# --------------------------------------------------------------------------
# Telling the ONE harmless delete failure from every dangerous one
#
# cleanup() used to swallow every OSError, written for the non-empty-directory
# case. On 2026-08-25 a Remove-Item printed no error, produced a
# "[fs] delete ... snapshotted" line, and left the file in the backing
# directory: the ledger recorded a destruction that never happened, and the
# user's delete never happened either. Both silently.
# --------------------------------------------------------------------------

def test_a_non_empty_directory_is_the_expected_failure(backing):
    backing.make_dir(r"\tree")
    backing.make_file(r"\tree\a.txt")
    try:
        backing.remove(r"\tree")
        pytest.fail("should have refused")
    except OSError as exc:
        assert is_directory_not_empty(exc), \
            "Windows revisits this directory; it must not raise an alarm"


def test_a_missing_file_is_NOT_the_expected_failure(backing):
    """Anything other than 'not empty' means the file the caller asked to
    delete is still there - or was never there - and has to be reported."""
    try:
        backing.remove(r"\nope.txt")
        pytest.fail("should have raised")
    except OSError as exc:
        assert not is_directory_not_empty(exc)


def test_a_permission_failure_is_NOT_swallowed():
    """The shape of the bug: on Windows an open handle without
    FILE_SHARE_DELETE makes the unlink fail with a permission error, which the
    old blanket except turned into silence."""
    exc = PermissionError(13, "Permission denied")
    assert not is_directory_not_empty(exc)


def test_the_windows_error_code_is_recognised_even_off_windows():
    """Python maps ERROR_DIR_NOT_EMPTY (145) to ENOTEMPTY, but the predicate
    checks both spellings so a mapping difference cannot turn the expected
    case into a false alarm."""
    exc = OSError(0, "dir not empty")
    exc.winerror = 145
    assert is_directory_not_empty(exc)


# --------------------------------------------------------------------------
# Rename - the operation with no delete signal
# --------------------------------------------------------------------------

def test_rename_moves_content_to_the_new_name(backing):
    backing.make_file(r"\old.txt")
    fd = backing.open_fd(r"\old.txt")
    try:
        backing.write_at(fd, b"payload", 0)
    finally:
        os.close(fd)
    backing.rename(r"\old.txt", r"\new.txt")
    assert not backing.exists(r"\old.txt")
    assert backing.read_all(r"\new.txt") == b"payload"


def test_rename_without_replace_refuses_an_occupied_destination(backing):
    """Windows refuses rather than clobbering, which is exactly why Move-Item
    -Force deletes the destination separately first - and why that path is
    caught by on_cleanup instead of on_rename."""
    backing.make_file(r"\a.txt")
    backing.make_file(r"\b.txt")
    with pytest.raises(FileExistsError):
        backing.rename(r"\a.txt", r"\b.txt", replace_if_exists=False)
    assert backing.exists(r"\a.txt")


def test_rename_with_replace_clobbers_the_destination(backing):
    """THE case the whole Windows guard exists for: Claude Code's Write tool,
    every save. No delete signal is emitted anywhere - fsguard.on_rename has
    already snapshotted the destination before this runs."""
    backing.make_file(r"\src.txt")
    backing.make_file(r"\dst.txt")
    fd = backing.open_fd(r"\src.txt")
    try:
        backing.write_at(fd, b"new", 0)
    finally:
        os.close(fd)
    backing.rename(r"\src.txt", r"\dst.txt", replace_if_exists=True)
    assert backing.read_all(r"\dst.txt") == b"new"
    assert not backing.exists(r"\src.txt")


def test_rename_across_directories(backing):
    backing.make_dir(r"\a")
    backing.make_dir(r"\b")
    backing.make_file(r"\a\f.txt")
    backing.rename(r"\a\f.txt", r"\b\f.txt")
    assert backing.listdir(r"\b") == ["f.txt"]


def test_rename_cannot_escape_the_backing_directory(backing):
    backing.make_file(r"\f.txt")
    with pytest.raises(PathEscape):
        backing.rename(r"\f.txt", r"\..\escaped.txt")


# --------------------------------------------------------------------------
# Concurrency - winfspy dispatches from a thread pool
# --------------------------------------------------------------------------

def test_concurrent_writes_to_distinct_offsets_do_not_interleave(backing):
    """The reason read_at/write_at take an offset instead of seeking: with a
    shared file position, two threads interleave a seek with someone else's
    write and the bytes land in the wrong place. Where pread/pwrite are absent
    (Windows) a lock provides the same guarantee, and this test is what proves
    the fallback is equivalent."""
    backing.make_file(r"\f.bin")
    fd = backing.open_fd(r"\f.bin")
    try:
        backing.set_size_fd(fd, 64 * 100)

        def writer(n):
            for _ in range(50):
                backing.write_at(fd, bytes([n]) * 64, n * 64)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for i in range(100):
            assert backing.read_at(fd, i * 64, 64) == bytes([i]) * 64, \
                f"block {i} was corrupted by a concurrent write"
    finally:
        os.close(fd)


def test_concurrent_creates_all_succeed(backing):
    def make(n):
        backing.make_file(f"\\c{n:03d}.txt")

    threads = [threading.Thread(target=make, args=(i,)) for i in range(60)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(backing.listdir("\\")) == 60


# --------------------------------------------------------------------------
# Construction and relocation
# --------------------------------------------------------------------------

def test_a_missing_backing_directory_is_refused(tmp_path):
    with pytest.raises(NotADirectoryError):
        Backing(str(tmp_path / "nope"))


def test_create_makes_the_backing_directory(tmp_path):
    b = Backing(str(tmp_path / "made"), create=True)
    assert os.path.isdir(b.root)


def test_relocate_moves_a_project_aside(tmp_path):
    """`demo_cli protect`: the project's own path has to be vacated so it can
    become the mount point - an NTFS reparse point only goes on an empty or
    missing directory."""
    src = tmp_path / "project"
    (src / "src").mkdir(parents=True)
    (src / "src" / "app.py").write_text("print(1)")
    dst = tmp_path / "project.real"

    Backing.relocate(str(src), str(dst))

    assert not src.exists(), "the original path must be free for the mount"
    assert (dst / "src" / "app.py").read_text() == "print(1)"


def test_relocate_refuses_to_merge_into_an_existing_backing(tmp_path):
    """Merging two trees is how somebody loses work silently. Refuse."""
    src = tmp_path / "project"
    src.mkdir()
    dst = tmp_path / "project.real"
    dst.mkdir()
    with pytest.raises(FileExistsError):
        Backing.relocate(str(src), str(dst))
    assert src.exists(), "nothing may be moved when the move is refused"


def test_relocate_refuses_a_missing_source(tmp_path):
    with pytest.raises(NotADirectoryError):
        Backing.relocate(str(tmp_path / "nothing"), str(tmp_path / "backing"))
