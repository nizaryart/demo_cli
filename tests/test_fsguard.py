"""The Windows behavioural guard's decision core.

Runs on every platform: the module under test knows nothing about WinFsp or
Windows, only about operations and paths. Same split that let the PowerShell
dialect work be developed on Linux and verified on Windows afterwards.

The values here are not invented. Flag numbers, call shapes and temp-file naming
all come from operation logs captured against winfspy 0.8.4 on Windows 10
(fsprobe/REPORT.md). Where a test encodes something surprising, the comment says
what was observed.
"""
import pytest

from demo_cli import fsguard as fs

# Observed on every ordinary write: allocation size + archive bit + three
# timestamps. Fires constantly and destroys nothing.
FLAGS_ORDINARY = 242
# Observed on every real delete: FspCleanupDelete | SetLastAccessTime.
FLAGS_DELETE = 33


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (r"\notes.txt", "notes.txt"),
    (r"\src\app.py", "src/app.py"),
    ("\\", ""),
    (None, ""),
    (r"\a\b\c.txt", "a/b/c.txt"),
])
def test_normalize_virtual_paths(raw, expected):
    assert fs.normalize(raw) == expected


def test_the_mount_root_is_never_a_target():
    """Everything lives under the root, so treating it as destroyable would
    make one operation appear to destroy the entire workspace."""
    assert not fs.in_scope("\\")
    assert not fs.in_scope("")
    assert not fs.in_scope(None)


@pytest.mark.parametrize("path", [
    r"\.git\objects\ab\cdef",
    r"\node_modules\left-pad\index.js",
    r"\src\__pycache__\app.cpython-311.pyc",
    r"\.demo_cli\receipts.jsonl",
])
def test_ignored_directories_are_out_of_scope(path):
    """One `git status` inside the mount touches hundreds of files under .git.
    Without this the ledger is unreadable and the snapshots are enormous."""
    assert not fs.in_scope(path)


@pytest.mark.parametrize("path", [r"\notes.txt", r"\src\app.py", r"\a\b\c.txt"])
def test_ordinary_paths_are_in_scope(path):
    assert fs.in_scope(path)


def test_scope_ignores_can_be_overridden():
    assert fs.in_scope(r"\.git\config", ignore={"node_modules"})


# --------------------------------------------------------------------------
# cleanup — ordinary deletes
# --------------------------------------------------------------------------

def test_cleanup_with_the_delete_bit_is_a_delete():
    v = fs.on_cleanup(r"\notes.txt", FLAGS_DELETE)
    assert v.destructive and v.kind == fs.DELETE and v.target == "notes.txt"


def test_ordinary_cleanup_is_not_a_delete():
    """Flags 242 fires after nearly every write. Treating cleanup itself as
    destructive would snapshot on literally every file operation."""
    assert not fs.on_cleanup(r"\notes.txt", FLAGS_ORDINARY).destructive


def test_the_delete_bit_must_be_MASKED_not_compared():
    """Real deletes arrive as 33, not 1 - the delete bit plus a timestamp bit.
    `flags == FSP_CLEANUP_DELETE` would miss every delete ever observed."""
    assert fs.on_cleanup(r"\a.txt", 33).destructive
    assert fs.on_cleanup(r"\a.txt", fs.FSP_CLEANUP_DELETE).destructive
    assert fs.on_cleanup(r"\a.txt", 0x01 | 0x80).destructive


def test_delete_of_an_ignored_path_is_skipped():
    assert not fs.on_cleanup(r"\.git\index", FLAGS_DELETE).destructive


# --------------------------------------------------------------------------
# set_file_size — how overwrite and empty actually happen
# --------------------------------------------------------------------------

def test_shrinking_a_file_destroys_content():
    v = fs.on_set_file_size(r"\notes.txt", new_size=0, current_size=29)
    assert v.destructive and v.kind == fs.TRUNCATE and v.target == "notes.txt"


def test_growing_a_file_destroys_nothing():
    assert not fs.on_set_file_size(r"\notes.txt", new_size=100, current_size=29).destructive


def test_same_size_destroys_nothing():
    assert not fs.on_set_file_size(r"\notes.txt", new_size=29, current_size=29).destructive


def test_truncate_to_zero_on_a_new_file_destroys_nothing():
    """A freshly created file is already 0 bytes; the truncate is a no-op."""
    assert not fs.on_set_file_size(r"\fresh.txt", new_size=0, current_size=0).destructive


# --------------------------------------------------------------------------
# rename — the gap with no delete signal
# --------------------------------------------------------------------------

def test_rename_over_an_existing_file_destroys_the_DESTINATION():
    """The single most important rule in this module.

    Observed: Claude Code's Write tool creates <original>.tmp.<pid>.<hex>,
    writes it, then renames it over the original. No cleanup(FspCleanupDelete),
    no can_delete, nothing. The original's content is gone when rename returns.
    """
    v = fs.on_rename(r"\notes.txt.tmp.8924.ea66e82f7cfb", r"\notes.txt",
                     replace_if_exists=True, dest_exists=True)
    assert v.destructive
    assert v.kind == fs.REPLACE
    assert v.target == "notes.txt", "must snapshot the DESTINATION, not the source"


def test_rename_target_is_never_the_source():
    """Getting this backwards snapshots a file that survives, and reports a
    recovery for one that did not happen."""
    v = fs.on_rename(r"\old.txt", r"\new.txt", replace_if_exists=True, dest_exists=True)
    assert v.target == "new.txt"


def test_rename_onto_a_free_name_destroys_nothing():
    assert not fs.on_rename(r"\a.txt", r"\b.txt",
                            replace_if_exists=True, dest_exists=False).destructive


def test_rename_without_replace_destroys_nothing():
    """Windows refuses the rename rather than clobbering, so nothing is lost.
    This is why Move-Item -Force deletes the destination separately first -
    that path is caught by on_cleanup instead."""
    assert not fs.on_rename(r"\a.txt", r"\b.txt",
                            replace_if_exists=False, dest_exists=True).destructive


def test_an_atomic_save_is_labelled_as_such():
    """Same destruction either way, but the receipt should distinguish an
    editor saving a file from an unrelated file being clobbered."""
    v = fs.on_rename(r"\notes.txt.tmp.13732.755b5f5ee82f", r"\notes.txt",
                     replace_if_exists=True, dest_exists=True)
    assert "atomic save" in v.reason


def test_an_unrelated_clobber_is_not_labelled_an_atomic_save():
    v = fs.on_rename(r"\downloads\other.txt", r"\notes.txt",
                     replace_if_exists=True, dest_exists=True)
    assert "atomic save" not in v.reason


@pytest.mark.parametrize("temp,target,expected", [
    (r"\notes.txt.tmp.8924.ea66e82f7cfb", r"\notes.txt", True),
    (r"\notes.txt.new",                   r"\notes.txt", True),
    (r"\notes.txt",                       r"\notes.txt", False),   # itself
    (r"\other.txt",                       r"\notes.txt", False),
    (r"\notes.txt.tmp",                   r"\other.txt", False),
])
def test_temp_sibling_detection(temp, target, expected):
    assert fs.is_temp_sibling(temp, target) is expected


# --------------------------------------------------------------------------
# overwrite — present in the API, never observed firing
# --------------------------------------------------------------------------

def test_overwrite_of_an_existing_file_is_destructive():
    v = fs.on_overwrite(r"\notes.txt", exists=True)
    assert v.destructive and v.kind == fs.OVERWRITE


def test_overwrite_of_a_missing_file_destroys_nothing():
    assert not fs.on_overwrite(r"\fresh.txt", exists=False).destructive


# --------------------------------------------------------------------------
# The full observed sequences, replayed
# --------------------------------------------------------------------------

def test_claude_code_write_tool_sequence_is_caught():
    """Replays the exact operation sequence captured from Claude Code's Write
    tool on a directory mount. Exactly ONE of these operations destroys data,
    and it is the rename - the one carrying no delete signal.
    """
    temp = r"\notes.txt.tmp.8924.ea66e82f7cfb"
    verdicts = [
        fs.on_cleanup(None, FLAGS_ORDINARY),                     # create+write of the temp
        fs.on_rename(temp, r"\notes.txt", True, dest_exists=True),
    ]
    destructive = [v for v in verdicts if v.destructive]
    assert len(destructive) == 1
    assert destructive[0].kind == fs.REPLACE
    assert destructive[0].target == "notes.txt"


def test_powershell_set_content_sequence_is_caught():
    """open -> set_file_size(0) -> write -> cleanup(242). The truncate is the
    destructive moment; the cleanup afterwards is not."""
    verdicts = [
        fs.on_set_file_size(r"\a.txt", new_size=0, current_size=7),
        fs.on_cleanup(None, FLAGS_ORDINARY),
    ]
    destructive = [v for v in verdicts if v.destructive]
    assert len(destructive) == 1 and destructive[0].kind == fs.TRUNCATE


def test_remove_item_sequence_is_caught():
    """can_delete (a permission check, not a signal) then cleanup with the
    delete bit. Only the second is destructive."""
    v = fs.on_cleanup(r"\a.txt", FLAGS_DELETE)
    assert v.destructive and v.kind == fs.DELETE


def test_reading_a_file_produces_no_verdicts_at_all():
    """35 operations for one Get-Content, none of them destructive. If any
    read path produced a verdict here, the guard would snapshot constantly."""
    verdicts = [
        fs.on_cleanup(None, FLAGS_ORDINARY),
        fs.on_set_file_size(r"\a.txt", new_size=7, current_size=7),
    ]
    assert not any(v.destructive for v in verdicts)
