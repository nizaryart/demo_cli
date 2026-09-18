"""Recovery: resolve the real target of a command and snapshot / restore it.

Target and operand resolution logic is in targets.py and re-exported here
for 100% backward compatibility.
"""
from __future__ import annotations

import datetime
import json
import math
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .classify import (
    FILE_WRITER_TARGET_VERBS,
    POSIX,
    POWERSHELL,
    PS_CLEAR_CONTENT_ALIASES,
    PS_COPY_ALIASES,
    PS_MOVE_ALIASES,
    PS_NEW_ITEM_ALIASES,
    PS_REMOVE_ALIASES,
    PS_RENAME_ALIASES,
    effective_command,
    effective_segments,
    is_file_writer_command,
    join_continuations,
    redirect_target,
    split_segments,
    strip_ps_escapes,
    substitute_assignments,
)
from .context import redact
from .targets import (
    IGNORED_DIRS,
    Target,
    _BRACE_MAX,
    _BRACE_MAX_DEPTH,
    _CD_ARGS,
    _CD_RE,
    _DB_FILE,
    _ENV_ASSIGN,
    _MV_RE,
    _PG_URL,
    _PS_CONTENT_ALIAS_RE,
    _PS_CONTENT_RE,
    _PS_DEST_ALIAS_RE,
    _PS_DEST_FLAGS,
    _PS_DEST_RE,
    _PS_NEWNAME_FLAGS,
    _PS_PATH_FLAGS,
    _PS_RENAME_RE,
    _PS_REMOVE_ALIAS_RE,
    _PS_REMOVE_ANY_RE,
    _PS_REMOVE_RE,
    _PS_VALUE_FLAGS,
    _RM_RE,
    _UNEXPANDED,
    _UNMODELLED,
    _WRITER_CMD_RE,
    _base_at,
    _changes_directory,
    _common_capture_root,
    _expand_braces,
    _expand_braces_bounded,
    _expand_range,
    _expanduser_any,
    _first_brace_group,
    _mv_target_dir,
    _operand_context,
    _path_operands,
    _ps_content_hit,
    _ps_dest_hit,
    _ps_dest_target,
    _ps_flagged_operands,
    _ps_named_operands,
    _ps_remove_hit,
    _ps_remove_item_operand,
    _ps_write_target,
    _split_top_commas,
    _tokenize,
    _too_broad,
    _win_aware_dirname,
    _win_aware_join,
    _writer_hit,
    effective_cwd,
    expanded_operands,
    extract_path_operand,
    ignored_dirs_under,
    is_fs_delete,
    is_remote_pg,
    ps_named_target,
    resolve_redirect_target,
    resolve_target,
    sole_segment,
    unignorable_dirs,
)

_IGNORE = shutil.ignore_patterns(*sorted(IGNORED_DIRS))

# Upper bound on what we will copy for a directory snapshot. A snapshot we
# cannot take quickly is not a recovery we should silently promise: above this
# the orchestrator escalates honestly instead of copying a multi-GB tree.
# Override with DEMO_CLI_MAX_SNAPSHOT_MB.
_DEFAULT_MAX_SNAPSHOT_MB = 256

# The byte cap bounds DISK SPACE. This one bounds TIME, and they are not the
# same instrument. Measured 2026-09-16 on Windows NTFS with Defender live:
#
#     2,000 files   131.1 MB   copytree 2.041s
#     2,000 files     1.0 MB   copytree 1.878s     131x the data, 9% the time
#    20,000 files    10.2 MB   copytree 21.794s
#
# 991 us per file, essentially independent of size, so a 256 MB cap of 1 KB
# files is 262,144 files and about 260 seconds. WSL2 measures 183 us/file -
# five times faster - which is why this has to be configurable rather than a
# constant someone guessed on a Linux box.
#
# The budget it has to fit inside is the HOOK timeout, and exceeding that is
# not a slow snapshot. It is a kill: the hook dies with no verdict, the host
# runs the command unguarded, and - measured on Claude Code the same day - it
# says NOTHING to the user. A crashed hook is announced; a timed-out one is
# silent. So this is refused in advance, never discovered afterwards.
#
# Override with DEMO_CLI_MAX_SNAPSHOT_FILES.
_DEFAULT_MAX_SNAPSHOT_FILES = 25_000


# --------------------------------------------------------------------------
# Recovery index (project-local)
# --------------------------------------------------------------------------

def _index_path(recovery_dir: str) -> str:
    return os.path.join(recovery_dir, "index.jsonl")


def _index_fs_path(recovery_dir: str) -> str:
    """The filesystem guard's own index.

    Same reason the receipt chain is split: this process writes in the backing
    directory while the hook writes through the mount, and WinFsp does not
    carry byte-range locks between them. The receipt file was visibly torn by
    that on 2026-09-02; the index was not, but only because the hook happens
    to snapshot rarely - one write on the whole labubu run against fsguard's
    206. Low contention is not a property to rely on.

    The index failing is WORSE than the receipt file failing, which is why it
    is fixed at the same time rather than later. A torn receipt line makes
    `verify` shout. A torn index line is skipped by load_entries, so a
    recovery point that exists on disk becomes unreachable - the tool silently
    loses a recovery it already told you it had.
    """
    return os.path.join(recovery_dir, "index-fs.jsonl")


def _pruned_fs_path(recovery_dir: str) -> str:
    """Ids pruned out of the filesystem guard's index, one per line.

    WHY A SECOND FILE INSTEAD OF EDITING THE FIRST
    ----------------------------------------------
    The split exists so each index has exactly ONE writer: the guard writes
    index-fs.jsonl in the backing, everything else writes index.jsonl through
    the mount, and WinFsp does not carry byte-range locks between the two. A
    lock taken on one side is not the lock taken on the other.

    `prune` broke that rule in the worst possible way. It computed doomed
    entries from the MERGED view, deleted their artefacts - fs ones included -
    and then rewrote index.jsonl only. So the fs index kept advertising
    recovery points whose bytes were gone, and fs survivors got a second copy
    written into the main index. Found by review 2026-09-07.

    The obvious repair - have prune rewrite index-fs.jsonl too - is worse than
    the bug. It truncates a file the guard may be appending to, across a lock
    boundary that does not compose: today's failure leaves stale entries in an
    intact file, that one can lose the file. Prefer a lie you can detect to a
    loss you cannot.

    So prune never touches the guard's file. It appends the pruned ids here,
    to a file the CLI side owns outright, and load_entries filters them out.
    Single writer per file, everywhere, and no truncation of anything another
    process holds open.

    Both files stay small - a few hundred bytes of ids - and the disk space
    was never here anyway: prune frees it by deleting the recovery ARTEFACTS,
    which it already does for both chains. This file only settles what the
    ledger is allowed to claim.

    A future mount can compact: at startup the guard is the sole writer of its
    own index and can drop tombstoned lines and clear this file safely. Not
    built, and not needed until the line count matters.
    """
    return os.path.join(recovery_dir, "index-fs.pruned")


def _read_pruned_fs(recovery_dir: str) -> set:
    """Ids tombstoned out of the fs index. Never raises: a missing or damaged
    tombstone file must not take the whole recovery ledger down with it."""
    out = set()
    try:
        with open(_pruned_fs_path(recovery_dir), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.add(line)
    except OSError:
        pass
    return out


def in_backing() -> bool:
    """True when this process writes the backing directly - i.e. it is the
    filesystem guard. Set by fsmount at mount time.

    A flag rather than a path comparison: the guard knows what it is, and
    inferring it from cwd or path shape is how a third writer ends up in the
    wrong chain silently.
    """
    return bool(os.environ.get("DEMO_CLI_FS_GUARD"))


def _record(recovery_dir: str, entry: dict) -> None:
    """Append one entry to the recovery index, durably and under a lock.

    This used to be a bare `open(..., "a")` and one `write`. Two ways that
    fails, both observed on 2026-08-25 in a real index:

    * A write interrupted before its newline (Ctrl+C on the filesystem guard)
      leaves a partial line. The NEXT append then lands on that same line,
      producing `{"id": "a", ..., "rec{"id": "b", ...}` - and load_entries
      silently drops both records, because it skips anything that will not
      parse. A recovery point that exists on disk becomes unreachable through
      the ledger, which is indistinguishable from never having taken it.
    * winfspy dispatches filesystem operations from a THREAD POOL, so two
      snapshots really can append at the same moment.

    receipts.py solved exactly this problem for the receipt chain - lock, then
    flush, then fsync. Reusing its lock rather than writing a second one is
    deliberate: two implementations of "append safely" is how they drift, and
    the ledger that finds your files deserves the same care as the ledger that
    proves what happened.

    The newline-first check HEALS a previously truncated line instead of
    compounding it: the broken record is left as its own unparseable line and
    only it is lost, rather than taking the next record down with it.
    """
    from .receipts import _chain_lock          # local: avoids an import cycle

    os.makedirs(recovery_dir, exist_ok=True)
    path = _index_fs_path(recovery_dir) if in_backing() else _index_path(recovery_dir)
    with _chain_lock(path):
        needs_newline = False
        try:
            if os.path.getsize(path):
                with open(path, "rb") as fh:
                    fh.seek(-1, os.SEEK_END)
                    needs_newline = fh.read(1) != b"\n"
        except OSError:
            pass                                # no file yet: nothing to heal
        with open(path, "a", encoding="utf-8") as f:
            if needs_newline:
                f.write("\n")
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _new_id() -> str:
    """Short, human-typable recovery-point id (prefix-matchable)."""
    return uuid.uuid4().hex[:8]


def _max_snapshot_bytes() -> int:
    """The directory-capture cap, in bytes. Never raises, never negative.

    `float()` was guarded and `int()` was not, which is the gap:

        DEMO_CLI_MAX_SNAPSHOT_MB=nan   float() fine, int() -> ValueError
        DEMO_CLI_MAX_SNAPSHOT_MB=inf   float() fine, int() -> OverflowError

    Neither is an OSError, and this runs BEFORE the try/except around the copy,
    so both escaped Guard.evaluate. The Claude Code adapter fails open on its
    own errors, so a typo in one environment variable turned every directory
    capture into an unguarded delete (2026-09-08).

    A NEGATIVE value was accepted silently and is worse than a crash: every
    tree exceeds a cap of -5 MB, so directory recovery is switched off with no
    message at all. Nonsense values fall back to the default rather than to
    "capture nothing", because silently disabling recovery is the dangerous
    direction. Zero is left alone - it is a coherent way to say "files only".
    """
    default = int(_DEFAULT_MAX_SNAPSHOT_MB * 1024 * 1024)
    raw = os.environ.get("DEMO_CLI_MAX_SNAPSHOT_MB")
    if raw is None:
        return default
    try:
        mb = float(raw)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(mb) or mb < 0:
        return default
    try:
        return int(mb * 1024 * 1024)
    except (ValueError, OverflowError):
        return default


def _max_snapshot_files() -> int:
    """The file-count cap, parsed as defensively as the byte cap above and for
    the same reason: this runs before the try/except around the copy, and a
    typo in one environment variable must not turn every directory capture into
    an unguarded delete."""
    raw = os.environ.get("DEMO_CLI_MAX_SNAPSHOT_FILES")
    if raw is None:
        return _DEFAULT_MAX_SNAPSHOT_FILES
    try:
        n = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_MAX_SNAPSHOT_FILES
    if not math.isfinite(n) or n < 0:
        return _DEFAULT_MAX_SNAPSHOT_FILES
    try:
        return int(n)
    except (ValueError, OverflowError):
        return _DEFAULT_MAX_SNAPSHOT_FILES


def _contains(outer: str, inner: str) -> bool:
    """Is `inner` at or underneath `outer`? Absolute, normalised, and it never
    raises - commonpath throws on paths from different drives, which on
    Windows is a legitimate answer of "no", not an error."""
    try:
        outer, inner = os.path.abspath(outer), os.path.abspath(inner)
        return outer == inner or os.path.commonpath([outer, inner]) == outer
    except ValueError:
        return False


def _walk_cost(path: str, byte_cap: int, file_cap: Optional[int] = None,
               ignore_dirs=None, skip_path=None) -> Tuple[int, int]:
    """(bytes, files) under `path`, skipping the same directories the copy will.

    ONE walk, two budgets. Short-circuits as soon as either cap is exceeded, so
    a huge tree is never walked to the end just to find out it is huge.

    `ignore_dirs` MUST be whatever the copy will skip. If the measurement
    excludes a directory the copy then includes, neither cap bounds anything -
    which is how a "256 MB cap" quietly copies gigabytes. checkpoint.py keeps
    .git, so it passes its own set.

    Until 2026-08-24 this held a hardcoded duplicate of IGNORED_DIRS, exactly
    the drift the comment on that constant warns about.
    """
    ignore = IGNORED_DIRS if ignore_dirs is None else frozenset(ignore_dirs)
    total = files = 0
    for root, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignore
                   and not (skip_path and _contains(skip_path,
                                                    os.path.join(root, d)))]
        for f in names:
            files += 1
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
            if total > byte_cap or (file_cap is not None and files > file_cap):
                return total, files
    return total, files


def _dir_size(path: str, cap: int, ignore_dirs=None, skip_path=None) -> int:
    """Bytes only. The byte half of _walk_cost, for callers that have no time
    budget to spend (checkpoint's own cap check, and the tests)."""
    return _walk_cost(path, cap, None, ignore_dirs, skip_path)[0]


def snapshot(target: Optional[Target], recovery_dir: str, strategy: str = "snapshot",
             action: Optional[str] = None, ignore_dirs=None,
             notes: Optional[dict] = None) -> Optional[dict]:
    """Capture a recovery point for a target. Returns the recovery entry or None.

    `strategy` comes from config: "snapshot" captures; "none"/"attest" never
    capture (attestation of an externally managed recovery point is reserved
    for a later release and is treated as non-recoverable here, by design,
    rather than claiming a recovery we have not verified).

    `action` is the human-readable thing that prompted the snapshot (a command
    or a file-edit), stored on the entry so `demo_cli log` can show *why* each
    recovery point exists.

    `notes`, when given, receives a "refused" key explaining a cap refusal in
    words the caller can put in front of a person. Returning a bare None says
    only that there is no recovery point; it cannot say the tree was too big,
    by how much, or which knob to turn - and this is the one refusal a user can
    actually do something about.
    """
    if not target or strategy in ("none", "attest"):
        return None

    os.makedirs(recovery_dir, exist_ok=True)
    kind, ref, ts, rid = target.kind, target.ref, _ts(), _new_id()
    action = redact(action) if action else None

    def _entry(recovery_point: str) -> dict:
        e = {"id": rid, "kind": kind, "target": ref,
             "recovery_point": recovery_point, "ts": ts, "action": action}
        _record(recovery_dir, e)
        return e

    if kind in ("sqlite", "file"):
        if not os.path.exists(ref):
            return None
        # The byte cap bounds DISK SPACE, and one file spends it as readily as
        # a tree. Only the dir branch below ever checked it, so this branch
        # copied a multi-GB file happily - on EVERY edit, with no dedup behind
        # it - and a copy that outlives the hook budget is a silent unguarded
        # command, not a slow one. The file COUNT cap is deliberately absent:
        # one file is one file, and for a single copy bytes bound the time too.
        cap = _max_snapshot_bytes()
        try:
            size = os.path.getsize(ref)
        except OSError:
            return None
        if size > cap:
            if notes is not None:
                notes["refused"] = (
                    f"{os.path.basename(ref) or ref} is "
                    f"{size // (1024 * 1024)} MB, over the "
                    f"{cap // (1024 * 1024)} MB snapshot cap; raise "
                    f"DEMO_CLI_MAX_SNAPSHOT_MB or take an independent backup.")
            return None
        bak = os.path.join(recovery_dir, f"{os.path.basename(ref)}.{ts}.{rid}.bak")
        try:
            shutil.copy2(ref, bak)
        except OSError:
            return None         # no snapshot -> the caller escalates. See below.
        return _entry(bak)

    if kind == "dir":
        if not os.path.isdir(ref):
            return None
        # Honesty + safety: refuse to "recover" a tree we cannot copy quickly.
        # The measurement and the copy must skip the SAME directories, or the
        # cap does not bound anything - see _dir_size.
        # NEVER COPY A TREE INTO ITSELF.
        #
        # The destination lives in recovery_dir. When the target IS the
        # workspace - `rm -rf .demo_cli`, an ordinary-looking command an agent
        # can issue - recovery_dir sits INSIDE ref, and copytree copies the
        # tree it is growing. Observed 2026-08-29: fifteen levels of
        # .demo_cli/recovery/....snapdir/recovery/....snapdir, stopped only by
        # Windows MAX_PATH, and `rm -rf` could not reach the bottom to clean it.
        #
        # _IGNORE does not cover this. It skips directories NAMED .demo_cli;
        # here .demo_cli is the source and the child being copied is named
        # `recovery`. The name-based list cannot see the collision - only the
        # absolute path can.
        #
        # The size cap does not cover it either: _dir_size measures BEFORE the
        # copy, and the growth happens during it. A guard whose recovery path
        # is a denial of service against itself is worse than one that
        # declines, so this is checked, not bounded.
        if _contains(recovery_dir, ref):
            return None          # snapshotting a backup into the backup store
        names = IGNORED_DIRS if ignore_dirs is None else frozenset(ignore_dirs)
        skip = recovery_dir if _contains(ref, recovery_dir) else None

        def ignore(dirpath, entries):
            out = {e for e in entries if e in names}
            if skip:
                out |= {e for e in entries
                        if _contains(skip, os.path.join(dirpath, e))}
            return out

        cap = _max_snapshot_bytes()
        file_cap = _max_snapshot_files()
        nbytes, nfiles = _walk_cost(ref, cap, file_cap, ignore_dirs, skip_path=skip)
        if nbytes > cap:
            if notes is not None:
                notes["refused"] = (
                    f"{os.path.basename(ref) or ref} exceeds the "
                    f"{cap // (1024 * 1024)} MB snapshot cap; raise "
                    f"DEMO_CLI_MAX_SNAPSHOT_MB or name a narrower target.")
            return None
        if file_cap is not None and nfiles > file_cap:
            # TIME, not space. Capture is ~1 ms per file on Windows, so this
            # many files would outlast the hook's timeout - and a hook killed
            # mid-copy is a SILENT unguarded command, not a slow one.
            if notes is not None:
                notes["refused"] = (
                    f"{os.path.basename(ref) or ref} holds more than "
                    f"{file_cap:,} files; capturing it would outlast the "
                    f"agent's hook timeout, and a hook killed mid-copy lets "
                    f"the command run unguarded with no warning. Raise "
                    f"DEMO_CLI_MAX_SNAPSHOT_FILES and DEMO_CLI_HOOK_TIMEOUT "
                    f"together, then re-run `demo_cli install-hook` so the "
                    f"host sees the new budget. Or name a narrower target.")
            return None
        snap = os.path.join(recovery_dir, f"{os.path.basename(ref.rstrip('/'))}.{ts}.{rid}.snapdir")
        # symlinks=True, AND NOT ONLY TO AVOID A CRASH.
        #
        # The default is False, which FOLLOWS every symlink and copies what it
        # points at. Two consequences, both found by review 2026-09-08:
        #
        #   * a DANGLING link raised shutil.Error straight out of
        #     Guard.evaluate. The Claude Code adapter fails open on its own
        #     errors, so the hook printed "internal error, stepping aside" and
        #     let the delete run UNGUARDED. One broken symlink anywhere in a
        #     project silently disabled recovery for every directory capture -
        #     and build trees and node_modules are full of them.
        #
        #   * the size cap stopped bounding anything. _dir_size walks with
        #     os.walk, which does NOT descend symlinked directories, so a link
        #     to a 2 MB tree measured as nothing and copied as 2 MB. Measured
        #     at 4x a 0.5 MB cap. Exactly what _dir_size's own docstring warns
        #     about, arriving from the copy side instead of the ignore list.
        #
        # Preserving the link is also the more faithful capture: `rm link`
        # destroys the link, not its target, so restoring a link is right and
        # restoring a regular file full of the target's bytes was wrong.
        #
        # The try/except stays regardless. "Degrade, never crash" is the
        # contract, and returning None here means no recovery point, which
        # makes the caller escalate - loudly, and without a claim.
        try:
            shutil.copytree(ref, snap, dirs_exist_ok=True, ignore=ignore,
                            symlinks=True)
        except OSError:         # shutil.Error is an OSError
            return None
        return _entry(snap)

    if kind == "postgres":
        if not shutil.which("pg_dump"):
            return None
        dump = os.path.join(recovery_dir, f"pg.{ts}.{rid}.dump")
        try:
            r = subprocess.run(["pg_dump", "-Fc", "-f", dump, ref],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            if r.returncode != 0 or not os.path.exists(dump):
                return None
        except Exception:
            return None
        return _entry(dump)

    return None


def snapshot_bytes(name: str, data: bytes, recovery_dir: str,
                   action: Optional[str] = None,
                   target: Optional[str] = None) -> Optional[dict]:
    """Capture content we already HOLD, rather than a path we can copy.

    `snapshot()` copies a file off the filesystem. A guard that intercepts a
    destructive operation *before* it happens sometimes holds the bytes with no
    path to read them from - an in-memory filesystem, a stream, a buffer about
    to be overwritten. This writes those bytes to a recovery point with an
    entry of exactly the same shape, so `undo`, `log`, `diff` and `verify`
    cannot tell the difference and need no special case.

    `target` is what the bytes came from, for the ledger; `name` only decides
    the filename of the backup.
    """
    if data is None:
        return None
    os.makedirs(recovery_dir, exist_ok=True)
    ts, rid = _ts(), _new_id()
    base = os.path.basename(str(name).replace("\\", "/").rstrip("/")) or "file"
    bak = os.path.join(recovery_dir, f"{base}.{ts}.{rid}.bak")
    with open(bak, "wb") as f:
        f.write(data)
    entry = {"id": rid, "kind": "file", "target": target or name,
             "recovery_point": bak, "ts": ts,
             "action": redact(action) if action else None}
    _record(recovery_dir, entry)
    return entry


def snapshot_before_restore(entry: Optional[dict],
                            recovery_dir: str) -> Optional[dict]:
    """Preserve what `undo` is about to overwrite.

    UNDO WAS THE ONE MUTATION THE TOOL DID NOT GATE. Everything an agent does
    is snapshotted before it destroys anything; `undo` overwrote a file with
    no recovery point of its own. The failure that exposed it: restore a file,
    do new work on it, then restore again out of habit - and the new work is
    gone, with nothing to go back to.

    Blocking a repeated id would not have fixed that. A DIFFERENT recovery
    point for the same file does identical damage and has never been used, so
    a once-only rule lets it straight through. The hazard is overwriting live
    content, not reusing an id, so the guard belongs on the overwrite.

    Returns the new entry, or None when there is nothing worth keeping: no
    target on disk, or bytes already identical to what is being restored -
    a recovery point recording no change is noise in the log, and noise is
    how a real one gets missed.

    FILES ONLY. A 'dir' entry restores by copytree overlay, which can clobber
    modified files the same way; capturing a whole tree here needs snapshot()
    and a Target, and is left as known work rather than half-done. Every
    recovery point the filesystem guard writes is a file.
    """
    if not entry or entry.get("kind") not in ("file", "sqlite"):
        return None
    target, rp = entry.get("target"), entry.get("recovery_point")
    if not target or not os.path.isfile(target):
        return None                     # nothing there to lose
    try:
        with open(target, "rb") as f:
            current = f.read()
    except OSError:
        return None
    try:
        with open(rp, "rb") as f:
            if f.read() == current:
                return None             # restoring identical bytes changes nothing
    except OSError:
        pass                            # cannot compare - keep the copy, it is cheap
    return snapshot_bytes(os.path.basename(target), current, recovery_dir,
                          action=f"undo {entry.get('id', '?')} overwrote {target}",
                          target=target)


def _read_index(path: str) -> Tuple[List[dict], int]:
    """One index file's entries, and how many lines could not be read."""
    entries: List[dict] = []
    unreadable = 0
    if not os.path.exists(path):
        return entries, unreadable
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                unreadable += 1
    return entries, unreadable


def unreadable_entries(recovery_dir: str) -> int:
    """How many index lines could not be parsed, across both indexes.

    Exposed because the count MATTERS: each one is a recovery point that
    exists on disk and that `undo` can no longer find. Silently dropping them
    - which load_entries used to do with a bare `except: pass` - means the
    tool promises a recovery it can no longer deliver, and says nothing. That
    is the exact failure the honesty invariant exists to prevent, committed by
    the recovery ledger itself.
    """
    return (_read_index(_index_path(recovery_dir))[1]
            + _read_index(_index_fs_path(recovery_dir))[1])


def load_entries(recovery_dir: str) -> List[dict]:
    """Every recovery point, from both indexes, oldest first.

    SPLIT ON WRITE, MERGED ON READ. The two files exist so that each is
    written from only one side of the WinFsp mount; nothing that reads them
    needs to know, so `undo`, `log` and `diff` are unchanged. Sorted by
    timestamp so a merged listing stays chronological rather than showing one
    file's history and then the other's.
    """
    entries = _read_index(_index_path(recovery_dir))[0]
    # Tombstones apply to the fs chain only. The main index is rewritten in
    # place by prune, so a pruned main entry is simply not there to filter.
    pruned = _read_pruned_fs(recovery_dir)
    entries += [e for e in _read_index(_index_fs_path(recovery_dir))[0]
                if e.get("id") not in pruned]
    # "ts", not "timestamp". Recovery entries have always used "ts" (see
    # _record's callers); "timestamp" is the RECEIPT key, and sorting on it
    # here meant every key was the empty string. Python's sort is stable, so
    # the merged list kept its concatenation order - every main entry, then
    # every fs entry - which is precisely the "one file's history and then the
    # other's" this docstring says it prevents.
    #
    # The consequence was not a subtle skew. latest() takes entries[-1], so it
    # returned the newest FS entry whenever index-fs.jsonl was non-empty, no
    # matter how much newer a main-chain entry was. `demo_cli undo` with no id
    # then restored the wrong point and reported RESTORED.
    #
    # Invisible on Linux and on Windows before a mount, because an empty fs
    # index leaves append order intact and the result is correct by accident.
    # Found by review on 2026-09-07; no test wrote both indexes.
    #
    # _ts() is "%Y%m%d-%H%M%S" - fixed width, zero padded - so lexicographic
    # order is chronological and no parsing is needed.
    return sorted(entries, key=lambda e: str(e.get("ts") or ""))


def latest(recovery_dir: str, target_ref: Optional[str] = None) -> Optional[dict]:
    entries = load_entries(recovery_dir)
    if target_ref:
        entries = [e for e in entries if e.get("target") == target_ref]
    return entries[-1] if entries else None


def find(recovery_dir: str, rid: str) -> Optional[dict]:
    """Find a recovery point by id (exact or unique prefix). Returns the entry,
    or None if nothing matches or the prefix is ambiguous."""
    matches = [e for e in load_entries(recovery_dir)
               if str(e.get("id", "")).startswith(rid)]
    return matches[-1] if len(matches) == 1 else None


def entry_size(entry: dict) -> int:
    """On-disk size of a recovery point (file or directory tree)."""
    rp = entry.get("recovery_point")
    if not rp or not os.path.exists(rp):
        return 0
    if os.path.isfile(rp):
        try:
            return os.path.getsize(rp)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(rp):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def prune(recovery_dir: str, keep: Optional[int] = None,
          older_than_days: Optional[int] = None) -> List[dict]:
    """Delete recovery-point artefacts (not receipts - those are the audit
    trail and must stay chain-intact) and rewrite the index.

    `keep`: retain the N most recent points, delete the rest.
    `older_than_days`: delete points whose timestamp is older than the cutoff.
    With neither argument, nothing is deleted. Returns the removed entries.
    """
    entries = load_entries(recovery_dir)
    if not entries:
        return []

    doomed: List[dict] = []
    survivors: List[dict] = entries

    if older_than_days is not None:
        cutoff = datetime.datetime.now() - datetime.timedelta(days=older_than_days)
        keep_set, drop = [], []
        for e in survivors:
            try:
                when = datetime.datetime.strptime(e.get("ts", ""), "%Y%m%d-%H%M%S")
            except ValueError:
                when = datetime.datetime.now()  # undated: treat as fresh, keep
            (drop if when < cutoff else keep_set).append(e)
        doomed += drop
        survivors = keep_set

    if keep is not None and len(survivors) > keep:
        doomed += survivors[:-keep] if keep > 0 else survivors[:]
        survivors = survivors[-keep:] if keep > 0 else []

    for e in doomed:
        e["_freed_bytes"] = entry_size(e)
        rp = e.get("recovery_point")
        if rp and os.path.exists(rp):
            try:
                shutil.rmtree(rp) if os.path.isdir(rp) else os.remove(rp)
            except OSError:
                pass

    # WHICH FILE EACH ENTRY CAME FROM DECIDES HOW IT IS REMOVED.
    #
    # This used to rewrite index.jsonl with every survivor and stop there, so
    # fs survivors were duplicated into the main index while still present in
    # their own, and doomed fs entries stayed listed with their artefacts
    # already deleted - the ledger advertising recovery that is gone. When
    # index.jsonl did not exist at all (a freshly mounted Windows project,
    # before any CLI-side snapshot) the rewrite was skipped entirely and
    # NOTHING was de-listed.
    #
    # The guard's index is never rewritten from here; see _pruned_fs_path.
    from .receipts import _chain_lock          # local: avoids an import cycle

    fs_ids = {e.get("id") for e in _read_index(_index_fs_path(recovery_dir))[0]}
    doomed_fs = [e for e in doomed if e.get("id") in fs_ids]

    # The main index, rewritten in place - now UNDER THE LOCK. _record has
    # always locked its appends; this rewrite never did, so a truncate could
    # land in the middle of one. Two writers, one file, one lock.
    idx = _index_path(recovery_dir)
    if os.path.exists(idx):
        with _chain_lock(idx):
            with open(idx, "w", encoding="utf-8") as f:
                for e in survivors:
                    if e.get("id") not in fs_ids:
                        f.write(json.dumps(e) + "\n")

    # The guard's index, tombstoned rather than rewritten.
    if doomed_fs:
        os.makedirs(recovery_dir, exist_ok=True)
        pruned = _pruned_fs_path(recovery_dir)
        with _chain_lock(pruned):
            with open(pruned, "a", encoding="utf-8") as f:
                for e in doomed_fs:
                    f.write(str(e.get("id", "")) + "\n")

    return doomed


@dataclass
class RestoreResult:
    """Whether the restore happened, and if not, WHY NOT.

    restore_entry() used to collapse every OSError into False, and the caller
    then printed a fixed guess: "check the target path is reachable". On
    2026-08-29 that guess was wrong in the one case that matters most.

    A filesystem-layer recovery point lives in the ACL-locked backing, so an
    unelevated shell cannot READ it. Undo failed, and the user was told
    "No recovery point could be restored" about a file sitting intact on
    disk - a FALSE NEGATIVE from the command someone runs precisely when they
    have already lost something. An unearned "REVERSIBLE" and an unearned
    "unrecoverable" break the same invariant; only the direction differs.

    `denied` is the distinction worth carrying: it means an elevated retry
    would work, which is actionable, where "gone" is not.
    """
    ok: bool
    denied: bool = False
    problem: Optional[str] = None


def restore(entry: Optional[dict]) -> RestoreResult:
    """restore_entry(), but it says why it failed."""
    if not entry:
        return RestoreResult(False, problem="no recovery entry")
    kind = entry.get("kind", "sqlite")
    rp = entry.get("recovery_point")
    try:
        present = bool(rp) and (os.path.isdir(rp) if kind == "dir"
                                else os.path.exists(rp))
    except OSError:
        present = False
    if not present:
        # Cannot even stat it. On Windows a directory locked to Administrators
        # denies traverse, so "not there" and "not allowed to look" are the
        # same answer here - and an elevated retry settles which.
        if rp and not _readable_parent(rp):
            return RestoreResult(False, denied=True,
                                 problem=f"{rp} is not readable from this shell")
        return RestoreResult(False, problem="the recovery point is missing")
    try:
        ok = restore_entry(entry)
    except PermissionError as e:
        return RestoreResult(False, denied=True, problem=str(e))
    if ok:
        return RestoreResult(True)
    denied, why = _why_restore_failed(entry)
    return RestoreResult(False, denied=denied, problem=why)


def _readable_parent(path: str) -> bool:
    parent = os.path.dirname(path) or "."
    try:
        os.listdir(parent)
        return True
    except OSError:
        return False


def _why_restore_failed(entry: dict):
    """Re-attempt the two file operations to learn which one was refused.

    Deliberately a SECOND look rather than plumbing the exception out of
    restore_entry: that function is called from thirteen places and from the
    syscall guard, and widening its contract to carry an error would touch all
    of them. The cost is one extra open on a path that already failed - only
    ever on the failure path, never in the normal one.
    """
    rp, target = entry.get("recovery_point"), entry.get("target")
    try:
        with open(rp, "rb"):
            pass
    except PermissionError:
        return True, f"{rp} cannot be read from this shell"
    except OSError as e:
        return False, f"{rp} cannot be read ({e.strerror})"
    parent = os.path.dirname(os.path.abspath(target or "")) or "."
    if not os.access(parent, os.W_OK):
        return True, f"{parent} cannot be written from this shell"
    return False, "the copy did not complete"


def restore_entry(entry: dict) -> bool:
    kind = entry.get("kind", "sqlite")
    rp, target = entry.get("recovery_point"), entry.get("target")
    if kind in ("sqlite", "file"):
        if not rp or not os.path.exists(rp):
            return False
        # Recreate the parent directory. A recursive delete removes the files
        # first and the directory afterwards, so by the time anyone runs undo
        # the file's parent is gone and copy2 has nowhere to write. The bytes
        # were captured perfectly and were still unrestorable - confirmed live
        # on 2026-08-25, where `undo` on tree/a.txt escalated for no reason
        # other than tree/ no longer existing.
        #
        # Making the directory is not a liberty: the entry records an ABSOLUTE
        # path, and putting a file back at that path means the path has to
        # exist. Nothing else is created and nothing existing is touched.
        parent = os.path.dirname(os.path.abspath(target))
        # A failed copy must REPORT failure, not raise. cmd_undo has no
        # try/except, so an exception here becomes a traceback and the caller
        # learns nothing about whether their file came back. Returning False
        # renders as ESCALATE, which is the honest answer.
        # ValueError as well as OSError: a path carrying an embedded null byte
        # raises ValueError from os, not OSError, and a target string comes
        # out of a ledger file that a bad write can corrupt.
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copy2(rp, target)
        except (OSError, ValueError):
            return False
        return True
    if kind == "dir":
        if not rp or not os.path.isdir(rp):
            return False
        # Coarse by design: copytree overlays the snapshot back onto the target,
        # bringing deleted files back and reverting modified ones to their
        # snapshot state, while leaving files created after the snapshot in
        # place. For a multi-path rm captured as its common directory this
        # restores the whole directory, which is exactly what makes the recovery
        # a provable superset - and also why an edit made to an unrelated file in
        # that directory after the snapshot would be rolled back here.
        try:
            # symlinks=True to match the snapshot: a captured link is restored
            # as a link. Without it, restore would follow the link, write a
            # regular file over it, and fail outright on a dangling one.
            shutil.copytree(rp, target, dirs_exist_ok=True, symlinks=True)
        except OSError:
            return False        # same reasoning as the file branch above
        return True
    if kind == "postgres":
        if not shutil.which("pg_restore") or not rp or not os.path.exists(rp):
            return False
        try:
            r = subprocess.run(["pg_restore", "--clean", "--if-exists", "-d", target, rp],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            return r.returncode == 0
        except Exception:
            return False
    return False
