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
from dataclasses import dataclass, field
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

# File-count cap bounds traversal time so deep directory snapshots complete within
# hook execution timeouts. Override with DEMO_CLI_MAX_SNAPSHOT_FILES.
_DEFAULT_MAX_SNAPSHOT_FILES = 25_000


# --------------------------------------------------------------------------
# Recovery index (project-local)
# --------------------------------------------------------------------------

def _index_path(recovery_dir: str) -> str:
    return os.path.join(recovery_dir, "index.jsonl")


def _index_fs_path(recovery_dir: str) -> str:
    """Path to the filesystem guard's private recovery index (index-fs.jsonl).

    Separated from the main index so the background VFS guard process writes to its
    own log without contending for locks across the WinFsp mount boundary.
    """
    return os.path.join(recovery_dir, "index-fs.jsonl")


def _pruned_fs_path(recovery_dir: str) -> str:
    """Path to tombstone list for filesystem guard entries (index-fs.pruned).

    Appends pruned IDs here rather than rewriting index-fs.jsonl, ensuring the
    VFS guard remains the sole writer of its own index file.
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
    """Append one entry to the recovery index under an OS file lock with flush/fsync.

    Checks and repairs any trailing unterminated line before appending.
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
    """Directory-capture cap in bytes from DEMO_CLI_MAX_SNAPSHOT_MB.

    Safely parses floats/ints; falls back to default on negative, NaN, or non-finite inputs.
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
    """File-count cap from DEMO_CLI_MAX_SNAPSHOT_FILES, defaulting to _DEFAULT_MAX_SNAPSHOT_FILES."""
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
    """Compute (bytes, files) under `path`, skipping directories in `ignore_dirs`.

    Short-circuits early as soon as either `byte_cap` or `file_cap` is exceeded.
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
        # Prevent self-copy recursion: refuse if recovery_dir is inside ref or ref is inside recovery_dir.
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
        # symlinks=True preserves symlinks as links without following them,
        # preventing infinite loops, broken target exceptions, and cap bypasses.
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
    """Snapshot the current on-disk target before 'undo' overwrites it (files/sqlite only).

    Returns the backup entry, or None if the target is missing or its contents
    are already identical to the recovery point being restored.
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
    # Sort chronologically by fixed-width zero-padded timestamp ("ts").
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

    # Main index is rewritten in place; filesystem guard entries are tombstoned.
    from .receipts import _chain_lock          # local: avoids an import cycle

    fs_ids = {e.get("id") for e in _read_index(_index_fs_path(recovery_dir))[0]}
    doomed_fs = [e for e in doomed if e.get("id") in fs_ids]

    # Rewrite the main index under the chain lock.
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
class ArtifactAuditResult:
    """Audit of on-disk recovery artifacts referenced by active index entries."""
    total_active: int = 0
    intact: int = 0
    missing: List[str] = field(default_factory=list)
    corrupt: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.corrupt


def audit_recovery_artifacts(recovery_dir: str) -> ArtifactAuditResult:
    """Verify that every active recovery entry in the ledger has an intact,
    non-empty snapshot file or directory on disk.

    Pruned entries are excluded because they were legitimately deleted and are
    no longer advertised by load_entries(). A missing or empty file for an
    active entry means the tool promises a recovery it cannot deliver.
    """
    entries = load_entries(recovery_dir)
    res = ArtifactAuditResult(total_active=len(entries))
    for e in entries:
        eid = str(e.get("id", "?"))
        kind = e.get("kind", "file")
        rp = e.get("recovery_point")
        if not rp:
            res.missing.append(eid)
            continue
        try:
            if kind == "dir":
                if not os.path.isdir(rp):
                    res.missing.append(eid)
                else:
                    res.intact += 1
            else:
                if not os.path.isfile(rp):
                    res.missing.append(eid)
                elif os.path.getsize(rp) == 0:
                    res.corrupt.append(eid)
                else:
                    res.intact += 1
        except OSError:
            res.missing.append(eid)
    return res


@dataclass
class RestoreResult:
    """Detailed result of a restore operation.

    Tracks whether restore succeeded (`ok`), and if refused due to permissions,
    sets `denied=True` with a diagnostic explanation in `problem`.
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
    """Inspect recovery point and target permissions to explain restore failure."""
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
        # Recreate the parent directory if missing so the file can be restored.
        parent = os.path.dirname(os.path.abspath(target))
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
        # Overlay the snapshot tree back onto the target with symlinks preserved.
        try:
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
