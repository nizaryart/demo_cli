"""The receipt ledger: an append-only, hash-chained record of
every decision. Each receipt commits to the one before it, so any edit,
insertion, removal, or reordering breaks the chain and is detectable by
`verify_chain`.

Beyond the *what* (command, decision, recovery point), each receipt also
records the *why*: the agent's declared intent and stated reasoning. That is
the audit-grade artefact - not just that a mutation happened, but the context
and rationale it happened under.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import heapq
import json
import os
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterator, List, Optional

from .context import redact
from .decide import INVARIANT
from .version import release_tag

RECEIPT_VERSION = "2.0"
GENESIS = "0" * 64

# A sha256 hex digest as it appears in a torn line's surviving text. Used to
# tell "the predecessor is unreadable" apart from "the predecessor is gone".
_HASH_TOKEN = re.compile(r"\b[0-9a-f]{64}\b")

# Chains are partitioned by writer: CHAIN_MAIN is written through user space / mount,
# and CHAIN_FS is written directly by the filesystem guard in the backing directory.
# This prevents lock contention and offset races across the WinFsp boundary.
CHAIN_MAIN = "main"     # hook, egress, CLI - written through the mount
CHAIN_FS = "fs"         # the filesystem guard - written in the backing

_FS_SUFFIX = "-fs"


def _base_path(path: str) -> str:
    """Return the main chain path for any given chain path, stripping suffixes."""
    root, ext = os.path.splitext(path)
    if root.endswith(_FS_SUFFIX):
        return root[:-len(_FS_SUFFIX)] + ext
    return path


def chain_path(path: str, chain: str = CHAIN_MAIN) -> str:
    """Return the filesystem path for the specified receipt chain."""
    base = _base_path(path)
    if chain != CHAIN_FS:
        return base
    root, ext = os.path.splitext(base)
    return root + _FS_SUFFIX + ext


def peer_path(path: str, chain: str = CHAIN_MAIN) -> str:
    """Return the alternate chain's path for cross-chain reads."""
    return chain_path(_base_path(path),
                      CHAIN_MAIN if chain == CHAIN_FS else CHAIN_FS)


def _canon(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


class ReceiptLockError(RuntimeError):
    """Raised when the sidecar receipt lock cannot be acquired in time."""


# Bounded lock timeout in seconds; configurable via DEMO_CLI_LOCK_TIMEOUT with fallback to 10.0s.
def _lock_timeout() -> float:
    try:
        value = float(os.environ.get("DEMO_CLI_LOCK_TIMEOUT", "10"))
    except (TypeError, ValueError):
        return 10.0
    return value if value > 0 else 10.0


_LOCK_TIMEOUT_SECONDS = _lock_timeout()
_LOCK_POLL_INTERVAL = 0.05


# File read configuration using errors="replace" so malformed UTF-8 lines do
# not crash readers or prevent subsequent receipt appends.
_READ = {"encoding": "utf-8", "errors": "replace"}


def _acquire(fh) -> None:
    """Take an exclusive, non-blocking lock on byte 0 of `fh`, retrying until
    `_LOCK_TIMEOUT_SECONDS` elapses. Raises ReceiptLockError rather than
    letting a caller proceed unlocked."""
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    if os.name == "nt":
        import msvcrt
        while True:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise ReceiptLockError(
                        f"Could not acquire receipt lock on {fh.name!r} "
                        f"within {_LOCK_TIMEOUT_SECONDS}s.")
                time.sleep(_LOCK_POLL_INTERVAL)
    else:
        import fcntl
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise ReceiptLockError(
                        f"Could not acquire receipt lock on {fh.name!r} "
                        f"within {_LOCK_TIMEOUT_SECONDS}s.")
                time.sleep(_LOCK_POLL_INTERVAL)


def _release(fh) -> None:
    if os.name == "nt":
        import msvcrt
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def _chain_lock(path: str):
    """Context manager acquiring an exclusive file lock on path + '.lock'."""
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)

    fh = open(lock_path, "a+b")
    try:
        # msvcrt.locking requires at least one byte; ensure file is non-empty.
        if os.fstat(fh.fileno()).st_size == 0:
            fh.write(b"\0")
            fh.flush()
            os.fsync(fh.fileno())

        _acquire(fh)
        try:
            yield
        finally:
            _release(fh)
    finally:
        fh.close()


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class Receipt:
    action_raw: str
    action_type: str
    target_environment: str
    decision: str
    reason: str
    mode: str
    matched_rule: Optional[str] = None
    classification: str = "safe"
    recovery_point: Optional[str] = None
    nonrecoverable_surface: Optional[str] = None
    dry_run_affected_rows: Optional[int] = None
    context: Dict = field(default_factory=dict)
    declared_intent: Dict = field(default_factory=dict)
    context_mismatches: List = field(default_factory=list)
    pipeline_segments: List = field(default_factory=list)
    remote_exec: bool = False
    # Shell dialect evaluated by the guard; None for non-shell operations.
    dialect: Optional[str] = None
    agent_id: str = "unknown"
    session_id: str = "unknown"
    invariant: str = INVARIANT
    receipt_version: str = RECEIPT_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_now)
    prev_receipt_hash: str = GENESIS
    # Advisory chain identifier (CHAIN_MAIN or CHAIN_FS).
    chain: str = CHAIN_MAIN
    # Peer chain head hash at write time for cross-chain causal ordering.
    peer_head: Optional[str] = None
    receipt_hash: str = ""

    def finalize(self) -> "Receipt":
        body = asdict(self)
        body.pop("receipt_hash")
        self.receipt_hash = hashlib.sha256(
            (_canon(body) + self.prev_receipt_hash).encode()).hexdigest()
        return self


def last_hash(path: str) -> str:
    r"""Return the last parseable receipt hash in path, or GENESIS if empty or nonexistent.

    Reads backwards from the tail via _tail_hash for O(1) tail lookups.
    """
    return _tail_hash(path)


# --------------------------------------------------------------------------
# CROSS-CHAIN ANCHORING
#
# Each receipt records the peer chain's head hash at the moment it was written:
#   1. ORDER: A receipt naming H(K) must have been written after K existed,
#      proving ordering without relying on machine clocks.
#   2. MUTUAL WITNESS: Truncating either chain breaks references from the
#      other chain, preventing undetected tail truncation.
# peer_head is included in the hashed receipt body.
# --------------------------------------------------------------------------
_PEER_CACHE: Dict[str, tuple] = {}   # path -> ((size, mtime_ns), head)
_PEER_CACHE_LOCK = threading.Lock()


def _tail_hash(path: str, max_bytes: int = 65536) -> str:
    """The last receipt_hash in a log, read from the tail rather than the whole
    file. Avoids O(n) full scans on every append."""
    # Expand the read window until a full line fits to avoid dropping partial
    # lines larger than max_bytes (which could otherwise fall through to GENESIS).
    # Doubling/quadrupling keeps O(1) performance for typical appends.
    try:
        size = os.path.getsize(path)
    except OSError:
        return GENESIS
    window = max(max_bytes, 1)
    while True:
        start = max(0, size - window)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                chunk = f.read()
        except OSError:
            return GENESIS
        lines = chunk.decode("utf-8", errors="replace").splitlines()
        if start > 0:
            lines = lines[1:]            # partial line from the mid-file seek
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)["receipt_hash"]
            except Exception:
                continue                 # torn line: keep walking backwards
        if start == 0:
            return GENESIS
        window *= 4


def peer_head(path: str, chain: str) -> Optional[str]:
    """The other chain's head, cached against its file identity (size, mtime).

    Cached on (size, mtime_ns) rather than a wall clock so bursts of appends
    anchor to the latest peer entries immediately while avoiding redundant
    reads when the peer file has not changed.
    """
    other = peer_path(path, chain)
    try:
        st = os.stat(other)
    except OSError:
        return None                      # no peer chain yet: nothing to anchor
    key = (st.st_size, st.st_mtime_ns)
    with _PEER_CACHE_LOCK:
        cached = _PEER_CACHE.get(other)
        if cached and cached[0] == key:
            return cached[1]
    head = _tail_hash(other)
    with _PEER_CACHE_LOCK:
        _PEER_CACHE[other] = (key, head)
    return head


def append_receipt(path: str, receipt: Receipt) -> Receipt:
    """Chain `receipt` to the log at `path` and persist it.

    The read-last-hash / finalize / append / flush / fsync sequence is held
    under a single exclusive cross-platform file lock (see `_chain_lock`) so
    concurrent writers cannot read the same last hash and append competing receipts.
    """
    receipt.action_raw = redact(receipt.action_raw)
    # Route by the receipt's own role rather than caller path.
    path = chain_path(path, getattr(receipt, "chain", CHAIN_MAIN))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    with _chain_lock(path):
        receipt.prev_receipt_hash = last_hash(path)
        # Read inside the lock before finalize so the anchored value is sealed in the hash.
        if receipt.peer_head is None:
            receipt.peer_head = peer_head(path, getattr(receipt, "chain", CHAIN_MAIN))
        receipt.finalize()
        # Ensure a torn line missing a trailing newline does not merge with
        # the newly appended receipt, which would corrupt both entries.
        needs_newline = False
        try:
            if os.path.getsize(path):
                with open(path, "rb") as probe:
                    probe.seek(-1, os.SEEK_END)
                    needs_newline = probe.read(1) != b"\n"
        except OSError:
            pass                        # no file yet: nothing to heal
        with open(path, "a", encoding="utf-8") as f:
            if needs_newline:
                f.write("\n")
            f.write(_canon(asdict(receipt)) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return receipt


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    head: str = GENESIS
    decisions: Dict[str, int] = field(default_factory=dict)
    broken_at: Optional[int] = None   # 1-based line number
    detail: Optional[str] = None
    # Damaged lines (unparseable/torn writes) are tracked and skipped rather
    # than immediately failing as tampering, allowing verification to resume
    # in segments across surviving valid entries.
    damaged_lines: List[int] = field(default_factory=list)
    segments: int = 1
    # Entries whose predecessor hash appears only inside an unreadable line:
    # a torn write and a re-typed hash look identical from here.
    inconclusive: List[int] = field(default_factory=list)
    # Lines whose `chain` disagrees with the file - two writers, one ledger.
    chain_conflict: List[int] = field(default_factory=list)
    # Entries whose prev_receipt_hash names a receipt that IS in this file,
    # but not the line immediately before them. See verify_chain.
    out_of_order: List[int] = field(default_factory=list)
    ledger: Optional[str] = None      # which file this result describes
    # No log at all. Uninitialized state rather than an integrity failure.
    absent: bool = False

    @property
    def damaged(self) -> bool:
        return bool(self.damaged_lines)

    @property
    def reordered(self) -> bool:
        return bool(self.out_of_order)


def _chain_conflict(path: str, rows) -> List[int]:
    """Line numbers whose `chain` disagrees with the file they sit in.

    Enforces the one-writer-per-file invariant introduced by the chain split.
    Legacy receipts predate the field and carry no `chain` (absent is permitted);
    only an explicitly disagreeing value is flagged as a conflict.
    """
    expected = CHAIN_FS if _base_path(path) != path else CHAIN_MAIN
    return [n for n, r in rows
            if r.get("chain") is not None and r.get("chain") != expected]


def verify_chain(path: str) -> VerifyResult:
    """Walk the receipt log end to end and report whether the hash chain holds.

    Returns ok=True for an intact chain, INCLUDING one interrupted by torn
    writes: every entry that survives is verified, and `damaged_lines` /
    `segments` say what could not be read. ok=False means tampering - content
    that was edited, inserted, removed or reordered.
    """
    if not os.path.exists(path):
        # An absent log represents an uninitialized state rather than tampering.
        # Report absent=True so the caller can distinguish it from a verified log.
        return VerifyResult(ok=True, absent=True, ledger=path,
                            detail="No receipts recorded yet.")

    rows = []
    damaged: List[int] = []
    # Hashes recoverable from lines that will NOT parse. A torn record still
    # carries its hash as readable text, and an entry that legitimately links
    # to it must not be called a removal just because the line is unreadable.
    salvaged: set = set()
    with open(path, **_READ) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append((n, json.loads(line)))
            except Exception:
                damaged.append(n)
                salvaged.update(_HASH_TOKEN.findall(line))

    # An appended receipt links to the last readable receipt (skipping damaged lines).
    # Distinguish between parsed receipts ('readable') and raw tokens from damaged
    # lines ('salvaged') so forged tokens cannot masquerade as valid entries.
    readable = {r.get("receipt_hash") for _, r in rows}
    inconclusive: List[int] = []
    # Check for chain conflicts before walking: if writers interleaved into
    # the same ledger, ordering cannot be trusted.
    conflict = _chain_conflict(path, rows)
    prev = GENESIS
    prev_line = 0
    segments = 1
    out_of_order: List[int] = []
    for n, r in rows:
        stored = r.get("receipt_hash", "")
        body = {k: v for k, v in r.items() if k != "receipt_hash"}
        recomputed = hashlib.sha256(
            (_canon(body) + r.get("prev_receipt_hash", "")).encode()).hexdigest()
        # Self-consistency check: verify receipt body hash against stored hash.
        if recomputed != stored:
            return VerifyResult(ok=False, broken_at=n, damaged_lines=damaged,
                                out_of_order=out_of_order,
                                chain_conflict=conflict, ledger=path,
                                detail="A field in this entry was edited after it was written.")
        link = r.get("prev_receipt_hash")
        if link != prev:
            if link in readable:
                # Out of order: predecessor exists in file but not on preceding line.
                out_of_order.append(n)
            elif link in salvaged:
                # Predecessor hash found only within an unparseable/torn line.
                inconclusive.append(n)
            elif conflict:
                # Chain conflict: cross-writer ordering in this file is untrusted.
                inconclusive.append(n)
            else:
                return VerifyResult(ok=False, broken_at=n, damaged_lines=damaged,
                                    out_of_order=out_of_order,
                                    inconclusive=inconclusive,
                                    chain_conflict=conflict, ledger=path,
                                    detail="An entry is missing: this one links to a "
                                           "receipt that is not in the log.")
        prev = stored
        prev_line = n

    decisions: Dict[str, int] = {}
    for _, r in rows:
        d = r.get("decision", "?")
        decisions[d] = decisions.get(d, 0) + 1
    notes = []
    if damaged:
        notes.append(f"{len(damaged)} line(s) could not be read. Every entry "
                     f"that could be read is verified; what the unreadable "
                     f"lines held cannot be established from this file.")
    if inconclusive:
        n_i = len(inconclusive)
        notes.append(f"{n_i} entr{'y' if n_i == 1 else 'ies'} link to a hash that "
                     f"appears only inside an unreadable line. That is what a torn "
                     f"write looks like, and also what removing an entry and "
                     f"re-typing its hash looks like. Not decidable here.")
    if conflict:
        notes.append(f"{len(conflict)} entr{'y' if len(conflict) == 1 else 'ies'} "
                     f"carry a different chain than the file they are in - two "
                     f"writers reached one ledger, which the split exists to "
                     f"prevent. Treat ordering in this file as unreliable.")
    if out_of_order:
        n_ooo = len(out_of_order)
        notes.append(f"{n_ooo} entr{'y' if n_ooo == 1 else 'ies'} out of chain order. Every "
                     f"referenced receipt is present, so nothing was removed - "
                     f"consistent with concurrent writers appending at stale "
                     f"offsets, or with deliberate reordering.")
    return VerifyResult(ok=not (out_of_order or inconclusive or conflict),
                        entries=len(rows), head=prev,
                        decisions=decisions, damaged_lines=damaged,
                        segments=segments, out_of_order=out_of_order,
                        inconclusive=inconclusive, chain_conflict=conflict,
                        ledger=path, detail=" ".join(notes) or None)


@dataclass
class CrossLinkResult:
    """Cross-chain verification result linking main and fs chains."""
    verified: int = 0            # peer_head values that resolve to a real entry
    unresolved: List[str] = field(default_factory=list)
    checked: bool = False        # False when there is no second chain to check
    # Entries appended after the last peer write (outside the cross-check window).
    unanchored: int = 0

    @property
    def ok(self) -> bool:
        return self.checked and not self.unresolved


def verify_cross_links(main_path: str, fs_path: str) -> CrossLinkResult:
    """Check that every peer_head names a hash that exists in the other chain.

    Detects tail truncation across chains: if entries are stripped from one chain,
    the other chain will still reference missing heads. Missing chains report
    checked=False.
    """
    res = CrossLinkResult()
    if not (os.path.exists(main_path) and os.path.exists(fs_path)):
        # When only one chain exists, all its entries are unanchored.
        res.unanchored = _unanchored_after_last_peer_write(main_path, fs_path)
        return res
    res.checked = True

    def hashes(p):
        out = set()
        try:
            with open(p, **_READ) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        h = json.loads(line).get("receipt_hash")
                    except Exception:
                        continue          # torn line: not evidence of anything
                    if h:
                        out.add(h)
        except OSError:
            pass
        return out

    known = {CHAIN_MAIN: hashes(main_path), CHAIN_FS: hashes(fs_path)}
    for path, chain in ((main_path, CHAIN_MAIN), (fs_path, CHAIN_FS)):
        peer = known[CHAIN_FS if chain == CHAIN_MAIN else CHAIN_MAIN]
        try:
            with open(path, **_READ) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    ph = r.get("peer_head")
                    # GENESIS is "the peer chain was empty", not a reference.
                    if not ph or ph == GENESIS:
                        continue
                    if ph in peer:
                        res.verified += 1
                    else:
                        res.unresolved.append(ph[:16])
        except OSError:
            pass

    # peer_head anchors backwards to the peer's head at write time. Entries
    # appended after the last peer write are unanchored until the next peer append.
    res.unanchored = _unanchored_after_last_peer_write(main_path, fs_path)
    return res


def _unanchored_after_last_peer_write(main_path: str, fs_path: str) -> int:
    """Entries in either chain written after the last receipt in the other."""
    tail_a = tail_receipts(main_path, n=1)
    tail_b = tail_receipts(fs_path, n=1)
    r_a = tail_a[0] if tail_a else None
    r_b = tail_b[0] if tail_b else None
    if not r_a or not r_b:
        # When only one chain exists, all entries are unanchored.
        cnt_a = sum(1 for _ in iter_receipts(main_path))
        cnt_b = sum(1 for _ in iter_receipts(fs_path))
        return cnt_a + cnt_b

    ts_a = str(r_a.get("timestamp") or "")
    ts_b = str(r_b.get("timestamp") or "")

    if ts_a > ts_b:
        return sum(1 for r in iter_receipts(main_path) if str(r.get("timestamp") or "") > ts_b)
    elif ts_b > ts_a:
        return sum(1 for r in iter_receipts(fs_path) if str(r.get("timestamp") or "") > ts_a)
    return 0


def anchor_chains(path: str) -> bool:
    """Explicitly anchor both chains against each other to close the unanchored tail.

    Writes a mutual anchor checkpoint to both chains, binding them to their
    current heads and reducing the unanchored count to 0.

    Returns True if an anchor was written, False if either chain is missing or
    there were no unanchored entries.
    """
    main_p = chain_path(path, CHAIN_MAIN)
    fs_p = chain_path(path, CHAIN_FS)
    if not (os.path.exists(main_p) and os.path.exists(fs_p)):
        return False

    if _unanchored_after_last_peer_write(main_p, fs_p) == 0:
        return False

    ts = _now()

    append_receipt(main_p, Receipt(
        action_raw="[fs] anchor checkpoint",
        action_type="checkpoint",
        target_environment="local",
        decision="ALLOW",
        reason="Mutual cross-chain anchor checkpoint.",
        mode="enforce-fs",
        matched_rule="fs_anchor",
        agent_id="fsguard",
        session_id="anchor",
        chain=CHAIN_FS,
        timestamp=ts,
    ))

    append_receipt(main_p, Receipt(
        action_raw="[main] anchor checkpoint",
        action_type="checkpoint",
        target_environment="local",
        decision="ALLOW",
        reason="Mutual cross-chain anchor checkpoint.",
        mode="enforce",
        matched_rule="main_anchor",
        agent_id="cli",
        session_id="anchor",
        chain=CHAIN_MAIN,
        timestamp=ts,
    ))
    return True


def iter_receipts(path: str) -> Iterator[dict]:
    """Yield every parseable receipt in the log, oldest first. Read-only, streaming."""
    if not os.path.exists(path):
        return
    with open(path, **_READ) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def load_receipts(path: str) -> List[dict]:
    """Return every receipt in the log, oldest first. Read-only."""
    return list(iter_receipts(path))


def iter_all_receipts(path: str) -> Iterator[dict]:
    """Yield every receipt from both chains (main and fs) merged chronologically.

    SPLIT ON WRITE, MERGED ON READ. Streams from disk in O(1) memory by merging
    the two sorted chain logs via heapq.merge.
    """
    base = _base_path(path)
    fs_p = chain_path(base, CHAIN_FS)
    has_base = os.path.exists(base)
    has_fs = os.path.exists(fs_p)

    if not has_fs:
        yield from iter_receipts(base)
        return
    if not has_base:
        yield from iter_receipts(fs_p)
        return

    yield from heapq.merge(
        iter_receipts(base),
        iter_receipts(fs_p),
        key=lambda r: str(r.get("timestamp") or "")
    )


def load_all_receipts(path: str) -> List[dict]:
    """Return every receipt from both chains (main and fs), oldest first.

    SPLIT ON WRITE, MERGED ON READ. The two files exist so that each is
    written from only one side of the WinFsp mount; nothing that reads them
    needs to know, so list, share, status and report see a single chronological
    stream.
    """
    return list(iter_all_receipts(path))


def tail_receipts(path: str, n: int = 20, max_bytes: int = 65536) -> List[dict]:
    """Return up to `n` receipts from the tail of the log at `path`, oldest first.
    Reads backwards in windows from the file end to avoid loading the entire
    file into memory.
    """
    if n <= 0:
        return []
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size == 0:
        return []

    window = max(max_bytes, n * 1024)
    while True:
        start = max(0, size - window)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                chunk = f.read()
        except OSError:
            return []

        lines = chunk.decode("utf-8", errors="replace").splitlines()
        if start > 0:
            lines = lines[1:]  # drop partial line from mid-file seek

        parsed = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
                if len(parsed) == n:
                    break
            except Exception:
                continue

        if len(parsed) == n or start == 0:
            parsed.reverse()
            return parsed

        window *= 4


def tail_all_receipts(path: str, n: int = 20) -> List[dict]:
    """Return up to `n` receipts across both chains (main and fs), oldest first.

    Reads from the tail of each log with bounded memory, merges them,
    and returns the latest `n` entries chronologically.
    """
    if n <= 0:
        return []
    base = _base_path(path)
    fs_p = chain_path(base, CHAIN_FS)
    main_tail = tail_receipts(base, n=n)
    fs_tail = tail_receipts(fs_p, n=n) if os.path.exists(fs_p) else []
    if not fs_tail:
        return main_tail
    if not main_tail:
        return fs_tail
    merged = main_tail + fs_tail
    merged.sort(key=lambda r: str(r.get("timestamp") or ""))
    return merged[-n:]


def latest_receipt(path: str) -> Optional[dict]:
    """Return the most recent receipt across both chains, or None."""
    tail = tail_all_receipts(path, n=1)
    return tail[0] if tail else None


def find_receipt(path: str, receipt_id: Optional[str] = None) -> Optional[dict]:
    """Pick a receipt: by (full or prefix) id if given, else the most recent.

    Matching by prefix mirrors how `log`/`undo` show short ids, so a user can
    paste the 8-char id they see rather than the full uuid. Searches across
    both main and filesystem receipt chains.
    """
    if not receipt_id or not receipt_id.strip():
        return latest_receipt(path)

    rid = receipt_id.strip()
    base = _base_path(path)
    fs_p = chain_path(base, CHAIN_FS)
    chains = [base]
    if os.path.exists(fs_p):
        chains.append(fs_p)

    exact_match = None
    prefix_match = None
    prefix_count = 0

    for cp in chains:
        for r in iter_receipts(cp):
            cid = str(r.get("receipt_id", ""))
            if cid == rid:
                exact_match = r
                break
            elif cid.startswith(rid):
                prefix_count += 1
                if prefix_count == 1:
                    prefix_match = r
        if exact_match is not None:
            break

    if exact_match is not None:
        return exact_match
    return prefix_match if prefix_count == 1 else None


def _fence_safe(text: str) -> str:
    r"""Neutralise characters (backticks and newlines) that would prematurely
    terminate markdown code fences in generated share cards.
    """
    if not text:
        return text
    return (text.replace("`", "\u02cb")          # modifier letter grave accent
                .replace("\r", " ")
                .replace("\n", " "))


def share_card(receipt: dict, *, repo: str = "github.com/nizaryart/DEMO_LOADING") -> str:
    """Build a copy-pasteable, plain-text (markdown-safe) proof card for a
    single receipt, plus a one-line command anyone can run to verify the chain
    this receipt belongs to.

    Deliberately colour-free: the shared artifact is meant to be pasted into a
    forum/PR/issue, where ANSI codes would be noise. `action_raw` is already
    redacted at write time, so the card inherits that privacy property.
    """
    rid = str(receipt.get("receipt_id", "?"))
    short = rid[:8]
    decision = receipt.get("decision", "?")
    reason = receipt.get("reason", "")
    action = _fence_safe(receipt.get("action_raw", ""))
    rule = receipt.get("matched_rule")
    surface = receipt.get("nonrecoverable_surface")
    env = receipt.get("target_environment", "unknown")
    recovered = bool(receipt.get("recovery_point"))
    rhash = str(receipt.get("receipt_hash", ""))
    phash = str(receipt.get("prev_receipt_hash", ""))
    ts = receipt.get("timestamp", "")

    intent = receipt.get("declared_intent") or {}
    reasoning = ""
    if isinstance(intent, dict):
        reasoning = intent.get("reasoning") or ""

    outcome = ("recovery point captured — reversible with one command"
               if recovered else
               "hard-stopped before it ran — no honest recovery point exists for this")

    lines = [
        "```",
        "demo_cli — pre-execution receipt",
        "",
        f"  command      {action}",
        f"  decision     {decision}",
    ]
    if rule:
        lines.append(f"  matched      {rule}")
    if surface:
        lines.append(f"  surface      {surface}")
    lines += [
        f"  environment  {env}",
        f"  outcome      {outcome}",
    ]
    if reasoning:
        lines.append(f"  agent's why  {reasoning[:200]}")
    lines += [
        "",
        f"  receipt      {short}   {ts}",
        f"  hash         {rhash[:32]}…",
        f"  prev         {phash[:32]}…",
        "",
        "  hash-chained: an edit to any entry below breaks the chain.",
        "  a head recorded elsewhere is what detects a whole-file rewrite.",
        "  verify the chain yourself:",
        f"    pipx install git+https://{repo}.git@{release_tag()} && demo_cli verify",
        "```",
    ]
    return "\n".join(lines)
