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
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .context import redact
from .decide import INVARIANT
from .version import release_tag

RECEIPT_VERSION = "2.0"
GENESIS = "0" * 64

# A sha256 hex digest as it appears in a torn line's surviving text. Used to
# tell "the predecessor is unreadable" apart from "the predecessor is gone".
_HASH_TOKEN = re.compile(r"\b[0-9a-f]{64}\b")

# --------------------------------------------------------------------------
# ONE WRITER PER FILE.
#
# The receipt log used to be a single file, and on Windows that file is
# reachable by two paths: through the WinFsp mount (which the hook and the
# egress addon use) and directly in the backing directory (which the mount
# process itself uses). Byte-range locks do not compose across WinFsp - a lock
# taken through the mount and a lock taken on NTFS are different locks - so
# both sides held "the" lock at once and appended at stale offsets.
#
# Observed 2026-09-02 on the labubu project: `demo_cli verify` reported
# TAMPERED at line 349, and the file contained records cut mid-key with the
# next record written over the remains. Nothing had tampered with anything;
# the guard had corrupted its own audit trail.
#
# The fix is not better locking. It is removing the need for locking to work
# across the boundary at all: each chain is written from exactly one side.
# Splitting happens on WRITE; every read merges. See recovery.load_entries and
# cli.cmd_verify - no command anyone types changes shape.
CHAIN_MAIN = "main"     # hook, egress, CLI - written through the mount
CHAIN_FS = "fs"         # the filesystem guard - written in the backing

_FS_SUFFIX = "-fs"


def _base_path(path: str) -> str:
    """The main chain's path, whichever chain's path was handed in.

    Normalising first makes chain_path idempotent: chain_path(fs_path, FS) is
    the fs path, not the fs path with a second suffix. Without this, deriving
    a peer from an already-routed path returned that path itself - so an fs
    receipt anchored to its own chain instead of the main one, and every
    peer_head came back None.
    """
    root, ext = os.path.splitext(path)
    if root.endswith(_FS_SUFFIX):
        return root[:-len(_FS_SUFFIX)] + ext
    return path


def chain_path(path: str, chain: str = CHAIN_MAIN) -> str:
    """Where a given chain's receipts live.

    receipts.jsonl -> receipts-fs.jsonl. Derived rather than configured: two
    settings that must agree is a way for them to disagree.
    """
    base = _base_path(path)
    if chain != CHAIN_FS:
        return base
    root, ext = os.path.splitext(base)
    return root + _FS_SUFFIX + ext


def peer_path(path: str, chain: str = CHAIN_MAIN) -> str:
    """The OTHER chain's file, for cross-chain reads. Accepts either chain's
    path, because callers hold whichever one they happen to be writing."""
    return chain_path(_base_path(path),
                      CHAIN_MAIN if chain == CHAIN_FS else CHAIN_FS)


def _canon(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


class ReceiptLockError(RuntimeError):
    """Raised when the sidecar receipt lock cannot be acquired in time."""


# Bounded so a stuck lock fails loudly instead of hanging a hook forever.
#
# Parsed defensively because this runs at IMPORT time, and the hook, the egress
# addon and the filesystem guard all import this module. `DEMO_CLI_LOCK_TIMEOUT=abc`
# raised ValueError before any of them could start - a typo in one environment
# variable took the whole guard down at startup rather than falling back.
def _lock_timeout() -> float:
    try:
        value = float(os.environ.get("DEMO_CLI_LOCK_TIMEOUT", "10"))
    except (TypeError, ValueError):
        return 10.0
    return value if value > 0 else 10.0


_LOCK_TIMEOUT_SECONDS = _lock_timeout()
_LOCK_POLL_INTERVAL = 0.05


# READERS PASS errors="replace"; THE WRITER DOES NOT NEED TO.
#
# Two bytes of invalid UTF-8 anywhere in a ledger used to raise
# UnicodeDecodeError out of verify_chain, last_hash, load_receipts and both
# cross-link loops. The try/except in each only wrapped json.loads, and the
# decode happens before it.
#
# last_hash is called INSIDE append_receipt, under the lock - so the file
# could never be appended to again. Not denial of verification: DENIAL OF
# RECORDING, silently, for every future command on that project. Found by
# review 2026-09-09, and reachable without an attacker: a command carrying a
# binary blob is enough.
#
# _tail_hash already had it, which is the tell - the author hit this once and
# fixed the one call site in front of them.
#
# The writer is safe as it stands: json.dumps(ensure_ascii=True) escapes even
# a lone surrogate from os.fsdecode before it reaches the file. Verified, so
# nobody adds a guard that is not needed.
#
# WHAT THIS DOES NOT DO: recover anything. A mangled line stays unreadable and
# the receipt it swallowed is gone. This restores the ability to read and to
# keep recording; it is not retroactive healing.
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
    """Exclusive lock guarding the read-last-hash / append pair, held across
    the full critical section (read last hash -> finalize -> append -> flush
    -> fsync). POSIX uses fcntl.flock; Windows uses msvcrt.locking on one byte
    of the sidecar `.lock` file. Both sides poll with a bounded retry loop and
    raise ReceiptLockError instead of silently proceeding unlocked."""
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)

    fh = open(lock_path, "a+b")
    try:
        # msvcrt.locking needs at least one byte to lock; keep it non-empty
        # either way so byte-0 locking is always well defined.
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
    # Which shell the guard judged this text as. None for anything that is not
    # a shell command (a file edit has no dialect). The adapters decide it from
    # signals the receipt does not otherwise record, so without this the trail
    # cannot answer "which rules were even eligible" after the fact.
    dialect: Optional[str] = None
    agent_id: str = "unknown"
    session_id: str = "unknown"
    invariant: str = INVARIANT
    receipt_version: str = RECEIPT_VERSION
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_now)
    prev_receipt_hash: str = GENESIS
    # Which log this belongs to. Advisory for grouping during verification,
    # never a filter for reading: receipts written before the split have no
    # `chain` and must keep verifying exactly as they did.
    chain: str = CHAIN_MAIN
    # The other chain's head hash when this was written, or None when there is
    # no other chain yet. Proves this receipt came after that one; see the
    # CROSS-CHAIN ANCHORING note above.
    peer_head: Optional[str] = None
    receipt_hash: str = ""

    def finalize(self) -> "Receipt":
        body = asdict(self)
        body.pop("receipt_hash")
        self.receipt_hash = hashlib.sha256(
            (_canon(body) + self.prev_receipt_hash).encode()).hexdigest()
        return self


def last_hash(path: str) -> str:
    r"""The hash every new receipt chains onto: the last parseable one, or
    GENESIS when the file holds none.

    READ FROM THE TAIL. This scanned the WHOLE FILE, line by line, once per
    append - so appending n receipts cost O(n^2) in total, and the cost landed
    in the pre-execution path where the user waits for it. Measured on a real
    receipt line of 888 bytes (2026-09-10):

        entries      file    last_hash    append_receipt
            100    0.1 MB      0.62 ms           5.66 ms
         10,000    8.6 MB        83 ms             86 ms
         50,000     43 MB       459 ms            541 ms
        100,000     86 MB      1145 ms            955 ms

    Half a second of latency, before the command runs, on every command,
    because the ledger got long. Nothing was wrong with any receipt - this was
    never a correctness fault - but a guard that gets slower the longer you
    have trusted it is a guard people turn off.

    _tail_hash has the identical contract and is flat at ~0.15 ms at every one
    of those sizes: it walks backwards, skips torn lines the same way, widens
    its window until it finds a parseable receipt, and returns GENESIS only
    after it has read the whole file. It was written for the PEER chain during
    the 2026-09-09 review, for this exact reason - its own docstring says a
    full scan per append turns a 200-file delete into 200 full reads - and
    nobody pointed the main chain at it.

        THE FIX WAS ALREADY IN THE FILE, APPLIED TO THE OTHER CALLER.

    Kept as a named function rather than inlined: it is what the rest of this
    module and its tests call the operation, and the two contracts are worth
    stating separately even when one delegates to the other.
    """
    return _tail_hash(path)


# --------------------------------------------------------------------------
# CROSS-CHAIN ANCHORING
#
# Splitting the log by writer stopped the corruption, but it cost the one
# property a single chain had: nothing linked a hook receipt to the filesystem
# capture that followed it. Two separate chains are two separate stories.
#
# Each receipt therefore records the OTHER chain's head hash at the moment it
# was written. That single field buys two things:
#
#   ORDER. A receipt naming H(K) must have been written after K existed - you
#   cannot reference a hash that has not been computed yet. So "the guard
#   evaluated the command before the deletion happened" becomes provable from
#   the files alone, with no trust in either machine's clock.
#
#   MUTUAL WITNESS. Delete K from the main chain and two things break: that
#   chain's own links, AND every fs receipt pointing at a hash now absent.
#   This closes truncation, the one attack a lone hash chain misses entirely -
#   lop off the tail of a single chain and what remains verifies perfectly.
#
# peer_head sits inside the hashed body, so it cannot be edited without
# breaking its own receipt's hash. It costs nothing to protect.
#
# WHAT IT DOES NOT DO: stop someone who can rewrite BOTH files consistently.
# Neither does a single chain - same threat model, no regression. The answer
# to that is an external anchor, which `verify` now prints the heads for.
_PEER_CACHE: Dict[str, tuple] = {}   # path -> ((size, mtime_ns), head)


def _tail_hash(path: str, max_bytes: int = 65536) -> str:
    """The last receipt_hash in a log, read from the tail rather than the whole
    file. The fs guard writes one receipt per file in a recursive delete, so a
    full O(n) scan per append turns a 200-file delete into 200 full reads."""
    # WIDEN UNTIL A WHOLE LINE FITS. GENESIS MEANS EMPTY, NOTHING ELSE.
    #
    # With a fixed window, a final line larger than it left only a partial
    # line, `lines[1:]` dropped that, and the function fell through to
    # GENESIS - which peer_head then recorded as the anchor, and
    # verify_cross_links skips GENESIS because it documents it as "the peer
    # chain was empty". So the anchor silently vanished and truncation of the
    # peer chain became undetectable.
    #
    # No attacker needed: a receipt whose action_raw runs past ~64 KB does it,
    # and redact() does not truncate. Found by review 2026-09-09 - the
    # control/bug pair was stark: a small tail gave unresolved=[hash], ok=False
    # on truncation; a large tail gave unresolved=[], ok=True.
    #
    # Doubling rather than reading the whole file keeps the O(1)-per-append
    # property this function exists for; it degrades to one full read only for
    # a file whose last line really is enormous.
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
            # The whole file has been read and holds no parseable receipt.
            # THIS is what GENESIS means.
            return GENESIS
        window *= 4


def peer_head(path: str, chain: str) -> Optional[str]:
    """The other chain's head, cached against its file identity.

    CACHED ON (size, mtime), NOT ON A CLOCK. A time-based cache was the first
    attempt and it silently weakened the guarantee: during a fast burst every
    receipt anchored to the same older head, so the NEWEST peer entries were
    referenced by nothing - and truncating exactly those, the easiest and most
    useful thing to remove, went undetected. A test caught it.

    Stat is microseconds and changes the instant the peer is appended to, by
    any process. So the burst optimisation survives - during a long run of fs
    captures the main chain is not moving, so the file is read once - while
    every anchor stays current.

    A stale value would still be SAFE in the sense that "written after that
    one" remains true. But safe is not the same as useful: an edge to an old
    entry proves less, and the entries that most need covering are the recent
    ones.
    """
    other = peer_path(path, chain)
    try:
        st = os.stat(other)
    except OSError:
        return None                      # no peer chain yet: nothing to anchor
    key = (st.st_size, st.st_mtime_ns)
    cached = _PEER_CACHE.get(other)
    if cached and cached[0] == key:
        return cached[1]
    head = _tail_hash(other)
    _PEER_CACHE[other] = (key, head)
    return head


def append_receipt(path: str, receipt: Receipt) -> Receipt:
    """Chain `receipt` to the log at `path` and persist it.

    The read-last-hash / finalize / append / flush / fsync sequence is held
    under a single exclusive cross-platform file lock (see `_chain_lock`) so
    concurrent writers - threads, or separate processes such as real hooks -
    cannot read the same last hash and append competing receipts.
    """
    receipt.action_raw = redact(receipt.action_raw)
    # ROUTE BY THE RECEIPT'S OWN ROLE, not by the caller's path. A caller that
    # passes cfg.receipts_path and sets chain="fs" gets the fs file; nobody has
    # to remember to build the right path at each call site, and a new writer
    # cannot land in the wrong chain by forgetting.
    path = chain_path(path, getattr(receipt, "chain", CHAIN_MAIN))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    with _chain_lock(path):
        receipt.prev_receipt_hash = last_hash(path)
        # Read INSIDE the lock, before finalize, so the anchored value is the
        # one that gets hashed. Outside it, a concurrent append could change
        # the peer head between reading and sealing.
        if receipt.peer_head is None:
            receipt.peer_head = peer_head(path, getattr(receipt, "chain", CHAIN_MAIN))
        receipt.finalize()
        # HEAL A TRUNCATED LINE INSTEAD OF LANDING ON IT.
        #
        # recovery._record has done this since 2026-08-25 and its docstring
        # spells out why: a write interrupted before its newline leaves a
        # partial line, and the next append lands on that SAME line, producing
        # `{...partial}{"receipt_id": ...}` - one unparseable line holding
        # both. The broken record takes the next good one down with it.
        #
        # append_receipt never got it. So the receipt chain, which is the
        # tamper-evidence artefact, was LESS robust than the recovery index:
        # a torn write destroyed the following receipt outright rather than
        # merely leaving a gap. Found while establishing that a genuine tear
        # does not break a link (2026-09-09) - exactly the "two
        # implementations of append safely is how they drift" that _record's
        # own comment warned about.
        #
        # This heals FORWARD only. The already-torn line stays unreadable and
        # whatever it swallowed is gone; nothing here is retroactive.
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
    # DAMAGE IS NOT TAMPERING, and saying so was a lie the verifier told.
    #
    # A line that will not parse is a WRITE that did not complete - a torn
    # append, a process killed mid-write, or the lock-domain bug that produced
    # exactly this on labubu (line 349, 2026-09-02). Nothing was altered.
    # Reporting "the log was altered" is the verifier claiming knowledge it
    # does not have, which is the same unearned certainty as an unearned
    # REVERSIBLE - the invariant this whole tool exists to keep.
    #
    # So: damaged lines are recorded and SKIPPED, and verification resumes
    # from the next entry as a new segment. Tampering - a line that parses but
    # whose hash or link is wrong - still fails hard, because that is a claim
    # the evidence supports.
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
    # No log at all. NOT an integrity failure - there is nothing to have
    # altered - but not evidence of protection either, so it gets its own
    # state rather than being folded into either neighbour.
    absent: bool = False

    @property
    def damaged(self) -> bool:
        return bool(self.damaged_lines)

    @property
    def reordered(self) -> bool:
        return bool(self.out_of_order)


def _chain_conflict(path: str, rows) -> List[int]:
    """Line numbers whose `chain` disagrees with the file they sit in.

    ONE WRITER PER FILE is the invariant the chain split introduced, and until
    now nothing checked it. It is not decoration: verify_chain's correctness
    depends on it. The `after_damage` excuse was deleted because a link can
    only break after a tear when two writers interleave across lock domains -
    the labubu shape - and the split makes that impossible. If the split is
    ever violated again (it was once, on 2026-09-02, the guard writing to the
    wrong ledger) that shape returns, and without this check it would surface
    as a flat TAMPERED verdict against an honest project.

    So the residual risk becomes an accurate diagnosis instead of a false
    accusation. Legacy receipts predate the field and carry no `chain`; absent
    is fine, only a DISAGREEING value is a conflict.
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
        # A LOG THAT DOES NOT EXIST HAS NOT BEEN TAMPERED WITH.
        #
        # This used to return ok=False, which `verify` rendered as TAMPERED -
        # so a freshly set-up project, seconds old and working perfectly,
        # was told its audit trail had been altered (dari, 2026-09-02). That
        # is a false alarm of the worst kind: it fires exactly when someone is
        # checking whether the tool works, and it accuses the tool of the one
        # thing it exists to detect.
        #
        # Reported as its own state instead. Not a failure - and not a pass
        # either, which is why `absent` is set and the renderer says plainly
        # that nothing has been recorded.
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

    # THERE IS NO `after_damage` EXCUSE ANY MORE, and the reason is worth
    # keeping because the excuse looked obviously necessary.
    #
    # It suppressed the broken-link failure for the first readable entry after
    # a damaged line, on the theory that a torn line takes its hash with it and
    # the next entry has nothing to link to. THAT NEVER HAPPENS. last_hash
    # SKIPS unparseable lines, so a receipt appended after a tear links to the
    # last GOOD entry - across the damage - and no link is broken at all.
    # Demonstrated 2026-09-09: m1, a real interrupted append, then m4, gives
    # m4.prev == m1.receipt_hash and segments == 1.
    #
    # So the excuse could only ever fire on a link that was intact when it was
    # written and unreadable afterwards - which without editing requires two
    # writers interleaving across lock domains. That is the labubu shape at
    # line 348, and ONE WRITER PER FILE is precisely what the chain split was
    # built to stop. The excuse was rescuing a case the split had already
    # removed.
    #
    # Meanwhile an attacker chose where to put a junk line, and a removal is
    # contiguous by construction, so one garbage line landed exactly in the
    # hole: five receipts, entries 3 and 4 replaced by one bad line, verdict
    # ok=True with "a torn write, not an alteration - nothing was edited"
    # printed over a deliberate removal. Reordering and forged insertion went
    # the same way, the hash being unkeyed.
    #
    # The split is an UNENFORCED invariant and has been violated once, so
    # deleting the excuse without checking the invariant would make
    # correctness quietly conditional on it. Hence _chain_conflict below.
    # Every hash this file contains, readable or salvaged. A link naming one
    # of these points at an entry that IS here - so nothing was removed, the
    # entries are merely not in chain order.
    # TWO SETS, NOT ONE, and the difference is the difference between a fact
    # and a guess. `readable` holds hashes of entries we actually parsed.
    # `salvaged` holds 64-hex tokens scraped off lines that would not parse -
    # which is evidence that a hash was THERE, and no evidence at all that it
    # belonged to a receipt. Merging them let a link resolve against a token
    # an attacker typed into their own junk line, and the report then said
    # "every referenced receipt is present, so nothing was removed" over a
    # removal (2026-09-09).
    readable = {r.get("receipt_hash") for _, r in rows}
    inconclusive: List[int] = []
    # BEFORE THE WALK, because it changes what a broken link MEANS.
    #
    # Two writers in one ledger produce exactly the shape a removal produces -
    # that is the labubu case. Computed after the loop, the "an entry is
    # missing" early return fired first and the report accused an honest
    # project of tampering while the real diagnosis sat one line below,
    # uncomputed. The better explanation must be available before the worse
    # one is asserted.
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
        # SELF-CONSISTENCY IS CHECKED FIRST, and is never excused. It needs no
        # predecessor, so neither damage nor disorder can cover an edited field.
        if recomputed != stored:
            return VerifyResult(ok=False, broken_at=n, damaged_lines=damaged,
                                out_of_order=out_of_order,
                                chain_conflict=conflict, ledger=path,
                                detail="A field in this entry was edited after it was written.")
        link = r.get("prev_receipt_hash")
        if link != prev:
            if link in readable:
                # OUT OF ORDER, NOT REMOVED. The predecessor is in this file,
                # just not on the preceding line. That is what concurrent
                # writers appending at stale offsets produce, and it is the
                # commonest shape of the WinFsp lock-domain bug - observed on
                # labubu at line 348, where an egress receipt correctly linked
                # to an fsguard receipt stored further along and torn.
                #
                # Reported, and still a failure, but NOT called tampering:
                # "an entry was removed" is a claim the evidence contradicts,
                # since the entry is right there. Deliberate reordering
                # produces the same shape, so the wording names both causes
                # and asserts neither.
                out_of_order.append(n)
            elif link in salvaged:
                # THE HASH IS IN AN UNREADABLE LINE. We cannot say the
                # predecessor is present - only that its hash appears in text
                # we could not parse. That is exactly what a genuine torn
                # write looks like AND exactly what someone deleting an entry
                # and typing its hash into a junk line looks like. The two are
                # indistinguishable from here, so neither is asserted.
                inconclusive.append(n)
            elif conflict:
                # Ordering in this file is not trustworthy, so an
                # ordering-based accusation is not either. Record it and let
                # the conflict be the headline.
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
        # NOT "not an alteration". The old wording volunteered the innocent
        # explanation for evidence we cannot explain, which is worse than
        # silence: a person who reads "nothing was edited" stops looking.
        # What we know is what is said.
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
    # OUT OF ORDER STILL FAILS. The chain is not linear, and a verifier that
    # returned ok for that would be excusing the one shape a reordering attack
    # produces. What changes is the WORDING, not the verdict: it names what is
    # true (the order is wrong) instead of what is not (an entry was removed).
    # INCONCLUSIVE IS NOT A PASS. An entry linking to a hash that exists only
    # inside an unreadable line is exactly what a torn write looks like and
    # exactly what deleting an entry and re-typing its hash looks like. If
    # that returned ok, the attacker would have bought silence by writing one
    # extra token - the vulnerability would have moved, not closed. "We could
    # not tell" is not "we looked and it was fine", here as everywhere else in
    # this codebase.
    #
    # A chain conflict is the same shape: it means ordering in this file is
    # not trustworthy, so the ordering verdict cannot be trusted either.
    return VerifyResult(ok=not (out_of_order or inconclusive or conflict),
                        entries=len(rows), head=prev,
                        decisions=decisions, damaged_lines=damaged,
                        segments=segments, out_of_order=out_of_order,
                        inconclusive=inconclusive, chain_conflict=conflict,
                        ledger=path, detail=" ".join(notes) or None)


# writes and verifies) plus the shareable proof-card builder. They reuse the
# same _canon / hashing already defined above, so nothing else changes.


@dataclass
class CrossLinkResult:
    """How the two chains vouch for each other."""
    verified: int = 0            # peer_head values that resolve to a real entry
    unresolved: List[str] = field(default_factory=list)
    checked: bool = False        # False when there is no second chain to check
    # Entries appended after the LAST peer write. peer_head records the peer's
    # head at write time, so nothing written afterwards is referenced by
    # anything - they are inside the ledger but outside the cross-check.
    unanchored: int = 0

    @property
    def ok(self) -> bool:
        # NOT A PASS WHEN NOTHING WAS CHECKED. The docstring one line above
        # distinguishes "we did not look" from "we looked and it was fine",
        # and `ok` collapsed them - so a caller writing `if links.ok` got a
        # clean answer for a check that never ran. cli.py happens to guard
        # with `if links else True`; the next caller would not have.
        return self.checked and not self.unresolved


def verify_cross_links(main_path: str, fs_path: str) -> CrossLinkResult:
    """Check that every peer_head names a hash that exists in the other chain.

    An unresolved link is REAL evidence, and it is the thing a single chain
    could never show: entries were removed from the end of a log. Truncate the
    main chain and its own hashes still verify perfectly - a valid, shorter
    history. But the fs chain still carries peer_head values pointing at the
    receipts that were cut, and those no longer resolve.

    Reads only; never raises. A missing file means there is nothing to check,
    which is reported as checked=False rather than as a pass - "we did not
    look" and "we looked and it was fine" are different answers.
    """
    res = CrossLinkResult()
    if not (os.path.exists(main_path) and os.path.exists(fs_path)):
        # COUNT THE UNANCHORED ENTRIES EVEN HERE - especially here. With one
        # chain there is nothing to anchor against, so EVERY entry is outside
        # the cross-check. That is the Linux shape, and returning 0 would be
        # the same misleading silence this count exists to remove.
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

    # HOW MUCH OF THE LEDGER THIS ACTUALLY COVERS.
    #
    # peer_head anchors BACKWARDS: it records the peer's head as it was when
    # the receipt was written. Everything appended after the last peer write
    # is therefore referenced by nothing, and truncating back to that point
    # leaves both chains verifying cleanly - no damage, no junk line, no
    # oversized receipt. Reproduced 2026-09-09.
    #
    # On Linux, and on Windows whenever the filesystem guard is idle, that
    # unreferenced region is the entire recent tail: exactly the receipts
    # worth removing.
    #
    # Closing it needs periodic anchoring, which is a feature with its own
    # failure modes and does not belong in a robustness pass. What belongs
    # here is not letting the reader infer coverage that does not exist - so
    # the count is reported, and the README and share_card say the same thing.
    res.unanchored = _unanchored_after_last_peer_write(main_path, fs_path)
    return res


def _unanchored_after_last_peer_write(main_path: str, fs_path: str) -> int:
    """Entries in either chain written after the last receipt in the other."""
    def stamps(path: str) -> List[str]:
        out: List[str] = []
        try:
            with open(path, **_READ) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ts = json.loads(line).get("timestamp")
                    except Exception:
                        continue
                    if ts:
                        out.append(ts)
        except OSError:
            pass
        return out

    a, b = stamps(main_path), stamps(fs_path)
    if not a or not b:
        # One chain only: nothing anchors anything, so every entry is
        # unanchored. That is the Linux shape, and saying so is the point.
        return len(a) + len(b)
    return (sum(1 for t in a if t > max(b)) +
            sum(1 for t in b if t > max(a)))


def load_receipts(path: str) -> List[dict]:
    """Return every receipt in the log, oldest first. Read-only."""
    rows: List[dict] = []
    if not os.path.exists(path):
        return rows
    with open(path, **_READ) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def load_all_receipts(path: str) -> List[dict]:
    """Return every receipt from both chains (main and fs), oldest first.

    SPLIT ON WRITE, MERGED ON READ. The two files exist so that each is
    written from only one side of the WinFsp mount; nothing that reads them
    needs to know, so list, share, status and report see a single chronological
    stream.
    """
    base = _base_path(path)
    main_rows = load_receipts(base)
    fs_p = chain_path(base, CHAIN_FS)
    fs_rows = load_receipts(fs_p) if os.path.exists(fs_p) else []
    merged = main_rows + fs_rows
    return sorted(merged, key=lambda r: str(r.get("timestamp") or ""))


def find_receipt(path: str, receipt_id: Optional[str] = None) -> Optional[dict]:
    """Pick a receipt: by (full or prefix) id if given, else the most recent.

    Matching by prefix mirrors how `log`/`undo` show short ids, so a user can
    paste the 8-char id they see rather than the full uuid. Searches across
    both main and filesystem receipt chains.
    """
    rows = load_all_receipts(path)
    if not rows:
        return None
    if not receipt_id:
        return rows[-1]
    rid = receipt_id.strip()
    # exact first, then unique prefix
    for r in rows:
        if r.get("receipt_id") == rid:
            return r
    matches = [r for r in rows if str(r.get("receipt_id", "")).startswith(rid)]
    # AMBIGUOUS MEANS AMBIGUOUS. The docstring said "unique prefix" and the
    # code returned matches[-1] - the newest of however many matched - with no
    # warning. With 60 receipts a one-character prefix matched nine and
    # silently picked one (2026-09-09). `undo` and `receipt --share` both take
    # an id from here, so guessing means restoring or publishing a receipt the
    # user did not ask for. recovery.find() already refuses on an ambiguous
    # prefix; this is the same rule applied to the other ledger.
    return matches[0] if len(matches) == 1 else None


def _fence_safe(text: str) -> str:
    r"""Neutralise anything that would end the code fence a proof card puts
    this text inside.

    share_card is the one artefact handed to a STRANGER - it is pasted into a
    PR or an issue, and it invites the reader to verify the chain themselves.
    A command containing ``` closed the fence early, so the rest of the
    command rendered as prose in somebody else's document, and redact() does
    not strip backticks or newlines (2026-09-09).

    Not a security boundary on its own - the card is not a trust anchor - but
    the tool should not be the thing that injects attacker-influenced markup
    into a third party's page.
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
        # WHAT THE CARD MAY CLAIM, AND WHAT IT MAY NOT.
        #
        # This is the one artefact handed to a stranger, and it invites them
        # to check. So it must not overstate: the chain detects an EDIT to any
        # entry it holds, and it does not by itself detect a rewrite of the
        # whole file - only a head hash recorded somewhere else does that.
        # Until 2026-09-09 the card said "tamper-evident" flatly while
        # verify could be made to report a modified ledger clean, and the
        # person least able to know better was the one being told.
        "  hash-chained: an edit to any entry below breaks the chain.",
        "  a head recorded elsewhere is what detects a whole-file rewrite.",
        "  verify the chain yourself:",
        f"    pipx install git+https://{repo}.git@{release_tag()} && demo_cli verify",
        "```",
    ]
    return "\n".join(lines)
