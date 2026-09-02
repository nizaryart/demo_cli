"""The receipt ledger: an append-only, hash-chained, tamper-evident record of
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
_LOCK_TIMEOUT_SECONDS = float(os.environ.get("DEMO_CLI_LOCK_TIMEOUT", "10"))
_LOCK_POLL_INTERVAL = 0.05


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
    last = GENESIS
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["receipt_hash"]
                    except Exception:
                        pass
    return last


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
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            start = max(0, f.tell() - max_bytes)
            f.seek(start)
            chunk = f.read()
    except OSError:
        return GENESIS
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    if start > 0:
        lines = lines[1:]                # partial line from the mid-file seek
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)["receipt_hash"]
        except Exception:
            continue                     # torn line: keep walking backwards
    return GENESIS


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
        with open(path, "a", encoding="utf-8") as f:
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
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append((n, json.loads(line)))
            except Exception:
                damaged.append(n)
                salvaged.update(_HASH_TOKEN.findall(line))

    # A torn line takes its hash with it, so the NEXT readable entry has no
    # predecessor to link to. That entry starts a new segment: unverifiable
    # against what came before, which is not the same as inconsistent with it.
    #
    # `after_damage` is true only for the first readable entry following a
    # damaged one. Everywhere else a broken link still fails hard - otherwise
    # one torn line would excuse every reordering after it, and an attacker
    # who can corrupt a line could hide anything that follows.
    # Every hash this file contains, readable or salvaged. A link naming one
    # of these points at an entry that IS here - so nothing was removed, the
    # entries are merely not in chain order.
    present = {r.get("receipt_hash") for _, r in rows} | salvaged
    damaged_set = set(damaged)
    prev = GENESIS
    prev_line = 0
    segments = 1
    out_of_order: List[int] = []
    for n, r in rows:
        after_damage = any(d in damaged_set for d in range(prev_line + 1, n))
        stored = r.get("receipt_hash", "")
        body = {k: v for k, v in r.items() if k != "receipt_hash"}
        recomputed = hashlib.sha256(
            (_canon(body) + r.get("prev_receipt_hash", "")).encode()).hexdigest()
        # SELF-CONSISTENCY IS CHECKED FIRST, and is never excused. It needs no
        # predecessor, so neither damage nor disorder can cover an edited field.
        if recomputed != stored:
            return VerifyResult(ok=False, broken_at=n, damaged_lines=damaged,
                                out_of_order=out_of_order, ledger=path,
                                detail="A field in this entry was edited after it was written.")
        link = r.get("prev_receipt_hash")
        if link != prev:
            if after_damage:
                segments += 1
            elif link in present:
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
            else:
                return VerifyResult(ok=False, broken_at=n, damaged_lines=damaged,
                                    out_of_order=out_of_order, ledger=path,
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
        notes.append(f"{len(damaged)} malformed line(s) - a torn write, not an "
                     f"alteration. Every readable entry verified.")
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
    return VerifyResult(ok=not out_of_order, entries=len(rows), head=prev,
                        decisions=decisions, damaged_lines=damaged,
                        segments=segments, out_of_order=out_of_order,
                        ledger=path, detail=" ".join(notes) or None)


# writes and verifies) plus the shareable proof-card builder. They reuse the
# same _canon / hashing already defined above, so nothing else changes.


@dataclass
class CrossLinkResult:
    """How the two chains vouch for each other."""
    verified: int = 0            # peer_head values that resolve to a real entry
    unresolved: List[str] = field(default_factory=list)
    checked: bool = False        # False when there is no second chain to check

    @property
    def ok(self) -> bool:
        return not self.unresolved


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
        return res
    res.checked = True

    def hashes(p):
        out = set()
        try:
            with open(p, encoding="utf-8") as f:
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
            with open(path, encoding="utf-8") as f:
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
    return res


def load_receipts(path: str) -> List[dict]:
    """Return every receipt in the log, oldest first. Read-only."""
    rows: List[dict] = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def find_receipt(path: str, receipt_id: Optional[str] = None) -> Optional[dict]:
    """Pick a receipt: by (full or prefix) id if given, else the most recent.

    Matching by prefix mirrors how `log`/`undo` show short ids, so a user can
    paste the 8-char id they see rather than the full uuid.
    """
    rows = load_receipts(path)
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
    return matches[-1] if matches else None


def share_card(receipt: dict, *, repo: str = "github.com/WePwn/demo_cli") -> str:
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
    action = receipt.get("action_raw", "")
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
        "  tamper-evident: this receipt links to the one before it.",
        "  verify the chain yourself:",
        f"    pipx install git+https://{repo}.git@{release_tag()} && demo_cli verify",
        "```",
    ]
    return "\n".join(lines)
