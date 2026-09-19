"""One writer per file, and the two files vouch for each other.

WHY THE SPLIT EXISTS
On Windows a protected project's receipt log is reachable by two paths: through
the WinFsp mount (hook, egress) and directly in the backing (the mount process
itself). Byte-range locks do not compose across WinFsp - a lock taken through
the mount is not the same lock as one taken on NTFS - so both sides held "the"
lock at once and appended at stale offsets. On 2026-09-02 the labubu project's
log contained records cut mid-key with the next record written over the
remains, and `verify` reported TAMPERED at line 349. Nothing had tampered with
anything; the guard had corrupted its own audit trail.

The fix is not better locking, it is removing the need for locking to work
across the boundary: each chain is written from exactly one side. Split on
write, merged on every read.

WHY THE CROSS-LINKS EXIST
The split cost the property a single chain had: nothing tied a hook receipt to
the filesystem capture that followed it. Each receipt now records the other
chain's head, which makes order provable and - more importantly - makes each
file a witness against truncation of the other.
"""
import json
import os

import pytest

from demo_cli.receipts import (CHAIN_FS, CHAIN_MAIN, GENESIS, Receipt,
                               append_receipt, chain_path, peer_path,
                               verify_chain, verify_cross_links,
                               load_all_receipts, find_receipt)


def _r(action="x", chain=CHAIN_MAIN, decision="ALLOW", **kw):
    return Receipt(action_raw=action, action_type="shell",
                   target_environment="dev", decision=decision,
                   reason="test", mode="enforce", chain=chain, **kw)


# --------------------------------------------------------------------------
# Routing: a receipt lands in the file its role names.
# --------------------------------------------------------------------------

def test_the_two_chains_are_separate_files(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    assert chain_path(main, CHAIN_MAIN) == main
    assert chain_path(main, CHAIN_FS) == str(tmp_path / "receipts-fs.jsonl")
    assert peer_path(main, CHAIN_FS) == main
    assert peer_path(main, CHAIN_MAIN) == str(tmp_path / "receipts-fs.jsonl")


def test_a_writer_cannot_land_in_the_wrong_chain_by_passing_the_wrong_path(tmp_path):
    """Callers pass cfg.receipts_path and set `chain`; routing is derived from
    the receipt's role, so no call site has to remember to build a path."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("hook command", chain=CHAIN_MAIN))
    append_receipt(main, _r("[fs] delete a.txt", chain=CHAIN_FS))

    assert "hook command" in open(main).read()
    assert "[fs] delete" not in open(main).read()
    fs = str(tmp_path / "receipts-fs.jsonl")
    assert "[fs] delete" in open(fs).read()


def test_each_chain_verifies_independently(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    for i in range(3):
        append_receipt(main, _r(f"cmd {i}", chain=CHAIN_MAIN))
        append_receipt(main, _r(f"[fs] delete {i}", chain=CHAIN_FS))
    assert verify_chain(main).ok
    assert verify_chain(chain_path(main, CHAIN_FS)).ok
    assert verify_chain(main).entries == 3


# --------------------------------------------------------------------------
# Damage is not tampering. The verifier used to claim it was.
# --------------------------------------------------------------------------

def test_a_torn_line_is_damage_not_tampering(tmp_path):
    """The exact shape found on labubu: a record cut mid-key. It is a write
    that did not finish. Reporting "the log was altered" asserts something the
    evidence does not support - the same unearned certainty as an unearned
    REVERSIBLE."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    with open(main, "a") as f:
        f.write('nup with FspCleanupDelete.","receipt_hash":"b9f8"}\n')
    append_receipt(main, _r("third"))

    v = verify_chain(main)
    assert v.ok, "a torn write must not be reported as tampering"
    assert v.damaged
    assert v.damaged_lines == [2]
    # The detail no longer says "a torn write, not an alteration". It could
    # not know that: the same bytes are produced by an interrupted append and
    # by someone replacing a record. It now reports what is observable - the
    # line could not be read - and volunteers no explanation for it.
    assert "could not be read" in v.detail
    assert "not an alteration" not in v.detail
    # STILL ONE SEGMENT, and that is the writer working as intended: last_hash
    # skips unreadable lines, so the next append links to the last READABLE
    # hash rather than to the wreckage. The chain closes over the damage
    # instead of being severed by it.
    assert v.segments == 1


def test_replacing_a_record_with_garbage_is_not_forgiven(tmp_path):
    """THIS TEST PREVIOUSLY ASSERTED THE VULNERABILITY, and is kept, inverted,
    as the record of it.

    It used to be called ...is_reported_as_a_segment and assert v.ok, on the
    theory that "the torn line ate a receipt whose hash the next entry had
    already chained onto" is an accident to be forgiven. Two things were wrong
    with that.

    First, the scenario is not reachable by accident. last_hash SKIPS
    unparseable lines, so a receipt appended after a tear links to the last
    READABLE entry - the chain closes over the damage (the test above pins
    exactly that). For a link to point INTO a torn line, the line must have
    been intact when the link was written and unreadable afterwards, which
    without editing requires two writers interleaving across lock domains -
    the labubu shape, which the chain split exists to prevent.

    Second, the construction here IS the attack. Rewriting the file to replace
    a record with garbage is what deleting an entry looks like, and a removal
    is contiguous by construction, so one junk line covers it exactly. Five
    receipts with entries 3 and 4 replaced by one bad line returned ok=True
    and printed "a torn write, not an alteration - nothing was edited" over a
    deliberate removal (2026-09-09).

    So the forgiving branch was deleted, not narrowed. What the suite had been
    calling correct behaviour was the hole.
    """
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    append_receipt(main, _r("second"))
    append_receipt(main, _r("third"))
    rows = open(main).read().splitlines()
    with open(main, "w") as f:              # destroy the middle record's text
        f.write(rows[0] + "\n")
        f.write("}}garbage{{\n")
        f.write(rows[2] + "\n")

    v = verify_chain(main)
    assert not v.ok, "a replaced record must not be waved through as damage"
    assert v.damaged_lines == [2]
    assert v.detail and "not an alteration" not in v.detail


def test_planting_the_victims_hash_in_the_junk_does_not_buy_a_pass(tmp_path):
    """The obvious follow-up move, and why `readable` and `salvaged` are two
    sets rather than one.

    Salvaged hashes are 64-hex tokens scraped off lines that would not parse.
    Merged into `present`, a link resolved against a token the attacker typed
    into their own junk line, and the report said "every referenced receipt is
    present, so nothing was removed". Now it resolves to INCONCLUSIVE, which
    is not a pass - otherwise the hole would have moved rather than closed.
    """
    main = str(tmp_path / "receipts.jsonl")
    for i in range(4):
        append_receipt(main, _r(f"entry {i}"))
    rows = open(main).read().splitlines()
    victim = json.loads(rows[2])["receipt_hash"]
    with open(main, "w") as f:
        f.write(rows[0] + "\n")
        f.write(rows[1] + "\n")
        f.write("}}garbage{{ " + victim + "\n")     # the deleted entry's hash
        f.write(rows[3] + "\n")

    v = verify_chain(main)
    assert not v.ok
    assert v.inconclusive, "the planted hash was treated as proof of presence"
    assert "not decidable" in (v.detail or "").lower()


def test_a_row_in_the_wrong_chain_is_reported(tmp_path):
    """ONE WRITER PER FILE is what makes deleting the forgiving branch safe,
    and nothing checked it. It has been violated once - the guard writing to
    the wrong ledger, 2026-09-02 - and if it recurs the labubu shape returns
    as a flat TAMPERED verdict against an honest project. Reported as its own
    state so the residual risk is a diagnosis rather than an accusation."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))

    # A GENUINE fs receipt, not a hand-edited one. `chain` sits inside the
    # hashed body, so editing the field breaks receipt_hash and is caught as
    # tampering long before this check - correctly. The violation this guards
    # against is a real fs-chain receipt landing in the main file, which is
    # what the guard did on 2026-09-02: valid hash, wrong ledger.
    fs_receipt = _r("written by the filesystem guard")
    fs_receipt.chain = "fs"
    append_receipt(main, fs_receipt)               # routes itself to -fs
    stray = open(chain_path(main, "fs")).read().splitlines()[0]
    with open(main, "a") as f:
        f.write(stray + "\n")                      # ...but lands here

    v = verify_chain(main)
    assert v.chain_conflict, "two writers in one ledger went unreported"
    assert not v.ok
    assert "two writers" in (v.detail or "")


def test_a_legacy_receipt_without_a_chain_field_is_not_a_conflict(tmp_path):
    """Receipts written before the split carry no `chain`. Absent is fine;
    only a DISAGREEING value is a conflict."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    rows = [json.loads(l) for l in open(main)]
    rows[0].pop("chain", None)
    with open(main, "w") as f:
        f.write(json.dumps(rows[0]) + "\n")

    assert verify_chain(main).chain_conflict == []


def test_an_edited_field_is_still_tampering(tmp_path):
    """The forgiving path must not become a hole."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    append_receipt(main, _r("second"))
    rows = [json.loads(l) for l in open(main)]
    rows[1]["action_raw"] = "something else"
    with open(main, "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")

    v = verify_chain(main)
    assert not v.ok
    assert "edited" in v.detail


def test_damage_cannot_be_used_as_cover_for_tampering(tmp_path):
    """A torn line excuses ONE missing link - the one whose predecessor is
    unreadable. It must not excuse an edit, nor every reordering after it, or
    an attacker who can corrupt a line could hide anything that follows."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    append_receipt(main, _r("second"))
    append_receipt(main, _r("third"))
    rows = [json.loads(l) for l in open(main)]
    rows[2]["reason"] = "rewritten"          # edit AFTER the damage
    with open(main, "w") as f:
        f.write(json.dumps(rows[0], sort_keys=True, separators=(",", ":")) + "\n")
        f.write("torn{\n")
        f.write(json.dumps(rows[2], sort_keys=True, separators=(",", ":")) + "\n")

    v = verify_chain(main)
    assert not v.ok, "an edited entry after a torn line is still tampering"


def test_interleaved_writers_are_out_of_order_not_removal(tmp_path):
    """THE SHAPE THE LOCK BUG ACTUALLY PRODUCES, from labubu line 348.

        347  claude-code  prev=6855f5d0  hash=3b076749
        348  egress       prev=b9f88269  hash=c7184adc   <- not 347's hash
        349  UNPARSEABLE (1 char)

    Line 348 linked to an fsguard receipt that was real and present, just
    stored further along and torn. Two writers appending at stale offsets
    leave entries out of FILE order while the chain itself is complete.

    "An entry was inserted, removed, or reordered" was wrong here in the way
    that matters: nothing was removed, and the receipt it named was still in
    the log. The verdict stays a failure - the chain is not linear - but it
    must not accuse.
    """
    main = str(tmp_path / "receipts.jsonl")
    a = append_receipt(main, _r("first"))
    b = append_receipt(main, _r("second"))
    c = append_receipt(main, _r("third"))
    rows = open(main).read().splitlines()
    with open(main, "w") as f:                    # swap the last two
        f.write(rows[0] + "\n" + rows[2] + "\n" + rows[1] + "\n")

    v = verify_chain(main)
    assert not v.ok, "a non-linear chain is still a failure"
    assert v.reordered
    assert v.broken_at is None, "not a hard break - do not report a location as tampering"
    assert "nothing was removed" in v.detail or "removed" in v.detail


def test_a_link_to_a_torn_receipt_is_not_called_a_removal(tmp_path):
    """A torn line keeps its hash as readable text. An entry linking to it is
    pointing at something that IS in the file, so calling it a removal
    contradicts the evidence."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    second = append_receipt(main, _r("second"))
    append_receipt(main, _r("third"))
    rows = open(main).read().splitlines()
    with open(main, "w") as f:
        f.write(rows[0] + "\n")
        # second survives only as wreckage, but its hash is still legible
        f.write('garbage"receipt_hash":"%s"}\n' % second.receipt_hash)
        f.write(rows[2] + "\n")

    v = verify_chain(main)
    assert v.damaged
    assert "missing" not in (v.detail or "")


def test_a_genuinely_missing_entry_is_still_reported_as_missing(tmp_path):
    """The forgiving paths must not swallow a real removal: when the
    referenced hash is nowhere in the file, an entry is gone."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("first"))
    append_receipt(main, _r("second"))
    append_receipt(main, _r("third"))
    rows = open(main).read().splitlines()
    with open(main, "w") as f:
        f.write(rows[0] + "\n" + rows[2] + "\n")   # second deleted outright

    v = verify_chain(main)
    assert not v.ok
    assert "missing" in v.detail


def test_the_ledger_path_is_reported(tmp_path):
    """Run from the wrong directory, verify checked a different project's log
    and said VERIFIED. Naming the file it read is what makes that visible."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("x"))
    assert verify_chain(main).ledger == main


def test_removing_entries_is_still_caught_without_damage(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    for i in range(4):
        append_receipt(main, _r(f"cmd {i}"))
    rows = open(main).read().splitlines()
    with open(main, "w") as f:
        f.write("\n".join(rows[:1] + rows[2:]) + "\n")     # drop the second
    v = verify_chain(main)
    assert not v.ok
    # "missing", not "removed, inserted, or reordered" - the dropped receipt's
    # hash is nowhere in the file, which is the one thing that IS established.
    assert "missing" in v.detail


# --------------------------------------------------------------------------
# Cross-chain anchoring.
# --------------------------------------------------------------------------

def test_a_receipt_records_the_other_chains_head(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    k = append_receipt(main, _r("hook allows the delete", chain=CHAIN_MAIN))
    f = append_receipt(main, _r("[fs] delete notes.txt", chain=CHAIN_FS))
    assert f.peer_head == k.receipt_hash, (
        "the fs receipt must name the hook receipt that preceded it")


def test_the_first_receipt_has_no_peer_to_anchor_to(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    first = append_receipt(main, _r("very first"))
    assert first.peer_head is None


def test_peer_head_is_covered_by_the_receipts_own_hash(tmp_path):
    """It sits inside the hashed body, so it cannot be edited without breaking
    the entry that carries it. That is what makes the link trustworthy."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("k", chain=CHAIN_MAIN))
    append_receipt(main, _r("f", chain=CHAIN_FS))
    fs = chain_path(main, CHAIN_FS)
    row = json.loads(open(fs).read().strip())
    row["peer_head"] = "0" * 64
    with open(fs, "w") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    assert not verify_chain(fs).ok


def test_cross_links_resolve_on_an_untouched_pair(tmp_path):
    main = str(tmp_path / "receipts.jsonl")
    for i in range(3):
        append_receipt(main, _r(f"cmd {i}", chain=CHAIN_MAIN))
        append_receipt(main, _r(f"[fs] delete {i}", chain=CHAIN_FS))
    links = verify_cross_links(main, chain_path(main, CHAIN_FS))
    assert links.checked and links.ok and links.verified > 0


def test_truncating_one_chain_is_caught_by_the_other(tmp_path):
    """THE ATTACK A LONE HASH CHAIN MISSES ENTIRELY. Lop entries off the end of
    a single chain and what remains verifies perfectly - a valid, shorter
    history. The peer's references to the removed entries are what expose it."""
    main = str(tmp_path / "receipts.jsonl")
    for i in range(3):
        append_receipt(main, _r(f"cmd {i}", chain=CHAIN_MAIN))
        append_receipt(main, _r(f"[fs] delete {i}", chain=CHAIN_FS))

    rows = open(main).read().splitlines()
    with open(main, "w") as f:
        f.write("\n".join(rows[:-1]) + "\n")          # drop the last entry

    assert verify_chain(main).ok, "the truncated chain still self-verifies"
    links = verify_cross_links(main, chain_path(main, CHAIN_FS))
    assert not links.ok, "the fs chain still points at the removed receipt"


def test_no_second_chain_means_not_checked_rather_than_passed(tmp_path):
    """"We did not look" and "we looked and it was fine" are different
    answers, and only one of them is evidence."""
    main = str(tmp_path / "receipts.jsonl")
    append_receipt(main, _r("only chain"))
    links = verify_cross_links(main, chain_path(main, CHAIN_FS))
    assert not links.checked
    # THIS TEST ASSERTED THE OPPOSITE OF ITS OWN NAME. It was called
    # ..._means_not_checked_rather_than_passed and then asserted links.ok -
    # i.e. that an unperformed check passes. The docstring on CrossLinkResult
    # already said the two must differ; `ok` collapsed them anyway, and the
    # test pinned the collapse (2026-09-09).
    assert not links.ok, "an unperformed check is not a pass"
    # And with one chain, nothing anchors anything: every entry sits outside
    # the cross-check. Saying so is the whole point of the count.
    assert links.unanchored == 1
    assert links.verified == 0


def test_the_peer_head_cache_never_serves_a_stale_head(tmp_path):
    """CAUGHT BY test_truncating_one_chain_is_caught_by_the_other.

    The cache was first keyed on a 1-second clock. During a fast burst every
    receipt then anchored to the same older head, so the NEWEST peer entries
    were referenced by nothing - and truncating exactly those, the easiest and
    most useful entries to remove, went undetected. The guarantee was quietly
    weakest precisely where it mattered most.

    Keying on (size, mtime) instead costs one stat and is always current.
    """
    main = str(tmp_path / "receipts.jsonl")
    k1 = append_receipt(main, _r("k1", chain=CHAIN_MAIN))
    f1 = append_receipt(main, _r("[fs] a", chain=CHAIN_FS))
    k2 = append_receipt(main, _r("k2", chain=CHAIN_MAIN))
    f2 = append_receipt(main, _r("[fs] b", chain=CHAIN_FS))
    assert f1.peer_head == k1.receipt_hash
    assert f2.peer_head == k2.receipt_hash, (
        "the second fs receipt must anchor to the newest main entry, not a "
        "cached older one")


# --------------------------------------------------------------------------
# Backward compatibility: no migration, ever.
# --------------------------------------------------------------------------

def test_receipts_written_before_the_split_still_verify(tmp_path):
    """The 388 entries already on labubu have no `chain` and no `peer_head`.
    verify_chain recomputes from whatever keys a row actually carries, so they
    must keep verifying untouched. Rewriting an audit log so that it verifies
    is precisely the wrong instinct."""
    import hashlib
    main = str(tmp_path / "receipts.jsonl")
    body = {"action_raw": "old style", "decision": "ALLOW",
            "prev_receipt_hash": GENESIS, "timestamp": "2026-08-01T00:00:00Z"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["receipt_hash"] = hashlib.sha256((canon + GENESIS).encode()).hexdigest()
    with open(main, "w") as f:
        f.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")

    v = verify_chain(main)
    assert v.ok and v.entries == 1


def test_a_new_receipt_chains_onto_a_pre_split_log(tmp_path):
    import hashlib
    main = str(tmp_path / "receipts.jsonl")
    body = {"action_raw": "old", "prev_receipt_hash": GENESIS}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["receipt_hash"] = hashlib.sha256((canon + GENESIS).encode()).hexdigest()
    with open(main, "w") as f:
        f.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")

    append_receipt(main, _r("new style"))
    assert verify_chain(main).ok


# --------------------------------------------------------------------------
# An empty ledger is neither a pass nor a failure.
#
# `demo_cli verify` on a project set up sixty seconds earlier reported
# TAMPERED, because a missing file returned ok=False and the renderer had only
# two states to put it in (dari, 2026-09-02). That is the worst-timed false
# alarm the tool can raise: it fires exactly when someone is checking whether
# the thing works, and it accuses the tool of the one failure it exists to
# detect.
# --------------------------------------------------------------------------

def test_a_missing_log_is_not_tampering(tmp_path):
    v = verify_chain(str(tmp_path / "never-written.jsonl"))
    assert v.absent
    assert v.ok, "there is nothing to have altered"
    assert v.entries == 0
    assert "No receipts" in v.detail


def test_an_empty_ledger_offers_no_head_to_anchor(tmp_path):
    """GENESIS is not a chain head. Printing it under 'record these outside
    this machine' would invite someone to write down a value attesting to
    nothing."""
    from demo_cli import cli
    proj = tmp_path / "proj"
    (proj / ".demo_cli").mkdir(parents=True)
    (proj / ".demo_cli.toml").write_text('mode = "enforce"\n')

    class A:
        root, no_color = str(proj), True
    assert cli.cmd_verify(A()) == 0, "a fresh project must not fail verify"


def test_a_log_that_exists_but_is_empty_is_not_absent(tmp_path):
    """An existing file with no entries is a real, verified-empty chain -
    distinct from never having written one."""
    p = tmp_path / "receipts.jsonl"
    p.write_text("")
    v = verify_chain(str(p))
    assert not v.absent
    assert v.ok and v.entries == 0


# --------------------------------------------------------------------------
# The merged recovery index. Found by review 2026-09-07; the coverage hole is
# the finding, not the typo.
#
# `load_entries` merges index.jsonl and index-fs.jsonl and its docstring says
# the result is chronological. It sorted on "timestamp", a key recovery
# entries have never had - they use "ts" - so every sort key was "" and the
# stable sort preserved concatenation order: all main entries, then all fs
# entries. latest() takes entries[-1], so `demo_cli undo` with no id restored
# the newest FS point regardless of how much newer a main point was.
#
# NOT ONE TEST IN 826 WROTE BOTH INDEX FILES. On Linux, and on Windows before
# a mount, index-fs.jsonl is empty, append order is already chronological, and
# the merge is correct by accident. The split's whole reason for existing had
# no read-path coverage.
# --------------------------------------------------------------------------

def _entry(rec_dir, idx_name, rid, ts):
    import json, os
    os.makedirs(rec_dir, exist_ok=True)
    with open(os.path.join(rec_dir, idx_name), "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": rid, "ts": ts, "target": "/x",
                            "recovery_point": f"/rp/{rid}", "kind": "file"}) + "\n")


def test_a_merged_index_is_ordered_by_time_not_by_file(tmp_path):
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    # Interleaved in time, deliberately written so that file order and time
    # order disagree: the fs entries are OLDER than the main one.
    _entry(d, "index-fs.jsonl", "fs-old", "20260101-090000")
    _entry(d, "index-fs.jsonl", "fs-mid", "20260101-100000")
    _entry(d, "index.jsonl",    "main-new", "20260101-110000")

    ids = [e["id"] for e in recovery.load_entries(d)]
    assert ids == ["fs-old", "fs-mid", "main-new"], \
        "merged order follows the files, not the clock"


def test_latest_returns_the_newest_point_across_both_chains(tmp_path):
    """The failure this actually caused. `demo_cli undo` with no id calls
    latest(), and latest() takes entries[-1]."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _entry(d, "index-fs.jsonl", "fs-old",   "20260101-090000")
    _entry(d, "index.jsonl",    "main-new", "20260101-110000")
    assert recovery.latest(d)["id"] == "main-new", \
        "undo would restore the older fs point and report RESTORED"


def test_the_newest_point_can_also_be_the_fs_one(tmp_path):
    """The mirror case, so the fix is not just 'prefer main'."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _entry(d, "index.jsonl",    "main-old", "20260101-090000")
    _entry(d, "index-fs.jsonl", "fs-new",   "20260101-110000")
    assert recovery.latest(d)["id"] == "fs-new"


def test_a_main_only_index_is_unaffected(tmp_path):
    """Why this was invisible: with no fs index, append order is already
    chronological and the broken sort preserved it."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _entry(d, "index.jsonl", "a", "20260101-090000")
    _entry(d, "index.jsonl", "b", "20260101-100000")
    assert [e["id"] for e in recovery.load_entries(d)] == ["a", "b"]
    assert recovery.latest(d)["id"] == "b"


def test_an_undated_entry_sorts_first_rather_than_crashing(tmp_path):
    """A torn or hand-edited entry must not take the whole listing down."""
    import json, os
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "index.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"id": "no-ts", "target": "/x"}) + "\n")
    _entry(d, "index.jsonl", "dated", "20260101-090000")
    assert [e["id"] for e in recovery.load_entries(d)] == ["no-ts", "dated"]


# --------------------------------------------------------------------------
# prune across the split. Found by review 2026-09-07, same coverage hole as
# the ordering bug: no test had ever written both index files.
#
# prune computed doomed entries from the MERGED view and deleted their
# artefacts - fs ones included - then rewrote index.jsonl only. Two failures:
#   * fs survivors written into the main index while still in their own, so
#     load_entries returned them twice
#   * doomed fs entries left listed with their bytes already deleted - the
#     ledger advertising a recovery that is gone, which is the one failure
#     this project treats as unacceptable
# and when index.jsonl did not exist at all, nothing was de-listed.
# --------------------------------------------------------------------------

def _point(rec_dir, idx_name, rid, ts):
    """An index entry whose recovery_point is a real file, so prune's delete
    is observable rather than a no-op."""
    import json, os
    os.makedirs(rec_dir, exist_ok=True)
    rp = os.path.join(rec_dir, rid + ".bak")
    with open(rp, "w", encoding="utf-8") as f:
        f.write(rid)
    with open(os.path.join(rec_dir, idx_name), "a", encoding="utf-8") as f:
        f.write(json.dumps({"id": rid, "ts": ts, "target": "/x",
                            "recovery_point": rp, "kind": "file"}) + "\n")
    return rp


def test_pruned_fs_entries_leave_the_ledger(tmp_path):
    """The headline failure: the artefact is deleted, so the entry must not
    still be offered."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    rp_old = _point(d, "index-fs.jsonl", "fs-old", "20260101-090000")
    _point(d, "index-fs.jsonl", "fs-new", "20260101-100000")

    recovery.prune(d, keep=1)

    assert not os.path.exists(rp_old), "prune should have deleted the artefact"
    ids = [e["id"] for e in recovery.load_entries(d)]
    assert ids == ["fs-new"], "a deleted recovery point is still being offered"


def test_prune_never_rewrites_the_guards_index(tmp_path):
    """The guard is the only writer of index-fs.jsonl. Truncating it from here
    crosses a lock boundary that does not compose, and can lose the file -
    worse than the stale entries it would fix."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _point(d, "index-fs.jsonl", "fs-old", "20260101-090000")
    _point(d, "index-fs.jsonl", "fs-new", "20260101-100000")
    before = open(os.path.join(d, "index-fs.jsonl"), encoding="utf-8").read()

    recovery.prune(d, keep=1)

    after = open(os.path.join(d, "index-fs.jsonl"), encoding="utf-8").read()
    assert after == before, "prune must not write the guard's file"


def test_fs_survivors_are_not_duplicated_into_the_main_index(tmp_path):
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _point(d, "index.jsonl",    "main-a", "20260101-090000")
    _point(d, "index-fs.jsonl", "fs-b",   "20260101-100000")
    _point(d, "index.jsonl",    "main-c", "20260101-110000")

    recovery.prune(d, keep=2)

    ids = [e["id"] for e in recovery.load_entries(d)]
    assert ids == ["fs-b", "main-c"]
    assert len(ids) == len(set(ids)), f"duplicate entries: {ids}"
    main = open(os.path.join(d, "index.jsonl"), encoding="utf-8").read()
    assert "fs-b" not in main, "an fs entry was written into the main index"


def test_pruning_works_with_no_main_index_at_all(tmp_path):
    """A freshly mounted Windows project, before any CLI-side snapshot. The
    old code checked os.path.exists(index.jsonl) and, finding none, de-listed
    nothing at all while still deleting every doomed artefact."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    rp_old = _point(d, "index-fs.jsonl", "fs-old", "20260101-090000")
    _point(d, "index-fs.jsonl", "fs-new", "20260101-100000")
    assert not os.path.exists(os.path.join(d, "index.jsonl"))

    recovery.prune(d, keep=1)

    assert not os.path.exists(rp_old)
    assert [e["id"] for e in recovery.load_entries(d)] == ["fs-new"]


def test_pruning_the_main_chain_still_rewrites_in_place(tmp_path):
    """The tombstone route is for the fs chain only. The main index has one
    writer on this side, so pruning it stays a rewrite - no tombstone file
    should appear for a main-only prune."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _point(d, "index.jsonl", "a", "20260101-090000")
    _point(d, "index.jsonl", "b", "20260101-100000")

    recovery.prune(d, keep=1)

    assert [e["id"] for e in recovery.load_entries(d)] == ["b"]
    main = open(os.path.join(d, "index.jsonl"), encoding="utf-8").read()
    assert '"id": "a"' not in main          # the id, not the letter
    assert not os.path.exists(os.path.join(d, "index-fs.pruned"))


def test_a_damaged_tombstone_file_does_not_hide_the_ledger(tmp_path):
    """Fail toward SHOWING a recovery point. An unreadable tombstone file must
    not silently remove entries whose artefacts are still on disk."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _point(d, "index-fs.jsonl", "fs-a", "20260101-090000")
    os.makedirs(os.path.join(d, "index-fs.pruned"))   # a directory, not a file
    assert [e["id"] for e in recovery.load_entries(d)] == ["fs-a"]


def test_find_and_latest_agree_with_the_filtered_view(tmp_path):
    """undo goes through both. Neither may resurrect a pruned entry."""
    from demo_cli import recovery
    d = str(tmp_path / "rec")
    _point(d, "index-fs.jsonl", "fs-old", "20260101-090000")
    _point(d, "index-fs.jsonl", "fs-new", "20260101-100000")

    recovery.prune(d, keep=1)

    assert recovery.latest(d)["id"] == "fs-new"
    assert recovery.find(d, "fs-old") is None


def test_load_all_receipts_merges_chronologically(tmp_path):
    """load_all_receipts merges both chains and sorts by timestamp."""
    main = str(tmp_path / "receipts.jsonl")
    r1 = append_receipt(main, _r("cmd1", chain=CHAIN_MAIN, timestamp="2026-09-01T10:00:00Z"))
    r2 = append_receipt(main, _r("[fs] delete 1", chain=CHAIN_FS, timestamp="2026-09-01T11:00:00Z"))
    r3 = append_receipt(main, _r("cmd2", chain=CHAIN_MAIN, timestamp="2026-09-01T12:00:00Z"))

    all_from_main = load_all_receipts(main)
    assert len(all_from_main) == 3
    assert [r["action_raw"] for r in all_from_main] == ["cmd1", "[fs] delete 1", "cmd2"]

    # Passing fs path also yields the exact same merged list
    fs = chain_path(main, CHAIN_FS)
    all_from_fs = load_all_receipts(fs)
    assert [r["action_raw"] for r in all_from_fs] == ["cmd1", "[fs] delete 1", "cmd2"]


def test_find_receipt_resolves_across_chains(tmp_path):
    """find_receipt can locate entries from either chain and find latest across both."""
    main = str(tmp_path / "receipts.jsonl")
    r1 = append_receipt(main, _r("cmd1", chain=CHAIN_MAIN, timestamp="2026-09-01T10:00:00Z"))
    r2 = append_receipt(main, _r("[fs] delete 1", chain=CHAIN_FS, timestamp="2026-09-01T11:00:00Z"))

    # By prefix from FS chain
    found_fs = find_receipt(main, r2.receipt_id[:8])
    assert found_fs is not None
    assert found_fs["action_raw"] == "[fs] delete 1"
    assert found_fs["chain"] == CHAIN_FS

    # Latest returns the newest entry across both
    latest = find_receipt(main)
    assert latest["receipt_id"] == r2.receipt_id


def test_cmd_status_and_report_cover_dual_chains(tmp_path, capsys):
    """cli.cmd_status and cmd_report report on both chains."""
    from demo_cli import cli
    from types import SimpleNamespace

    main = str(tmp_path / ".demo_cli" / "receipts.jsonl")
    os.makedirs(os.path.dirname(main), exist_ok=True)
    append_receipt(main, _r("cmd1", chain=CHAIN_MAIN, decision="ALLOW"))
    append_receipt(main, _r("[fs] delete 1", chain=CHAIN_FS, decision="REVERSIBLE",
                            recovery_point="/tmp/bak.1"))

    args = SimpleNamespace(root=str(tmp_path))

    # cmd_status
    ret = cli.cmd_status(args)
    assert ret == 0
    out = capsys.readouterr().out
    assert "receipts" in out
    # Both receipts accounted for
    assert "2" in out

    # cmd_report
    ret = cli.cmd_report(args)
    assert ret == 0
    out = capsys.readouterr().out
    assert "receipts" in out
    assert "ALLOW" in out
    assert "REVERSIBLE" in out

