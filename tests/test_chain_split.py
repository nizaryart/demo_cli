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
                               verify_chain, verify_cross_links)


def _r(action="x", chain=CHAIN_MAIN, **kw):
    return Receipt(action_raw=action, action_type="shell",
                   target_environment="dev", decision="ALLOW",
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
    assert "torn write" in v.detail
    # STILL ONE SEGMENT, and that is the writer working as intended: last_hash
    # skips unreadable lines, so the next append links to the last READABLE
    # hash rather than to the wreckage. The chain closes over the damage
    # instead of being severed by it.
    assert v.segments == 1


def test_a_torn_line_that_severs_the_chain_is_reported_as_a_segment(tmp_path):
    """When the damage does break the link - the torn line ate a receipt whose
    hash the next entry had already chained onto - verification resumes as a
    new segment rather than declaring tampering. The entries are unverifiable
    against their predecessor, which is not the same as inconsistent with it."""
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
    assert v.ok
    assert v.damaged_lines == [2]
    assert v.segments == 2


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
    assert links.ok          # nothing unresolved, but nothing verified either
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
