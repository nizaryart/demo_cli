"""Recovery: resolve the real target of a command and snapshot / restore it.

The single most important property of this module is what it does *not* do: it
never falls back to a default target. If a destructive command's target cannot
be resolved to the thing it will actually affect, `resolve_target` returns
None, the orchestrator captures nothing, and the decision is escalated. That is
how the "snapshot something unrelated and call it recovered" failure is removed
by construction.

Supported target kinds: sqlite (.db file), postgres (connection URL),
file, dir.
"""
from __future__ import annotations

import datetime
import json
import math
import os
import re
import shlex
import glob as _glob
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .classify import (POSIX, POWERSHELL, effective_command, effective_segments,
                       join_continuations,
                       strip_ps_escapes,
                       redirect_target, split_segments,
                       substitute_assignments)
from .context import redact

_PG_URL = re.compile(r"\bpostgres(?:ql)?://\S+", re.I)
_DB_FILE = re.compile(r"[\w./\\-]+\.db\b")
# The single source of truth for "directories not worth guarding". Real work
# touches these constantly - one `git status` walks hundreds of files under
# .git - so snapshotting or receipting them buries the ledger in noise.
#
# Shared deliberately: syscall_guard (Linux) and fsguard (Windows) both filter
# on it, and copytree derives its exclusion list from it below. Three separate
# copies had already drifted apart before this was unified; adding an entry must
# fix every platform at once, not one of them.
IGNORED_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".demo_cli", ".demo_cli_recovery",
})

_IGNORE = shutil.ignore_patterns(*sorted(IGNORED_DIRS))

# Upper bound on what we will copy for a directory snapshot. A snapshot we
# cannot take quickly is not a recovery we should silently promise: above this
# the orchestrator escalates honestly instead of copying a multi-GB tree.
# Override with DEMO_CLI_MAX_SNAPSHOT_MB.
_DEFAULT_MAX_SNAPSHOT_MB = 256


@dataclass
class Target:
    kind: str   # sqlite | postgres | file | dir
    ref: str    # absolute path or connection URL
    label: str  # redacted, human-safe


def resolve_target(cmd: str, explicit_db: Optional[str] = None,
                   db_url: Optional[str] = None, target_path: Optional[str] = None) -> Optional[Target]:
    """Resolve the target a command will affect. No default fallback."""
    # Postgres URL: explicit flag, then a URL embedded in the command.
    url = db_url
    if not url:
        m = _PG_URL.search(cmd)
        if m:
            url = m.group(0)
    if url:
        return Target("postgres", url, redact(url))

    # Explicit file / dir target.
    if target_path:
        ap = os.path.abspath(target_path)
        return Target("dir", ap, ap) if os.path.isdir(ap) else Target("file", ap, ap)

    # Explicit sqlite db, or a .db path literally named in the command.
    candidates: List[str] = []
    if explicit_db:
        candidates.append(explicit_db)
    m = _DB_FILE.search(cmd)
    if m:
        candidates.append(m.group(0))
    for cand in candidates:
        if os.path.exists(cand):
            ap = os.path.abspath(cand)
            return Target("sqlite", ap, ap)
    # An explicit --db that does not exist yet is still a declared target.
    if explicit_db:
        ap = os.path.abspath(explicit_db)
        return Target("sqlite", ap, ap)
    return None


# --------------------------------------------------------------------------
# Filesystem-operand extraction (Trou 2): make the snapshot actually fire on
# the auto-fire path for rm / mv, where the target is named in the command
# rather than passed as a flag.
# --------------------------------------------------------------------------

# Leading env-var assignments (`X=1 rm ...`) are a shell prefix before the
# command word; allow them so the operand extractor still fires (#006).
_ENV_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_RM_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?rm\b", re.I)
_MV_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?mv\b", re.I)
_PS_REMOVE_RE = re.compile(r"^\s*(?:Remove-Item|ri)\b", re.I)

# Brace expansion. The shell expands `{a,b}` and `{1..3}` BEFORE globbing and
# *unconditionally* - independent of what exists on disk - so `rm file{1,2,3}.txt`
# deletes three files even though none of them is named literally anywhere. This
# is the same failure mode as the glob one: the command reaches us as the literal
# string, so if we do not expand braces ourselves we see one non-existent operand
# and snapshot nothing. Bounded by _BRACE_MAX: a pathological expansion falls back
# to the literal token (we capture nothing for it -> the honest escalate path),
# never an unbounded blow-up.
_BRACE_MAX = 1024
# One recursion level per brace GROUP, so a token with thousands of them blew
# the stack once the expansion was made linear (2026-09-08). Before that it was
# exponential and hung long before it got deep, which is the only reason this
# never showed. A RecursionError is not an OSError, so it would have escaped
# Guard.evaluate and the hook would have failed open - the same silent
# unguarded-delete as the dangling-symlink crash.
#
# 64 is far past anything meaningful: _BRACE_MAX caps the product at 1024, so
# even binary groups stop expanding after ten. Past this the token is literal.
_BRACE_MAX_DEPTH = 64


def _split_top_commas(s: str) -> List[str]:
    """Split on commas at brace-depth 0 only, so nested groups stay intact."""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def _expand_range(inner: str) -> Optional[List[str]]:
    """Expand a `{m..n}` numeric or `{a..z}` single-char range, or None."""
    m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)", inner)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = 1 if b >= a else -1
        vals = range(a, b + step, step)
        return None if len(vals) > _BRACE_MAX else [str(v) for v in vals]
    m = re.fullmatch(r"([a-zA-Z])\.\.([a-zA-Z])", inner)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        step = 1 if b >= a else -1
        vals = range(a, b + step, step)
        return None if len(vals) > _BRACE_MAX else [chr(v) for v in vals]
    return None


def _first_brace_group(s: str) -> Optional[tuple]:
    """Index span (start, end) of the first balanced top-level {...}, or None."""
    depth, start = 0, -1
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0:
                return start, i
    return None


def _expand_braces(token: str) -> List[str]:
    """Expand shell brace syntax in one operand, bash-style: `{a,b,c}` lists and
    `{m..n}` / `{a..z}` ranges, including nesting and cartesian products
    (`{a,b}{1,2}` -> a1 a2 b1 b2). A group with no top-level comma and no valid
    range (e.g. `{foo}`) stays literal, exactly as the shell leaves it. Falls
    back to the unexpanded token if the expansion would exceed _BRACE_MAX."""
    try:
        out = _expand_braces_bounded(token)
    except RecursionError:
        # The depth cap below should make this unreachable. It is caught
        # anyway: a token shape nobody predicted must degrade to "literal",
        # never take the guard down. "Degrade, never crash."
        return [token]
    return [token] if out is None else out


def _expand_braces_bounded(token: str, depth: int = 0) -> Optional[List[str]]:
    """The recursion behind _expand_braces. None means "too big, give up".

    TWO DEFECTS, ONE SHAPE (found by review 2026-09-08).

    1. EXPONENTIAL IN TIME. The tail was expanded INSIDE the option loop:

           for opt in options:
               for opt_x in _expand_braces(opt):
                   for tail in _expand_braces(post):   # recomputed every time

       so T(n) = 2*T(n-1) for `{a,b}` repeated n times - measured at 4x per
       two groups: 10 groups 0.016s, 18 groups 2.6s, 20 groups 10.6s, 600
       groups never returned. _BRACE_MAX bounded `result`, but the blowup
       happens inside the recursive calls, before the first append, so the
       check was never reached. A hang in the guard's hot path, which runs
       before every single tool call.

       The tail does not depend on the option, so it is computed once.

    2. THE BAIL PRODUCED GARBAGE, NOT A FALLBACK. The old bail returned
       `[token]` from an INNER level, and the outer level then combined that
       literal with its own options - yielding operands like `a{a,b}{a,b}...`
       that are neither the full expansion nor the original token. Visible in
       the timings above as absurd result counts (14 groups -> 8 items).
       Those strings reach _path_operands as candidate paths.

       So "too big" is now a distinct return value that propagates all the way
       up, and the caller substitutes the whole unexpanded token exactly once.
       A partial expansion is never a safe answer: the operand list is what
       decides whether a command is a single-target capture or an escalation.
    """
    if depth > _BRACE_MAX_DEPTH:
        return None
    grp = _first_brace_group(token)
    if grp is None:
        return [token]
    a, b = grp
    pre, inner, post = token[:a], token[a + 1:b], token[b + 1:]

    tails = _expand_braces_bounded(post, depth + 1)  # once, not per option
    if tails is None:
        return None

    options = _split_top_commas(inner)
    if len(options) <= 1:
        rng = _expand_range(inner)
        if rng is None:
            # Not expandable: keep this group literal, expand anything after
            # it. (_expand_range also returns None for a range that is simply
            # too large, and literal is the right answer for that too.)
            return [token[:b + 1] + tail for tail in tails]
        options = rng

    expanded: List[List[str]] = []
    total = 0
    for opt in options:
        ex = _expand_braces_bounded(opt, depth + 1)  # options may nest
        if ex is None:
            return None
        expanded.append(ex)
        total += len(ex)
        # Bounded BEFORE building the product, so the cost of refusing is not
        # itself the thing that hangs.
        if total * len(tails) > _BRACE_MAX:
            return None
    return [pre + opt_x + tail
            for ex in expanded for opt_x in ex for tail in tails]


def _mv_target_dir(seg: str) -> Tuple[Optional[str], bool]:
    """(target directory, ambiguous?) for `mv -t DIR src...`.

    `mv -t bk s1` moves s1 INTO bk, so the file at risk is bk/s1. _mv took
    ops[-1] as the destination, and _path_operands drops `-t` as a flag while
    keeping its value - so ops was [bk, s1] and ops[-1] was the SOURCE. The
    guard snapshotted s1, which is merely being moved away, and reported
    REVERSIBLE while bk/s1 was overwritten with nothing captured. Found by
    review 2026-09-08.

    Returns ambiguous=True for a short-flag cluster we cannot split with
    confidence (`mv -ft bk s1`). Escalating on a spelling we cannot read is
    the same contract as everywhere else in this module.
    """
    toks = _tokenize(seg)
    for i, tok in enumerate(toks):
        if tok in ("-t", "--target-directory"):
            return (toks[i + 1].strip("'\"") if i + 1 < len(toks) else None), False
        if tok.startswith("--target-directory="):
            return tok.split("=", 1)[1].strip("'\""), False
        if tok.startswith("-") and not tok.startswith("--") and "t" in tok[1:]:
            if tok.startswith("-t"):
                return tok[2:].strip("'\""), False      # -tbk
            return None, True                            # -ft bk: do not guess
    return None, False


def _tokenize(cmd: str, windows_paths: Optional[bool] = None) -> List[str]:
    """Split a command line into words the way a shell would - respecting quotes.

    `cmd.split()` cuts on whitespace and knows nothing about quotes, so

        Remove-Item -Recurse -Force "C:\\Program Files\\MyApp"
        rm -rf "/home/nizar/my project"

    each became TWO operands, the target could not be pinned down, and nothing
    was snapshotted. That is not a Windows bug - it is every path containing a
    space, on every platform.

    shlex is Python's shell lexer, but its POSIX mode treats backslash as an
    ESCAPE character - and on Windows a backslash is a PATH SEPARATOR. Left
    enabled it silently destroys every unquoted Windows path:

        rm -rf C:\\Users\\pc\\Temp\\x.txt   ->   'C:UserspcTempx.txt'

    which then does not exist, so no target resolves and everything escalates.
    (Regression found only by running the suite on real Windows: 15 failures
    against a clean baseline. The chunk-2 check tested a QUOTED path, where
    backslash happens to survive, and generalised from it.)

    There is no single correct setting - the two shells genuinely disagree:

        rm -rf C:\\Users\\x        needs escaping OFF   (Windows path)
        rm -rf my\\ project        needs escaping ON    (POSIX escaped space)

    so it follows the platform, with an explicit override for callers that know
    they are reading PowerShell.

    shlex raises on unbalanced quotes. A malformed command must degrade to the
    old behaviour, never crash the guard - same fail-open rule as the hooks.
    """
    if windows_paths is None:
        windows_paths = os.name == "nt"
    lex = shlex.shlex(cmd, posix=True)
    lex.whitespace_split = True          # split on whitespace, not shell punctuation
    if windows_paths:
        lex.escape = ""                  # backslash is a path separator, not an escape
    try:
        return list(lex)
    except ValueError:
        return cmd.strip().split()


def _path_operands(cmd: str, base: Optional[str] = None) -> List[str]:
    """Crude operand extraction: drop the leading command word(s) and any flags,
    keep the rest as candidate paths. Not a shell parser - good enough to find
    the target of a simple rm / mv.

    Braces and globs are expanded here the way the shell would expand them, in
    that order (braces first, then glob each result). The command we are handed
    has NOT been through the shell yet: `rm -f Reports/*.png` and
    `rm file{1,2,3}.txt` both arrive as literal strings, so os.path.exists() on
    them is False and the operand extractor would see nothing at all. Expanding
    them ourselves is the only way to know what the command will actually
    destroy - which is also, exactly, the thing the user needed to see.
    """
    toks = _tokenize(cmd)
    i = 0
    # Skip the shell prefix: leading env-var assignments and sudo come BEFORE the
    # command word. (After the command word, `X=1` would be a real filename, so
    # only the leading run is skipped - `rm X=1 f` still treats X=1 as an operand.)
    while i < len(toks) and (_ENV_ASSIGN.match(toks[i]) or toks[i] == "sudo"):
        i += 1
    if i < len(toks) and toks[i] in ("rm", "mv"):
        i += 1
    out: List[str] = []
    for tok in toks[i:]:
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        # The shell expands `~` before the command ever sees it, so our view of
        # the operands has to as well. Left literal, `~/a` became "<cwd>/~/a"
        # via abspath - a path that cannot exist - and two such operands
        # collapsed to a common root of the CURRENT DIRECTORY. `rm -f ~/a ~/b`
        # run from a subdirectory then snapshotted that subdirectory and
        # reported REVERSIBLE, while the files that died were in $HOME and the
        # recovery point held none of them (2026-09-08). Expanded, they
        # collapse to $HOME, which _too_broad refuses, and the command
        # escalates honestly.
        tok = os.path.expanduser(tok)
        # `base` is the working directory the shell will actually be in when
        # this runs - set only when a `cd` moved it somewhere other than here.
        # Without it, globbing and os.path.exists resolve against OUR cwd and
        # the answer describes a different directory's contents.
        if base and not os.path.isabs(tok):
            tok = os.path.normpath(os.path.join(base, tok))
        for piece in _expand_braces(tok):
            if any(ch in piece for ch in "*?["):
                out.extend(sorted(_glob.glob(piece)))
            else:
                out.append(piece)
    return out


_PS_PATH_FLAGS = {"-literalpath", "-path"}


def sole_segment(cmd: str, rx, dialect: str = POSIX) -> Optional[str]:
    """The ONE segment of a command line that `rx` matches, or None.

    WHY THIS EXISTS (found 2026-08-25, on Windows, by a PowerShell test that
    should never have been platform-gated).

    Every operand extractor below is written as if its verb were the first
    word on the line - `_path_operands` skips a leading run of assignments and
    `sudo`, `_ps_remove_item_operand` drops exactly one token. Anything else in
    front leaks in as an extra operand, the count stops being one, and the
    extractor gives up:

        echo hi; rm a.txt                  -> None
        cd build && rm -rf ./out           -> None
        Write-Host hi; Remove-Item a.txt   -> None
        $t = "a.txt"; Remove-Item $t       -> None

    None of that was dangerous - an unresolved target escalates, so the action
    is blocked rather than run unsnapshotted - but `cd x && rm y` is what
    agents actually write, and a guard that blocks the common case instead of
    protecting it gets uninstalled. Narrowing to the matching segment fixes
    every one of them, in both dialects, without touching the extractors.

    THE HONESTY RULE, and the reason this returns None rather than the first
    match: when TWO segments are destructive -

        rm a.txt; rm b.txt

    - picking one would snapshot a.txt and let b.txt die unrecorded, while the
    receipt claimed a recovery. That is the partial-recovery lie FIX #5 exists
    to prevent, so several matches means no target and an honest escalation.
    """
    matches = [s for s in split_segments(cmd, dialect) if rx.search(s)]
    return matches[0] if len(matches) == 1 else None


def _ps_remove_item_operand(cmd: str) -> Optional[str]:
    """Conservative PowerShell `Remove-Item` target extraction. Supports:

        Remove-Item -Recurse -Force ".\\victim"
        Remove-Item -LiteralPath ".\\victim" -Recurse -Force
        Remove-Item -Path ".\\victim" -Recurse -Force

    Not a shell parser - like `_path_operands`, good enough to find the single
    target of a simple call. Any flag other than -Path/-LiteralPath is skipped
    without consuming a value, so a command carrying an unsupported flag with
    its own argument (e.g. `-ErrorAction Stop`) leaves that argument looking
    like a second positional operand - deliberately, so it is treated as
    ambiguous below rather than guessed at. Returns None (never a target) when
    the operand count is not exactly one, or the operand contains a wildcard:
    the honesty rule is that a target this function cannot pin down exactly
    must not be snapshotted at all.
    """
    if not _PS_REMOVE_RE.search(cmd):
        return None
    tokens = _tokenize(cmd, windows_paths=True)[1:]  # PowerShell: \\ is a path sep
    targets: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.lower() in _PS_PATH_FLAGS:
            i += 1
            if i < len(tokens):
                targets.append(tokens[i].strip("'\""))
            i += 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        targets.append(tok.strip("'\""))
        i += 1
    if len(targets) != 1:
        return None
    target = targets[0]
    if not target or any(ch in target for ch in "*?[]"):
        return None
    return target


# The PowerShell cmdlets that overwrite or empty ONE named file, and the ones
# that clobber a DESTINATION. Kept separate from Remove-Item's reader, which has
# its own tested behaviour we do not want to disturb.
_PS_CONTENT_RE = re.compile(r"^\s*(?:Clear-Content|clc|Set-Content|Out-File|New-Item)\b", re.I)
_PS_DEST_RE = re.compile(r"^\s*(?:Move-Item|Copy-Item|Rename-Item)\b", re.I)

_PS_DEST_FLAGS = {"-destination"}
# -NewName IS NOT A PATH. `Rename-Item -Path C:\proj\a.txt -NewName b.txt`
# clobbers C:\proj\b.txt - the name is relative to the SOURCE's directory,
# not to the working directory. Taken literally it resolved against the cwd,
# found nothing there, and the guard read that as "creates" and cleared the
# destructive flag: a false ALLOW while the real file was overwritten
# (2026-09-09).
#
# Its own set rather than a cmdlet check, because the semantics belong to the
# FLAG: -NewName exists only on Rename-Item, so matching the cmdlet would only
# ever be a proxy for matching the flag - and a less precise one.
_PS_NEWNAME_FLAGS = {"-newname"}
_PS_RENAME_RE = re.compile(r"^\s*Rename-Item\b", re.I)
# Flags whose NEXT token is a value, not a path. Without this list
# `Set-Content -Path x -Value "hello"` yields two candidate targets and looks
# ambiguous, so a perfectly ordinary overwrite would escalate instead of being
# snapshotted.
_PS_VALUE_FLAGS = {"-value", "-encoding", "-erroraction", "-itemtype", "-filter",
                   "-include", "-exclude", "-stream", "-width", "-name"}


def _ps_flagged_operands(cmd: str) -> List[Tuple[Optional[str], str]]:
    """Candidate targets with the flag that named each one, in order.

    The loop already TOLD path flags from destination flags and then appended
    both to one flat list, throwing the distinction away a line later - which
    is why `Copy-Item -Destination keep\b.txt -Path a.txt` resolved to the
    source: _ps_dest_target could only take the last element and hope the
    author wrote the flags in the usual order. PowerShell named parameters are
    order-free (2026-09-09).

    A positional operand carries None as its flag.
    """
    toks = _tokenize(cmd, windows_paths=True)[1:]     # drop the cmdlet itself
    out: List[Tuple[Optional[str], str]] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        low = tok.lower()
        if low in _PS_PATH_FLAGS or low in _PS_DEST_FLAGS or low in _PS_NEWNAME_FLAGS:
            i += 1
            if i < len(toks):
                out.append((low, toks[i].strip("'\"")))
            i += 1
            continue
        if low in _PS_VALUE_FLAGS:
            i += 2                                     # flag and its value
            continue
        if tok.startswith("-"):
            i += 1                                     # switch with no value
            continue
        out.append((None, tok.strip("'\"")))
        i += 1
    return out


def _ps_named_operands(cmd: str) -> List[str]:
    """The values only, in order - the shape every existing caller expects."""
    return [value for _, value in _ps_flagged_operands(cmd)]


def _win_aware_dirname(path: str) -> str:
    r"""dirname() that works for a Windows path on a POSIX host.

    os.path.dirname(r"proj\old.txt") is "" on Linux, because a backslash is an
    ordinary character there - so a join against it silently does nothing and a
    fix built on it looks correct while achieving nothing. The suite runs on
    both platforms with literal `C:\...` fixtures, so this cannot be left to
    os.path.
    """
    import ntpath
    return ntpath.dirname(path) if "\\" in path else os.path.dirname(path)


def _win_aware_join(head: str, tail: str, flavour_of: str = "") -> str:
    r"""join(), choosing the separator from `flavour_of` rather than from head.

    The head of "proj\old.txt" is "proj", which carries no backslash - so
    deciding on the head produced "proj/b.txt" for a Windows command. The
    original operand is the thing that knows which flavour of path this is.
    """
    import ntpath
    if not head:
        return tail
    windows = "\\" in (flavour_of or head)
    return ntpath.join(head, tail) if windows else os.path.join(head, tail)


def _ps_write_target(cmd: str) -> Optional[str]:
    """The one file a content cmdlet overwrites or empties, or None.

    Exactly one operand, no wildcard - the same honesty rule Remove-Item uses:
    a target this cannot pin down exactly must not be snapshotted at all.
    """
    ops = _ps_named_operands(cmd)
    if len(ops) != 1:
        return None
    target = ops[0]
    if not target or any(ch in target for ch in "*?[]"):
        return None
    return target


def _ps_dest_target(cmd: str) -> Optional[str]:
    r"""What a Move/Copy/Rename -Force will CLOBBER: the destination, not the
    source. Mirrors the mv branch of extract_path_operand.

    RESOLVED BY FLAG, NOT BY POSITION. `ops[-1]` assumed the author wrote
    -Path before -Destination; PowerShell named parameters are order-free, so
    `Copy-Item -Destination keep.txt -Path a.txt` resolved to the SOURCE.

    -NewName is joined to the source's directory, because it names a file
    beside the source rather than a path from here. A -NewName containing a
    separator is refused: PowerShell's behaviour there is something neither I
    nor the reviewer could confirm without a Windows box, and refusing is
    correct under both readings - unreachable if PowerShell errors, and the
    honest answer if it does not. Choosing the branch that is right either way
    is cheaper than being sure.

    ONE CMDLET CHECK, and only in the positional fallback. `Rename-Item a b`
    means -NewName b while `Move-Item a b` means -Destination b, and no flag
    separates them, so nothing else can. It is not new coupling: ps_named_target
    already reaches this function through _PS_DEST_RE, which is literally
    Move-Item|Copy-Item|Rename-Item.
    """
    pairs = _ps_flagged_operands(cmd)
    values = [v for _, v in pairs]
    if len(values) < 2:
        return None

    def _flagged(names):
        return next((v for f, v in pairs if f in names), None)

    src = _flagged(_PS_PATH_FLAGS)
    newname = _flagged(_PS_NEWNAME_FLAGS)

    if newname is not None:
        if "/" in newname or "\\" in newname:
            return None                     # a path, not a name: ambiguous
        base = src if src is not None else next(
            (v for f, v in pairs if f is None), None)
        if base is None:
            return None
        dst = _win_aware_join(_win_aware_dirname(base), newname, base)
    else:
        dst = _flagged(_PS_DEST_FLAGS)
        if dst is None:
            dst = values[-1]                # positional
            if _PS_RENAME_RE.search(cmd):
                dst = _win_aware_join(_win_aware_dirname(values[0]), dst,
                                      values[0])

    if not dst or any(ch in dst for ch in "*?[]"):
        return None
    return dst


def ps_named_target(cmd: str) -> Tuple[Optional[str], bool]:
    r"""(absolute path, resolved?) for a PowerShell write or clobber.

    Same contract and same shape as resolve_redirect_target, deliberately: two
    functions answering "what does this command touch" with two conventions is
    how three modules came to disagree and cost a silent data loss.

    The docstring here already said the rule - "a name that does not resolve at
    all is ambiguous and must still escalate" - and the code returned a bare
    string, so the guard could not tell an unresolvable name from a resolvable
    one that is merely absent. `Set-Content -Path $env:APPDATA
otes.txt` came
    back as that literal, os.path.exists said no, and the guard read it as
    creation and cleared the flag. The third comment/code contradiction found
    in this review, and the last place the contract was missing.

    Existence is still NOT checked here: resolved-and-absent means "creates"
    and only the caller can act on that. Resolved means "we know which file",
    nothing more.
    """
    if _PS_CONTENT_RE.search(cmd):
        named = _ps_write_target(cmd)
    elif _PS_DEST_RE.search(cmd):
        named = _ps_dest_target(cmd)
    else:
        return None, False
    if not named:
        return None, False
    named = _expanduser_any(named)
    if _UNEXPANDED.search(named):
        return None, False
    return os.path.abspath(named), True


def _expanduser_any(path: str) -> str:
    r"""expanduser that also handles `~\x`, which os.path.expanduser leaves
    alone on POSIX because a backslash is not a separator there."""
    if path.startswith("~\\"):
        return os.path.join(os.path.expanduser("~"), path[2:])
    return os.path.expanduser(path)


def _too_broad(path: str) -> bool:
    """Capture surfaces we refuse however small they measure: the filesystem
    root, a Windows drive root, and $HOME. `rm ~/a ~/b` must never quietly
    become "snapshot the entire home directory"."""
    ap = os.path.abspath(path)
    if os.path.dirname(ap) == ap:                       # "/" or "C:\\"
        return True
    return ap == os.path.abspath(os.path.expanduser("~"))


def _common_capture_root(paths: List[str]) -> Optional[str]:
    """The one directory that provably contains every path the command can
    affect. Snapshotting it captures a SUPERSET of the damage, so the recovery
    stays provable rather than partial - which is the whole invariant. Returns
    None when no such directory exists, or when it would be absurdly broad."""
    # Two distinct Windows drive letters have no common root at all. Detect this
    # with ntpath (available on every OS) so it is caught even when the check
    # runs on a POSIX host, where backslash paths would otherwise be treated as
    # literal filenames and collapse to a bogus common root under the cwd.
    # AN UNEXPANDED OPERAND IS NOT A PATH, and a common root computed from one
    # is meaningless. `$HOME/a` abspath's to "<cwd>/$HOME/a", so two of them
    # collapse to the current directory and the capture lands on whatever
    # happens to be there. Same contract as resolve_redirect_target: refusing
    # to answer is an answer, guessing is not.
    if any(_UNEXPANDED.search(p) for p in paths):
        return None
    import ntpath
    drives = {ntpath.splitdrive(p)[0].upper() for p in paths}
    drives.discard("")
    if len(drives) > 1:
        return None
    try:
        root = os.path.commonpath([os.path.abspath(p) for p in paths])
    except ValueError:                                  # different drives (Windows)
        return None
    if not os.path.isdir(root):
        root = os.path.dirname(root)
    if not root or not os.path.isdir(root) or _too_broad(root):
        return None
    return root


def expanded_operands(cmd: str, dialect: str = POSIX) -> List[str]:
    """The concrete list of existing paths an rm / mv will touch.

    Exposed so the preview can PRINT it. claude-code#76626: an agent ran
    `rm -f Reports/report_*.txt Reports/report_*.png` intending "just to check
    the current file count". The glob expansion IS the file count. Showing this
    list answers the question the agent was asking and makes the deletion
    impossible to approve by accident, in the same operation. The preview is not
    friction here - the preview is the task.

    Returns [] for anything that is not an rm / mv, so callers can invoke it
    unconditionally: the crude operand split is only meaningful for those two.

    PER SEGMENT, AGAINST THE EFFECTIVE DIRECTORY. _RM_RE is anchored at the
    start of the string, so matched against a whole LINE it saw nothing in

        cd x && rm -rf a b
        echo hi; rm -rf a b
        bash -c "rm -rf a b"

    and the preview printed "no files affected" for deletions that were about
    to happen. The snapshot was correct throughout - only the display lied,
    which is why no test caught it and why it is worse than it sounds: this is
    the surface built FOR claude-code#76626, where the agent's stated goal was
    to COUNT the files. A preview that answers "none" is the wrong answer to
    the exact question that incident was about. Found by review 2026-09-08.

    Every rm/mv segment contributes, not just one. The snapshot decision has
    its own multiplicity rule and escalates; the preview's job is to show what
    the line touches, and showing half of it would be the display telling a
    smaller version of the same lie.
    """
    segments, moved = _operand_context(cmd, dialect)
    seen, out = set(), []
    for index, seg in enumerate(segments):
        if not (_RM_RE.search(seg) or _MV_RE.search(seg)):
            continue
        # This segment's view, not the line's. See _base_at.
        base, ok = _base_at(cmd, segments, index, moved)
        if not ok:
            return []                   # unmodellable cd: nothing honest to show
        for path in _path_operands(seg, base):
            # ABSOLUTE AND DEDUPED BY IDENTITY, not by spelling. `rm a.txt; rm
            # ./a.txt` is one file, and a string dedupe reported "files
            # matched: 2" - inflating the very count that #76626 was about.
            # Mixing relative and absolute in one list also made render's
            # redact() show the same file two ways depending on whether a cd
            # appeared earlier in the line.
            real = os.path.normpath(os.path.abspath(path))
            if real not in seen and os.path.exists(real):
                seen.add(real)
                out.append(real)
    # Sorted because glob order is os.scandir order: stable on one filesystem,
    # not guaranteed across them. An unsorted preview is a test that passes
    # here and fails on somebody else's machine.
    return sorted(out)


def extract_path_operand(cmd: str, dialect: str = POSIX) -> Optional[str]:
    """Return the filesystem path an rm / mv will affect, or None.

    Honesty rule (the invariant): never snapshot a SUBSET and imply full
    recovery.

    v0.4 - a multi-path rm used to return None unconditionally. That was too
    blunt, and it cost someone their work. Live incident, claude-code#76626: an
    agent ran

        rm -f Reports/report_*.txt Reports/report_*.png

    intending only to count the files. Every path was local, bounded and cheap
    to copy - precisely the case where full capture is PROVABLE - and the old
    rule escalated instead of capturing. Not in the recycle bin (no CLI delete
    ever is), not git-tracked, not in shadow copies. Permanently gone.

    So: several paths that collapse into one capturable directory now snapshot
    that DIRECTORY. It is a superset of everything the command can touch, so the
    recovery is still provable, never partial. Anything that does NOT collapse
    to one bounded directory still returns None and still escalates honestly.
    The size cap in snapshot() and the project-root bound in guard() both still
    apply on top of this.

    Two cautions for anyone touching this later:

    * This function is NOT the honesty boundary by itself. When only one operand
      exists among several, the result collapses to that single path even if it
      lies outside the project; it is the guard's `within` project-root check
      (guard.evaluate) that refuses to snapshot or claim reversibility for it.
      Do not reuse extract_path_operand at a new call site without that bound.
    * The directory return means undo is COARSE: restoring a multi-path rm
      restores the whole captured directory to its snapshot state (see
      restore_entry). That is what keeps recovery a provable superset, but it
      also rolls back unrelated edits made to other files in that directory
      after the snapshot. Immediately after the rm (the flagship flow) this is a
      non-issue; the window only matters if other writes land before undo.
    """
    # A command written across two lines is still one command; fold it before
    # looking for operands, or the path on the second line is simply not seen.
    # Unwrap a nested shell FIRST, and take its dialect with it. classify_pipeline
    # does the same on the same input; if only one of them did, the classifier
    # would call `powershell -c "Remove-Item x"` destructive while the operand
    # extractor looked for a path in text that no longer describes the action.
    #
    # SPLIT BEFORE UNWRAPPING, not after. `echo hi; bash -c "rm -rf ./out"`
    # used to unwrap nothing (the line starts with `echo`) and the nested rm's
    # operand was never found - the command was still flagged by the unanchored
    # rm_rf rule, so the guard escalated instead of snapshotting. Both callers
    # now go through the one function so they cannot drift apart.
    # `T=notes.txt; rm $T` names its target in the same string it uses it in.
    # Resolving that (substitute=True) rather than in the classifier keeps the
    # change to WHAT WE SNAPSHOT, and leaves WHETHER IT IS DESTRUCTIVE alone:
    # `rm $T` is already classified as an rm either way. It happens per nesting
    # level, before that level is split, because the assignment and its use are
    # sibling segments. Returns the command untouched unless every reference
    # resolved, so this can only ever narrow an escalation into a precise
    # snapshot, never widen anything.

    # DISPATCH ON THE SEGMENT, NOT THE LINE.
    #
    # Every rule below is anchored to the start of its input (`^\s*...rm\b`),
    # because a bare `rm` has to be a command word and not the middle of a
    # filename. Applied to a whole command LINE that anchor also means the verb
    # must come first - so `cd build && rm -rf ./out` matched nothing at all and
    # escalated, and that is what agents actually write. Found 2026-08-25.
    #
    # Several destructive segments (`rm a.txt; rm b.txt`) return None. Picking
    # one would snapshot a.txt while b.txt died unrecorded, with the receipt
    # claiming a recovery - the partial-recovery lie FIX #5 exists to prevent.
    segments, moved = _operand_context(cmd, dialect)
    # `base` stays None whenever the shell has not actually moved, so every
    # command without a `cd` - the overwhelming majority - takes exactly the
    # path it took before, returning relative operands relative. Only a real
    # relocation changes anything, and then absolute is the only honest answer.
    base: Optional[str] = None

    def _rm(seg: str) -> Optional[str]:
        # Collect every operand BEFORE deciding anything. Filtering to
        # os.path.exists() first and only then counting was the bug: an
        # operand that is a real, literal path but happens not to exist on
        # THIS machine (e.g. a Unix path like /etc/hosts checked from a
        # Windows host) would silently vanish from the count, so a genuinely
        # multi-target rm looked like a single-target one and collapsed to
        # that one target instead of escalating. A non-wildcard operand is a
        # real rm argument regardless of whether it currently exists; only
        # wildcard operands are existence-filtered (by the glob expansion
        # inside _path_operands itself, since a glob that matches nothing
        # touches nothing).
        ops = _path_operands(seg, base)
        if len(ops) == 1:
            return ops[0] if os.path.exists(ops[0]) else None
        if len(ops) > 1:
            return _common_capture_root(ops)
        return None

    def _mv(seg: str) -> Optional[str]:
        ops = _path_operands(seg, base)

        # `mv -t DIR src...` inverts the operand order: every source lands in
        # DIR, so the files at risk are DIR/basename(src) - not ops[-1], which
        # is a source. See _mv_target_dir.
        tdir, ambiguous = _mv_target_dir(seg)
        if ambiguous:
            return None
        if tdir:
            root = os.path.abspath(os.path.join(base, tdir)) if (
                base and not os.path.isabs(tdir)) else os.path.abspath(tdir)
            srcs = [o for o in ops if os.path.abspath(o) != root]
            hit = [p for p in (os.path.join(root, os.path.basename(sp))
                               for sp in srcs) if os.path.exists(p)]
            if len(hit) == 1:
                return hit[0]
            if len(hit) > 1:
                return _common_capture_root(hit)
            # Nothing is overwritten: the sources only change place, and the
            # move is undone by moving them back.
            if len(srcs) == 1 and os.path.exists(srcs[0]):
                return srcs[0]
            return _common_capture_root(srcs) if len(srcs) > 1 else None

        if len(ops) >= 2:
            dst, src = ops[-1], ops[-2]
            if os.path.exists(dst):
                return dst
            if os.path.exists(src):
                return src
        return None

    def _existing(fn):
        def run(seg: str) -> Optional[str]:
            target = fn(seg)
            return target if target and os.path.exists(target) else None
        return run

    # MULTIPLICITY IS COUNTED ACROSS RULES, NOT WITHIN EACH ONE.
    #
    # The loop below returns on the first rule that matches, so it could only
    # ever see its own segments. `rm a.txt; rm b.txt` escalated correctly - two
    # hits for one rule - while these did not:
    #
    #     rm old.txt; mv new.txt keep.txt      snapshot of old.txt, REVERSIBLE
    #     rm old.txt; echo z > keep.txt        snapshot of old.txt, REVERSIBLE
    #
    # keep.txt is clobbered in both, with nothing captured and the receipt
    # claiming a recovery. That is the partial-recovery lie FIX #5 exists to
    # prevent, surviving because the two destructive steps used DIFFERENT
    # verbs. Found by review 2026-09-08.
    #
    # A set of indices, so one segment matching two rules still counts once,
    # and the redirect detector is included because `> file` is a destructive
    # step even though no rule regex covers it.
    acting = {i for i, seg in enumerate(segments)
              if any(rx.search(seg) for rx in (_RM_RE, _MV_RE, _PS_REMOVE_RE,
                                               _PS_CONTENT_RE, _PS_DEST_RE))
              or redirect_target(seg)}
    if len(acting) > 1:
        return None

    for rx, handler in ((_RM_RE, _rm),
                        (_MV_RE, _mv),
                        (_PS_REMOVE_RE, _existing(_ps_remove_item_operand)),
                        (_PS_CONTENT_RE, _existing(_ps_write_target)),
                        (_PS_DEST_RE, _existing(_ps_dest_target))):
        hits = [(i, seg) for i, seg in enumerate(segments) if rx.search(seg)]
        if not hits:
            continue
        if len(hits) != 1:
            return None
        idx, seg = hits[0]
        base, ok = _base_at(cmd, segments, idx, moved)
        if not ok:
            return None                         # cannot model it: do not guess
        target = handler(seg)
        # Belt and braces: a relative answer after a move would describe the
        # wrong directory, and there is no honest way to interpret it.
        if target and moved and base and not os.path.isabs(target):
            return None
        return target

    # Truncating output redirection ('> file'): snapshot the file it overwrites.
    # Uses the same quote-aware detector as the classifier, so classify (is it
    # destructive?) and recovery (what to snapshot?) can never disagree.
    #
    # Per SEGMENT, and only when exactly one segment redirects. `cmd` is the
    # raw line now, not a normalised whole, and `a > x; b > y` must escalate
    # for the same reason two rm segments do: snapshotting x while y is
    # truncated unrecorded is the partial-recovery lie.
    tgt, _ = resolve_redirect_target(cmd, dialect, moved=moved)
    if tgt:
        return tgt if os.path.exists(tgt) else None
    return None


# A target token that is not a filename yet. Three families, and the third is
# the one that bit us: a token CUT AT WHITESPACE inside an unclosed construct.
#
#   $VAR ${VAR} %VAR%      a variable we could not substitute
#   $( ` )                 command substitution - the value does not exist
#                          until the shell runs the inner command
#   !VAR!                  cmd.exe delayed expansion
#
# `echo x > $(cat name.txt)` reaches redirect_target as the partial token
# `$(cat`, because the target is read up to whitespace. The first version of
# this regex looked for `$\w` and `${` and matched neither, so the resolver
# reported RESOLVED for a string that can never name a file - the guard then
# stat'd it, found it absent, and read absent as creation. Same false ALLOW
# the resolver exists to prevent, through a different door (2026-09-08).
#
# This is not evasion and does not sit behind the §2 frontier: `> $(date
# +%F).log` and `> $(hostname).sql` are ordinary idioms. They belong in the
# RESOLUTION gap - known-dangerous, unresolvable before it runs - which is
# answered by escalate, not by a guess.
_UNEXPANDED = re.compile(r"""
      \$\w | \$\{ | \$\(          # $VAR  ${VAR}  $(cmd
    | `                            # `cmd`
    | %\w+% | %\w+:               # %VAR%  %VAR:~0,3%
    | ![\w]+!                      # !VAR!  (cmd.exe delayed expansion)
    | [()]                         # a stray bracket means the token was cut
""", re.X)


def resolve_redirect_target(cmd: str, dialect: str = POSIX,
                            moved: Optional[bool] = None
                            ) -> Tuple[Optional[str], bool]:
    """(absolute target, resolved?) for a truncating output redirection.

    THE ONE RESOLVER, because three modules used to answer this differently and
    the disagreement cost a silent data loss (2026-09-08).

        classify_pipeline           effective segments  (since 2026-09-02)
        extract_path_operand        effective segments + substitution
        Guard.evaluate              THE RAW LINE

    The classifier was widened on 2026-09-02 to judge unwrapped segments, so it
    began flagging `bash -c "echo x > app.db"`. The guard's creates-if-missing
    correction still read the raw line, could not find a target there (the `>`
    is inside quotes), and cleared the flag - reading "I cannot find it" as
    "there is nothing there to destroy". An existing file was truncated with no
    snapshot, no receipt and no escalation. Five spellings did this; only the
    bare `echo x > app.db` was ever handled correctly.

    RESOLVED IS NOT THE SAME AS FOUND, and that distinction is the whole point:

        (path, True)   a single, fully expanded target. The caller stats it:
                       present means overwrite, absent means creation.
        (None, False)  nothing resolved, MORE than one segment redirects, or
                       the target still carries an unexpanded variable. The
                       caller must keep its classification and escalate.

    Two redirects are unresolved on purpose. `a > x; b > y` snapshotting x
    while y is truncated unrecorded is the partial-recovery lie, the same
    reason a multi-target rm returns None.

    An unexpanded `$HOME/data.db` is unresolved for the same reason: it does
    not exist under that literal name, so treating it as "found and absent"
    reads a real file as a new one. Substitution handles in-line assignments;
    anything from the environment is beyond us and must say so.
    """
    segments = [seg for seg, _ in
                effective_segments(cmd, dialect, substitute=True)] or [cmd]
    hits = [t for t in (redirect_target(seg) for seg in segments) if t]
    if len(hits) != 1:
        return None, False
    tgt = hits[0]
    # `cd build && echo x > out.log` truncates build/out.log, not <cwd>/out.log.
    # The redirect path has the same wrong-directory problem as the operand
    # path, so it takes the same refusal. Callers that already computed it pass
    # it in; the rest work it out here.
    if moved is None:
        moved = _changes_directory(segments)
    if moved and not os.path.isabs(os.path.expanduser(tgt)):
        # Which segment redirects? Its cwd is the one that matters.
        idx = next((i for i, seg in enumerate(segments) if redirect_target(seg)), 0)
        here = effective_cwd(cmd, segments, idx)
        if here is None:
            return None, False                  # unmodellable: refuse
        return os.path.normpath(
            os.path.join(here, os.path.expanduser(tgt))), True
    if _UNEXPANDED.search(tgt):
        return None, False
    # `~` IS resolvable, unlike $(cmd), so expand it rather than escalate.
    # Left alone it became "<cwd>/~/notes.db" - a path that cannot exist, so
    # the guard read a real file in the home directory as a creation. The
    # commonest of the unexpanded forms and the one worth resolving properly.
    return os.path.abspath(os.path.expanduser(tgt)), True


_CD_RE = re.compile(r"^\s*(?:cd|chdir|pushd|popd|Set-Location|sl)\b", re.I)


_CD_ARGS = re.compile(r"^\s*(?:cd|chdir|Set-Location|sl)\s*(?P<arg>.*?)\s*$", re.I)
_UNMODELLED = re.compile(r"^\s*(?:pushd|popd)\b", re.I)


def effective_cwd(cmd: str, segments: List[str], upto: int) -> Optional[str]:
    """The working directory in effect when segments[upto] runs, or None.

    STEP 2 OF THE cd FIX. Step 1 refused every relative operand after a `cd`,
    which closed the wrong-file snapshot and escalated a pattern agents write
    constantly. This folds the `cd`s instead, so the common case resolves to
    the RIGHT file rather than to nothing.

    Folding is one line per hop - normpath(join(cwd, arg)) - and it composes,
    so any number of `cd`s in a row works, and `..`, `.` and absolute paths
    all fall out for free. It also matches bash: bash's default `cd` is
    LOGICAL (-L), so `cd link` then `cd ..` returns to the link's parent,
    which is exactly what normpath does. (`cd -P` would differ; it is refused
    below along with everything else we cannot model.)

    RETURNS None RATHER THAN A GUESS, for:

      * `pushd` / `popd`         a directory stack we do not model
      * a `(` or `)` anywhere    `(cd x && rm y); rm z` puts z back at the
                                 original cwd, and we do not track subshells
      * a `|` anywhere           each side of a pipeline runs in its own
                                 subshell, so a `cd` on the left never reaches
                                 the right. split_segments discards the
                                 separator, so we cannot tell `cd x | rm y`
                                 from `cd x && rm y` - refuse both rather than
                                 get one of them wrong
      * CDPATH set               `cd foo` can then land somewhere else entirely
      * an unexpanded argument   `cd $VAR`, `cd $(...)`, a backtick
      * more than one argument   `cd a b` is an error in bash, not a hop
      * a target that is not a directory NOW

    THE ONE CASE THIS CANNOT DECIDE, stated plainly: with `;` rather than
    `&&`, whether the `cd` succeeded is a runtime fact.

        cd build && rm -rf ./out    cd fails -> rm never runs. Safe.
        cd build ;  rm -rf ./out    cd fails -> rm runs at the OLD cwd.

    Requiring the target to be a real directory reduces that to a race - the
    directory would have to vanish between this check and the command - rather
    than a guess. It is the residual risk, and it is smaller than either
    alternative: escalating every chained rm, or resolving against the wrong
    directory.
    """
    if os.environ.get("CDPATH"):
        return None
    if "(" in cmd or ")" in cmd or "|" in cmd:
        return None

    cwd = os.getcwd()
    previous = cwd
    for seg in segments[:upto]:
        if _UNMODELLED.match(seg):
            return None
        m = _CD_ARGS.match(seg)
        if not m:
            continue
        arg = (m.group("arg") or "").strip().strip("'\"")
        if not arg:                              # bare `cd` goes home
            arg = os.path.expanduser("~")
        elif arg == "-":                         # back where we came from
            arg = previous
        if _UNEXPANDED.search(arg) or len(arg.split()) > 1:
            return None
        nxt = os.path.normpath(os.path.join(cwd, os.path.expanduser(arg)))
        if not os.path.isdir(nxt):
            return None
        previous, cwd = cwd, nxt
    return cwd


def _changes_directory(segments: List[str]) -> bool:
    """Does any segment move the shell somewhere else before the destructive one?

    STEP 1 OF THE FIX FOR A WRONG-FILE SNAPSHOT (2026-09-08).

        cd build && rm -rf ./out

    On 2026-08-25 operand extraction moved from the whole line to per-segment,
    because an anchored rule applied to a whole line matched nothing here and
    the command escalated. That fixed the escalation and introduced something
    worse: `./out` is now resolved against the CURRENT directory, so the guard
    snapshots <cwd>/out - an unrelated, innocent directory - while build/out is
    the one deleted. The receipt says REVERSIBLE and `undo` would restore the
    wrong tree over live data.

    Until the cwd is actually tracked (step 2), a relative operand after a `cd`
    is UNRESOLVED. That is the same contract as resolve_redirect_target and
    _common_capture_root: refusing to answer is an answer, guessing is not.

    Absolute operands are unaffected - `cd x && rm /tmp/y` needs no cwd.

    Deliberately broad: pushd/popd and PowerShell's Set-Location/sl count too,
    since all of them invalidate the assumption in the same way.
    """
    return any(_CD_RE.match(seg) for seg in segments)


def _operand_context(cmd: str, dialect: str = POSIX) -> Tuple[List[str], bool]:
    """(effective segments, does anything move the working directory?).

    The segment/substitute preamble was copied into three functions and was
    already a drift risk.
    """
    segments = [seg for seg, _ in
                effective_segments(cmd, dialect, substitute=True)] or [cmd]
    return segments, _changes_directory(segments)


def _base_at(cmd: str, segments: List[str], index: int,
             moved: bool) -> Tuple[Optional[str], bool]:
    """(base directory, could we tell?) for the segment at `index`.

    ONE STRATEGY, RESOLVED PER INDEX, and the index is the caller's choice.

    The first version of this shared helper resolved the cwd once, as of the
    END of the line - and handed that to expanded_operands, which needs the
    directory in force AT ITS SEGMENT. So

        cd build && rm -rf ./out            preview: build/out   correct
        cd build && rm -rf ./out && cd ..   preview: (nothing)   WRONG

    The trailing `cd` moved the end-of-line cwd, `./out` resolved against the
    wrong directory, the exists() filter dropped it, and the preview said "no
    files affected" for a deletion that was about to happen - the exact lie
    F12 was written to remove, reintroduced by its own fix (2026-09-09).

    Note the shape of that failure: because the operand list is filtered by
    exists(), a WRONG BASE can never surface as a wrong path. It can only
    surface as a missing one. Silence is the only symptom this bug has.

    `base` is None when nothing moved - the overwhelming majority - so callers
    take exactly the path they took before. `ok` is False only when a `cd`
    exists and cannot be modelled.
    """
    if not moved:
        return None, True
    here = effective_cwd(cmd, segments, index)
    if here is None:
        return None, False
    if os.path.normpath(here) == os.path.normpath(os.getcwd()):
        return None, True
    return here, True


def unignorable_dirs(cmd: str, dialect: str = POSIX) -> frozenset:
    """Ignored directory names this command explicitly reaches into.

    IGNORED_DIRS keeps `.git`, `node_modules` and `__pycache__` out of a
    directory snapshot, because copying them on every rm is expensive and they
    are usually reconstructible. That reasoning holds right up until the
    command NAMES something inside one:

        rm proj/.git/config proj/src/a.py

    collapses to `proj`, snapshots it without `.git`, and reports REVERSIBLE.
    The snapshot contains src/a.py and nothing else; `undo` restores half the
    damage and says nothing about the other half. The entry is
    indistinguishable from a complete capture - no field records the omission -
    which is what makes it a lie rather than a limitation. Found by review
    2026-09-08.

    So an ignore is a default, not a rule: a directory the command reaches
    into is captured after all. If that makes the capture exceed the size cap,
    snapshot() returns None and the command escalates, which is the honest
    outcome and needs no extra code.

    `.demo_cli` and `.demo_cli_recovery` are NEVER returned. Un-ignoring the
    recovery store would copy the backup into the backup, and `rm
    .demo_cli/something` is a request to delete recovery points, not a reason
    to duplicate them.
    """
    segments, moved = _operand_context(cmd, dialect)
    # End of the line on purpose: "does this command reach into an ignored
    # directory ANYWHERE" is a whole-line question, unlike the two callers
    # below which care about one segment's view.
    base, ok = _base_at(cmd, segments, len(segments), moved)
    if not ok:
        return frozenset()              # cannot tell where it points; do not guess

    hit = set()
    for seg in segments:
        for op in _path_operands(seg, base):
            parts = set(os.path.abspath(op).split(os.sep))
            hit |= (IGNORED_DIRS & parts)
    return frozenset(hit - {".demo_cli", ".demo_cli_recovery"})


def is_fs_delete(cmd: str) -> bool:
    """True if cmd is a local filesystem delete/move whose target THIS module
    resolves by operand extraction (rm / mv / PowerShell Remove-Item). Used by
    the guard to refuse a partial .db-name capture for such a command (#004)."""
    return bool(_RM_RE.search(cmd) or _MV_RE.search(cmd) or _PS_REMOVE_RE.search(cmd))


def is_remote_pg(ref: str) -> bool:
    """True if a Postgres connection string points somewhere other than the
    local machine. A pg_dump over the wire is not a recovery point we can stand
    behind for a system we do not control, so the orchestrator escalates these
    honestly rather than claiming reversibility."""
    try:
        from urllib.parse import urlparse
        host = (urlparse(ref).hostname or "").lower()
    except Exception:
        return False
    return host not in ("", "localhost", "127.0.0.1", "::1")


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


def _contains(outer: str, inner: str) -> bool:
    """Is `inner` at or underneath `outer`? Absolute, normalised, and it never
    raises - commonpath throws on paths from different drives, which on
    Windows is a legitimate answer of "no", not an error."""
    try:
        outer, inner = os.path.abspath(outer), os.path.abspath(inner)
        return outer == inner or os.path.commonpath([outer, inner]) == outer
    except ValueError:
        return False


def _dir_size(path: str, cap: int, ignore_dirs=None, skip_path=None) -> int:
    """Sum file sizes under `path`, ignoring the same noise as the copy, and
    short-circuiting as soon as `cap` is exceeded (so we never walk a huge tree
    just to find out it is huge).

    `ignore_dirs` MUST be whatever the copy will skip. If the measurement
    excludes a directory the copy then includes, the cap check passes and the
    copy is unbounded - which is how a "256 MB cap" quietly copies gigabytes.
    checkpoint.py keeps .git, so it passes its own set.

    Until 2026-08-24 this held a hardcoded duplicate of IGNORED_DIRS, exactly
    the drift the comment on that constant warns about.
    """
    ignore = IGNORED_DIRS if ignore_dirs is None else frozenset(ignore_dirs)
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignore
                   and not (skip_path and _contains(skip_path,
                                                    os.path.join(root, d)))]
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
            if total > cap:
                return total
    return total


def snapshot(target: Optional[Target], recovery_dir: str, strategy: str = "snapshot",
             action: Optional[str] = None, ignore_dirs=None) -> Optional[dict]:
    """Capture a recovery point for a target. Returns the recovery entry or None.

    `strategy` comes from config: "snapshot" captures; "none"/"attest" never
    capture (attestation of an externally managed recovery point is reserved
    for a later release and is treated as non-recoverable here, by design,
    rather than claiming a recovery we have not verified).

    `action` is the human-readable thing that prompted the snapshot (a command
    or a file-edit), stored on the entry so `demo_cli log` can show *why* each
    recovery point exists.
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
        if _dir_size(ref, cap, ignore_dirs, skip_path=skip) > cap:
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
