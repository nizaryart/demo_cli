"""Target & operand resolution.

Resolves the real target of a command (SQLite, PostgreSQL, file, directory)
and parses command operands without modifying or executing anything.

The single most important property of this module is what it does *not* do:
it never falls back to a default target. If a destructive command's target
cannot be resolved to the thing it will actually affect, target resolution
returns None, the orchestrator captures nothing, and the decision is escalated.
That is how the "snapshot something unrelated and call it recovered" failure is
removed by construction.
"""
from __future__ import annotations

import glob as _glob
import ntpath
import os
import re
import shlex
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .classify import (FILE_WRITER_TARGET_VERBS, POSIX, POWERSHELL,
                       PS_CLEAR_CONTENT_ALIASES,
                       PS_COPY_ALIASES, PS_MOVE_ALIASES, PS_NEW_ITEM_ALIASES,
                       PS_REMOVE_ALIASES, PS_RENAME_ALIASES,
                       effective_command, effective_segments,
                       is_file_writer_command,
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
# on it, and copytree derives its exclusion list from it in recovery.py. Three
# separate copies had already drifted apart before this was unified; adding an
# entry must fix every platform at once, not one of them.
IGNORED_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".demo_cli", ".demo_cli_recovery",
})


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
# An in-place writer POINTED AT a path. Two conditions, deliberately: the
# command word must be one that takes a path (so npm/pip are excluded), AND
# the segment must match the classifier's own writer rule (so a read without
# --write is not counted as an action).
_WRITER_CMD_RE = re.compile(
    r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?(?:"
    + "|".join(FILE_WRITER_TARGET_VERBS) + r")\b", re.I)


def _writer_hit(seg: str, _dialect: str) -> bool:
    return bool(_WRITER_CMD_RE.match(seg) and is_file_writer_command(seg))


_MV_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?mv\b", re.I)
_PS_REMOVE_RE = re.compile(r"^\s*Remove-Item\b", re.I)
# `ri` is Remove-Item in PowerShell and Ruby's documentation viewer on POSIX.
# classify.py gates the matching rule the same way; if these two disagree, one
# module calls a command a deletion while the other looks for its target in
# text that does not describe one.
_PS_REMOVE_ALIAS_RE = re.compile(rf"^\s*(?:{PS_REMOVE_ALIASES})\b", re.I)
_PS_REMOVE_ANY_RE = re.compile(
    rf"^\s*(?:Remove-Item|{PS_REMOVE_ALIASES})\b", re.I)


def _ps_remove_hit(seg: str, dialect: str) -> bool:
    return bool(_PS_REMOVE_RE.search(seg)
                or (dialect == POWERSHELL and _PS_REMOVE_ALIAS_RE.search(seg)))

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
    # DROPPING THE COMMAND WORD IS WHAT MAKES THE REST OF THIS WORK, and it
    # was a two-element tuple. Everything else kept its verb as a phantom
    # operand, so `black app.py` counted TWO paths and collapsed to a common
    # root instead of naming the file - while the flag skipping below already
    # handled --write and -w for free. The generic machinery was all here;
    # this line was the gate.
    #
    # Only a BARE verb is recognised. `./node_modules/.bin/prettier a.js`
    # keeps its command word and still collapses - a stated miss, not a
    # claim.
    if i < len(toks) and (toks[i] in ("rm", "mv")
                          or toks[i].lower() in FILE_WRITER_TARGET_VERBS):
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
    if not _PS_REMOVE_ANY_RE.search(cmd):
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
_PS_CONTENT_RE = re.compile(
    r"^\s*(?:Clear-Content|Set-Content|Out-File|New-Item)\b", re.I)
_PS_CONTENT_ALIAS_RE = re.compile(
    rf"^\s*(?:{PS_CLEAR_CONTENT_ALIASES}|{PS_NEW_ITEM_ALIASES})\b", re.I)
_PS_DEST_RE = re.compile(r"^\s*(?:Move-Item|Copy-Item|Rename-Item)\b", re.I)
# `cp`, `copy` and `move` are ordinary POSIX commands, and this matcher feeds
# the multiplicity counter - counting `cp a b` as a destructive step on POSIX
# would escalate an ordinary `rm x; cp a b`. Hence the gate, not a wider regex.
_PS_DEST_ALIAS_RE = re.compile(
    rf"^\s*(?:{PS_MOVE_ALIASES}|{PS_COPY_ALIASES}|{PS_RENAME_ALIASES})\b", re.I)


def _ps_content_hit(seg: str, dialect: str) -> bool:
    return bool(_PS_CONTENT_RE.search(seg)
                or (dialect == POWERSHELL and _PS_CONTENT_ALIAS_RE.search(seg)))


def _ps_dest_hit(seg: str, dialect: str) -> bool:
    return bool(_PS_DEST_RE.search(seg)
                or (dialect == POWERSHELL and _PS_DEST_ALIAS_RE.search(seg)))


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
_PS_RENAME_RE = re.compile(
    rf"^\s*(?:Rename-Item|{PS_RENAME_ALIASES})\b", re.I)
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
    return ntpath.dirname(path) if "\\" in path else os.path.dirname(path)


def _win_aware_join(head: str, tail: str, flavour_of: str = "") -> str:
    r"""join(), choosing the separator from `flavour_of` rather than from head.

    The head of "proj\old.txt" is "proj", which carries no backslash - so
    deciding on the head produced "proj/b.txt" for a Windows command. The
    original operand is the thing that knows which flavour of path this is.
    """
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
    `Copy-Item -Destination keep\b.txt -Path a.txt` resolved to the SOURCE.

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


def ps_named_target(cmd: str,
                    dialect: str = POSIX) -> Tuple[Optional[str], bool]:
    r"""(absolute path, resolved?) for a PowerShell write or clobber.

    Same contract and same shape as resolve_redirect_target, deliberately: two
    functions answering "what does this command touch" with two conventions is
    how three modules came to disagree and cost a silent data loss.

    The docstring here already said the rule - "a name that does not resolve at
    all is ambiguous and must still escalate" - and the code returned a bare
    string, so the guard could not tell an unresolvable name from a resolvable
    one that is merely absent. `Set-Content -Path $env:APPDATA\notes.txt` came
    back as that literal, os.path.exists said no, and the guard read it as
    creation and cleared the flag. The third comment/code contradiction found
    in this review, and the last place the contract was missing.

    Existence is still NOT checked here: resolved-and-absent means "creates"
    and only the caller can act on that. Resolved means "we know which file",
    nothing more.
    """
    if _ps_content_hit(cmd, dialect):
        named = _ps_write_target(cmd)
    elif _ps_dest_hit(cmd, dialect):
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
    pairs, moved = _operand_context(cmd, dialect)
    segments = [seg for seg, _ in pairs]
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
    pairs, moved = _operand_context(cmd, dialect)
    segments = [seg for seg, _ in pairs]
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
    def _rx(rx):
        return lambda seg, _d: bool(rx.search(seg))

    # (does this segment act?, what is its target?). A matcher takes the
    # segment AND its dialect, because `ri` only means Remove-Item in one.
    # The writer row reuses _rm UNCHANGED: one operand -> that path, several
    # -> their common capture root. That is already exactly a formatter's
    # semantics, so `prettier --write src/` snapshots src/ and
    # `black a.py b.py` snapshots the directory holding both.
    _MATCHERS = ((_rx(_RM_RE), _rm),
                 (_rx(_MV_RE), _mv),
                 (_writer_hit, _rm),
                 (_ps_remove_hit, _existing(_ps_remove_item_operand)),
                 (_ps_content_hit, _existing(_ps_write_target)),
                 (_ps_dest_hit, _existing(_ps_dest_target)))

    acting = {i for i, (seg, d) in enumerate(pairs)
              if any(m(seg, d) for m, _ in _MATCHERS) or redirect_target(seg)}
    if len(acting) > 1:
        return None

    for match, handler in _MATCHERS:
        hits = [(i, seg) for i, (seg, d) in enumerate(pairs) if match(seg, d)]
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


def _operand_context(cmd: str,
                     dialect: str = POSIX) -> Tuple[List[Tuple[str, str]], bool]:
    """([(segment, its dialect)], does anything move the working directory?).

    The dialect is per SEGMENT, not per line: `powershell -c "ri x"` run from
    bash is a PowerShell segment inside a POSIX command, and the `ri` alias is
    only Remove-Item in the former.
    """
    pairs = list(effective_segments(cmd, dialect, substitute=True)) or [(cmd, dialect)]
    return pairs, _changes_directory([seg for seg, _ in pairs])


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
    pairs, moved = _operand_context(cmd, dialect)
    segments = [seg for seg, _ in pairs]
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


def ignored_dirs_under(paths) -> frozenset:
    """Ignored directory names that lie AT OR UNDER one of `paths`.

    unignorable_dirs answers one direction - an operand INSIDE an ignored
    directory, `rm proj/.git/config`. This answers the ANCESTOR direction,
    which that question cannot see:

        rm -rf proj        destroys proj/.git and proj/node_modules
                           completely while naming nothing ignored at all

    So the name-based set came back empty, the ignore list stayed in force,
    and the capture was a strict SUBSET reported REVERSIBLE - 3 files of 7,
    with no field on the entry recording the omission and `undo` exiting 0.
    Exactly the failure unignorable_dirs was written to stop, arriving from
    the opposite side. Measured 2026-09-17.

    DELIBERATELY NOT "everything under the capture root". Several scattered
    operands collapse to a common root they do NOT destroy -
    `rm proj/src/a.py proj/other/c.py` resolves to `proj` - and lifting the
    ignore there would copy .git on a two-file delete, which is the cost the
    ignore list exists to avoid. Only a directory inside the actual blast
    radius is lifted.

    Never descends INTO an ignored directory: the NAME is the answer, not
    the contents, and walking node_modules to discover it is node_modules
    would cost what this is trying to bound. Stops early once every
    candidate is found.

    .demo_cli / .demo_cli_recovery are never returned, matching
    unignorable_dirs.
    """
    candidates = IGNORED_DIRS - {".demo_cli", ".demo_cli_recovery"}
    hit = set()
    for path in paths or ():
        try:
            if not os.path.isdir(path):
                continue
            base = os.path.basename(os.path.abspath(path).rstrip(os.sep))
            if base in candidates:
                hit.add(base)
            for _dirpath, dirnames, _files in os.walk(path):
                hit |= candidates & set(dirnames)
                dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
                if hit == candidates:
                    break
        except OSError:
            continue
        if hit == candidates:
            break
    return frozenset(hit)


def is_fs_delete(cmd: str, dialect: str = POSIX) -> bool:
    """True if cmd is a local filesystem delete/move whose target THIS module
    resolves by operand extraction (rm / mv / PowerShell Remove-Item). Used by
    the guard to refuse a partial .db-name capture for such a command (#004)."""
    return any(
        bool(_RM_RE.search(s) or _MV_RE.search(s) or _ps_remove_hit(s, dialect))
        for s in split_segments(cmd, dialect) or [cmd]
    )


def is_remote_pg(ref: str) -> bool:
    """True if a Postgres connection string points somewhere other than the
    local machine. A pg_dump over the wire is not a recovery point we can stand
    behind for a system we do not control, so the orchestrator escalates these
    honestly rather than claiming reversibility."""
    try:
        host = (urlparse(ref).hostname or "").lower()
    except Exception:
        return False
    return host not in ("", "localhost", "127.0.0.1", "::1")

