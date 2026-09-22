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

import functools
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
# Filesystem-operand extraction: identify targets for commands where operands
# are arguments (e.g. rm, mv) rather than flags.
# --------------------------------------------------------------------------

# Allow leading environment variable assignments (e.g. 'X=1 rm ...') before command words.
_ENV_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_RM_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?rm\b", re.I)
# In-place file writers: must take a path and match the classifier's writer rules.
_WRITER_CMD_RE = re.compile(
    r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?(?:"
    + "|".join(FILE_WRITER_TARGET_VERBS) + r")\b", re.I)


def _writer_hit(seg: str, _dialect: str) -> bool:
    return bool(_WRITER_CMD_RE.match(seg) and is_file_writer_command(seg))


_MV_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?mv\b", re.I)
_PS_REMOVE_RE = re.compile(r"^\s*Remove-Item\b", re.I)
# 'ri' alias is Remove-Item only under PowerShell.
_PS_REMOVE_ALIAS_RE = re.compile(rf"^\s*(?:{PS_REMOVE_ALIASES})\b", re.I)
_PS_REMOVE_ANY_RE = re.compile(
    rf"^\s*(?:Remove-Item|{PS_REMOVE_ALIASES})\b", re.I)


def _ps_remove_hit(seg: str, dialect: str) -> bool:
    return bool(_PS_REMOVE_RE.search(seg)
                or (dialect == POWERSHELL and _PS_REMOVE_ALIAS_RE.search(seg)))

# Brace expansion bounds: expand '{a,b}' and '{1..3}' bash-style before globbing.
# Bounded by _BRACE_MAX and _BRACE_MAX_DEPTH to avoid hangs on pathological input.
_BRACE_MAX = 1024
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
    """Recursive helper for _expand_braces. Returns None if expansion exceeds bounds.

    Computes suffix tails once per group (linear rather than exponential recursion)
    and propagates aborts up the call tree to avoid producing partial expansions.
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
            # Not expandable: keep this group literal, expand anything after it.
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
        # Bounded before building the product to prevent hangs.
        if total * len(tails) > _BRACE_MAX:
            return None
    return [pre + opt_x + tail
            for ex in expanded for opt_x in ex for tail in tails]


def _mv_target_dir(seg: str) -> Tuple[Optional[str], bool]:
    """Extract (target directory, ambiguous?) for `mv -t DIR src...`.

    When -t / --target-directory is used, destination is DIR rather than the last
    operand. Returns (dir, False) if found, (None, False) if absent, or
    (None, True) if an ambiguous flag cluster (e.g. -ft) cannot be safely split.
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


@functools.lru_cache(maxsize=512)
def _tokenize_cached(cmd: str, windows_paths: bool) -> Tuple[str, ...]:
    lex = shlex.shlex(cmd, posix=True)
    lex.whitespace_split = True          # split on whitespace, not shell punctuation
    if windows_paths:
        lex.escape = ""                  # backslash is a path separator, not an escape
    try:
        return tuple(lex)
    except ValueError:
        return tuple(cmd.strip().split())


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
    return list(_tokenize_cached(cmd, bool(windows_paths)))


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
    # Drop the bare command verb so it isn't treated as a path operand.
    if i < len(toks) and (toks[i] in ("rm", "mv")
                          or toks[i].lower() in FILE_WRITER_TARGET_VERBS):
        i += 1
    out: List[str] = []
    for tok in toks[i:]:
        if tok.startswith("-"):
            continue
        tok = tok.strip("'\"")
        # Expand user home directory '~' so operands match actual filesystem paths.
        tok = os.path.expanduser(tok)
        # 'base' is the effective working directory when 'cd' moved it.
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
    """Find the single segment in a multi-command line matching `rx`, or None.

    If exactly one segment matches (e.g. 'cd build && rm -rf ./out'), returns
    that segment. If zero or multiple segments match (e.g. 'rm a; rm b'), returns
    None to avoid partial snapshots and ensure honest escalation.
    """
    matches = [s for s in split_segments(cmd, dialect) if rx.search(s)]
    return matches[0] if len(matches) == 1 else None


def _ps_remove_item_operand(cmd: str) -> Optional[str]:
    """Extract single target operand for PowerShell Remove-Item, or None if ambiguous/wildcard."""
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
    r"""Resolve destination target that Move/Copy/Rename -Force will clobber.

    Resolves by flag (-Destination, -NewName) rather than purely positional order.
    -NewName is joined to the source's directory. Returns None if ambiguous or
    contains wildcards.
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


# Unexpanded shell tokens (variables, command substitutions, unclosed quotes/brackets).
# Tokens matching these cannot be safely resolved to a concrete path before execution.
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
    """Find the common directory containing all target paths for superset capture.

    Returns None if paths span multiple drives, contain unexpanded variables,
    or collapse to an overly broad directory (e.g. root or $HOME).
    """
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
    """Return concrete sorted list of existing paths affected by rm / mv in `cmd`.

    Evaluates operands per segment against the effective working directory so
    chained 'cd' commands resolve targets accurately.
    """
    pairs, moved = _operand_context(cmd, dialect)
    segments = [seg for seg, _ in pairs]
    seen, out = set(), []
    for index, seg in enumerate(segments):
        if not (_RM_RE.search(seg) or _MV_RE.search(seg)):
            continue
        base, ok = _base_at(cmd, segments, index, moved)
        if not ok:
            return []                   # unmodellable cd: nothing honest to show
        for path in _path_operands(seg, base):
            real = os.path.normpath(os.path.abspath(path))
            if real not in seen and os.path.exists(real):
                seen.add(real)
                out.append(real)
    return sorted(out)


def extract_path_operand(cmd: str, dialect: str = POSIX) -> Optional[str]:
    """Return the filesystem path a mutating command (rm, mv, writer) will affect, or None.

    Single paths return that path if it exists. Multiple paths that collapse into a
    single common parent directory return that directory for superset snapshotting.
    If targets cannot be collapsed to a single valid directory, returns None to escalate.
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

    # Multiplicity across rules: count destructive steps across all matchers and redirects.
    # If multiple distinct operations occur in one line, escalate to prevent partial recovery.
    def _rx(rx):
        return lambda seg, _d: bool(rx.search(seg))

    # Matchers: (does this segment act?, what is its target?).
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
        # Refuse relative target after a directory move if it cannot be verified.
        if target and moved and base and not os.path.isabs(target):
            return None
        return target

    # Truncating output redirection ('> file'): snapshot target if exactly one segment redirects.
    tgt, _ = resolve_redirect_target(cmd, dialect, moved=moved)
    if tgt:
        return tgt if os.path.exists(tgt) else None
    return None


def resolve_redirect_target(cmd: str, dialect: str = POSIX,
                            moved: Optional[bool] = None
                            ) -> Tuple[Optional[str], bool]:
    """Resolve the target path for a truncating output redirection (> file).

    Returns (absolute_path, True) if exactly one segment redirects to an expanded,
    resolvable target. Returns (None, False) if zero or multiple segments redirect,
    or if the redirection target contains unexpanded shell variables.
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
    """Compute simulated working directory up to segments[upto], or None if unmodellable.

    Folds sequential 'cd' commands. Returns None for constructs like CDPATH,
    pipes, subshells, pushd/popd, unexpanded variables, or non-existent directories.
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
    """True if any segment changes the working directory (cd, chdir, pushd, Set-Location)."""
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
    """Resolve (base_directory, ok) for the segment at `index`.

    Returns the simulated working directory active when the segment at `index` runs.
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
    """Return ignored directory names explicitly targeted by the command.

    If a command targets paths inside an ignored directory (e.g. proj/.git/config),
    that directory is included in the snapshot. Recovery directories (.demo_cli,
    .demo_cli_recovery) are never included.
    """
    pairs, moved = _operand_context(cmd, dialect)
    segments = [seg for seg, _ in pairs]
    # Check whole-line target paths for ignored directories
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
    """Return ignored directory names that lie at or under one of target `paths`.

    Ensures ignored directories destroyed as descendants of target paths are
    accounted for without unnecessary deep recursive traversals.
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

