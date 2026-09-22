"""Command classification.

Pure, dependency-free. Given a (possibly chained / piped) command string,
decide what kind of action it is: destructive, mutating, a safe read, an
opaque remote fetch-and-run, or a mutation of a surface that a local snapshot
cannot cover (external side effects, credentials, migrations, ...).

Classification never decides what to *do* - that is `decide.py`. It only
describes the command. The regex rules here encode real failure modes raised
by users during the validation sprint (piped/chained commands hiding a
destructive step, formatters rewriting whole trees, curl | bash).
"""
from __future__ import annotations

import functools
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------
# Shell dialects
# --------------------------------------------------------------------------
POSIX = "posix"
POWERSHELL = "powershell"

# --------------------------------------------------------------------------
# Rule tables
# --------------------------------------------------------------------------

# SQL statement shapes shared by destructive rules, _SQL_MUTATING, and preview.
_SQL_TRUNCATE_RX = (
    # Match TRUNCATE TABLE or bare TRUNCATE at statement end.
    r"\bTRUNCATE\s+TABLE\b"
    r"|\bTRUNCATE\s+[\w.\"`\[\]]+\s*(?:;|$)"
)
# Match DELETE FROM to avoid matching ordinary prose.
_SQL_DELETE_RX = r"\bDELETE\s+FROM\b"
_SQL_UPDATE_RX = r"\bUPDATE\s+[\w.\"`\[\]]+\s+SET\b"
_SQL_DDL_RX = (
    r"\b(?:DROP|ALTER|CREATE)\s+"
    r"(?:TEMP(?:ORARY)?\s+|UNIQUE\s+|MATERIALIZED\s+|OR\s+REPLACE\s+)*"
    r"(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|TRIGGER|FUNCTION|"
    r"PROCEDURE|ROLE|USER|EXTENSION|TYPE)\b"
)
_SQL_INSERT_RX = r"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\b|\bREPLACE\s+INTO\b"

# PowerShell aliases shared with recovery.py.
PS_REMOVE_ALIASES = "ri|del|erase|rd|rmdir"
PS_COPY_ALIASES = "cpi|copy|cp"
PS_MOVE_ALIASES = "mi|move"
PS_RENAME_ALIASES = "ren|rni"
PS_NEW_ITEM_ALIASES = "ni"
PS_CLEAR_CONTENT_ALIASES = "clc"
PS_STOP_SERVICE_ALIASES = "spsv"

# Mutating sc.exe verbs (query operations are excluded; failureflag precedes failure).
_SC_WRITE_VERBS = (
    "delete|config|create|sdset|failureflag|failure|privs|sidtype"
    "|description|triggerinfo|preferrednode|managedaccount|boot|stop"
)

# (rule_id, action_type, pattern). First match wins, order matters.
_DESTRUCTIVE_RULES = [
    ("sql_drop", "sql", r"\bDROP\s+(?:DATABASE|TABLE|SCHEMA)\b"),
    ("sql_truncate", "sql", _SQL_TRUNCATE_RX),
    ("sql_delete", "sql", _SQL_DELETE_RX),
    ("tf_destroy", "infra", r"\bterraform\s+destroy\b"),
    # Matches cluster state deletion operations.
    ("kubectl_delete", "infra", r"\bkubectl\s+delete\b"),
    ("cloud_delete", "infra", r"\b(?:aws|gcloud|az)\b[\w\s.-]*\b(?:delete|terminate|destroy|rb)\b"),
    ("railway_drop", "infra", r"railway\s+run.*production.*(?:DROP|DELETE|TRUNCATE)"),
    ("railway_vol_del", "infra", r"railway\s+volume\s+delete"),
    # ---- Service and account control -------------------------------------
    # SCM and account modifications (unrecoverable state changes).
    ("service_control", "system",
     rf"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:{_SC_WRITE_VERBS})\b"),
    ("service_control", "system",
     r"\b(?:Stop-Service|Remove-Service|Set-Service|New-Service"
     r"|Suspend-Service|Restart-Service)\b"),
    ("service_control", "system",
     rf"^\s*(?:{PS_STOP_SERVICE_ALIASES})\b", POWERSHELL),
    ("service_control", "system",
     r"\bnet\s+stop\b"
     r"|\bsystemctl\b[^|;&]*\s(?:stop|disable|mask|kill)\b"
     r"|\bservice\s+\S+\s+stop\b"),
    # Account and share modifications.
    ("account_control", "system",
     r"\bnet\s+(?:user|localgroup)\b[^|;&]*\s/(?:delete|add)\b"
     r"|\bnet\s+share\b[^|;&]*\s/delete\b"
     r"|\b(?:userdel|groupdel|deluser|delgroup)\b"),
    ("git_force_push", "git", r"\bgit\s+push\b.*(?:--force|-f)\b"),
    ("git_reset_hard", "git", r"\bgit\s+reset\s+--hard\b"),
    # rm with recursive and force (-rf / -fr), excluding container runtimes covered elsewhere.
    ("rm_rf", "shell",
     r"(?<!docker )(?<!podman )\brm\b"
     r"(?=[^|;&]*\b-?[a-z]*r[a-z]*\b)(?=[^|;&]*\b-?[a-z]*f[a-z]*\b)[^|;&]*"),
    # Top-level rm invocations (allowing leading env var assignments and sudo).
    ("rm_local", "shell", r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?rm\b[^|;&]*"),
    # PowerShell Remove-Item with both -Recurse and -Force flags (in any order or abbreviation).
    ("ps_remove_item_rf", "shell",
     r"\bRemove-Item\b(?=[^|;&]*\s-r[a-z]*\b)(?=[^|;&]*\s-f[a-z]*\b)[^|;&]*"),
    # Alias twin, PowerShell only.
    ("ps_remove_item_rf", "shell",
     rf"\b(?:{PS_REMOVE_ALIASES})\b(?=[^|;&]*\s-r[a-z]*\b)"
     rf"(?=[^|;&]*\s-f[a-z]*\b)[^|;&]*", POWERSHELL),
    # Top-level Remove-Item invocations (recoverable single file/dir targets).
    ("ps_remove_item", "shell", r"^\s*Remove-Item\b[^|;&]*"),
    # ---- PowerShell content destroyers -----------------------------------
    # Truncation and overwrite operations (-Force required for move/copy/rename; append excluded).
    ("ps_clear_content", "shell", r"^\s*Clear-Content\b[^|;&]*"),
    ("ps_clear_content", "shell",
     rf"^\s*(?:{PS_CLEAR_CONTENT_ALIASES})\b[^|;&]*", POWERSHELL),
    ("ps_set_content", "shell",
     r"^\s*(?:Set-Content|Out-File)\b(?![^|;&]*\s-(?:Append|NoClobber)\b)[^|;&]*"),
    ("ps_move_force", "shell", r"^\s*Move-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_move_force", "shell",
     rf"^\s*(?:{PS_MOVE_ALIASES})\b(?=[^|;&]*\s-Force\b)[^|;&]*", POWERSHELL),
    ("ps_copy_force", "shell", r"^\s*Copy-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_copy_force", "shell",
     rf"^\s*(?:{PS_COPY_ALIASES})\b(?=[^|;&]*\s-Force\b)[^|;&]*", POWERSHELL),
    ("ps_rename_force", "shell", r"^\s*Rename-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_rename_force", "shell",
     rf"^\s*(?:{PS_RENAME_ALIASES})\b(?=[^|;&]*\s-Force\b)[^|;&]*", POWERSHELL),
    ("ps_new_item_force", "shell", r"^\s*New-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_new_item_force", "shell",
     rf"^\s*(?:{PS_NEW_ITEM_ALIASES})\b(?=[^|;&]*\s-Force\b)[^|;&]*", POWERSHELL),
    # Whole-volume operations (non-recoverable).
    ("ps_format_volume", "shell", r"\b(?:Format-Volume|Clear-Disk)\b"),
    ("rmdir_s", "shell", r"\brmdir\b.*\/[sS]"),
    ("del_force", "shell", r"\bdel\b.*\/[fFsS]"),
    # PowerShell del/erase/rd/rmdir aliases without flags (cmd.exe rules above take precedence).
    ("ps_remove_item", "shell",
     rf"^\s*(?:{PS_REMOVE_ALIASES})\b[^|;&]*", POWERSHELL),
    ("mv_overwrite", "shell", r"\bmv\s+(?:-[a-z]*f[a-z]*\s+)?\S+\s+\S+"),
    # Local data destroyers (snapshotted when target is resolvable, escalated otherwise).
    ("fs_shred", "shell", r"\bshred\b"),
    ("fs_truncate", "shell", r"\btruncate\b[^|;&]*\s-s\b"),
    ("fs_dd_of", "shell", r"\bdd\b[^|;&]*\bof=\S+"),
    # Whole-device filesystem format (non-recoverable).
    ("fs_mkfs", "shell", r"\bmkfs(?:\.\w+)?\b"),
    ("fs_find_delete", "shell", r"\bfind\b[^|;&]*\s-delete\b"),
    ("git_clean", "git", r"\bgit\s+clean\b[^|;&]*-[a-z]*d"),
    # Destructive git actions (history rewrites, discarding uncommitted work, reflog expiry).
    ("git_worktree_remove", "git", r"\bgit\s+worktree\s+remove\b[^|;&]*(?:--force|\s-f)\b"),
    # Case-sensitive -D or explicit force delete (-d -f / --delete --force).
    ("git_branch_delete", "git",
     r"\bgit\s+branch\b(?:[^|;&]*\s(?-i:-\w*D\w*)\b"
     r"|(?=[^|;&]*\s(?:--delete|-d)\b)(?=[^|;&]*\s(?:--force|-f)\b)[^|;&]*)"),
    ("git_checkout_discard", "git", r"\bgit\s+checkout\b[^|;&]*?(?:\s--\s|\s\.(?:\s|$))"),
    ("git_restore", "git", r"\bgit\s+restore\b"),
    ("git_stash_drop", "git", r"\bgit\s+stash\s+(?:drop|clear)\b"),
    # Stash drop/pop operations that consume stashes.
    ("git_stash_pop", "git", r"\bgit\s+stash\s+pop\b"),
    ("git_reflog_expire", "git", r"\bgit\s+reflog\s+expire\b"),
    ("git_gc_prune", "git", r"\bgit\s+gc\b[^|;&]*--prune=\S+"),
    ("git_filter_branch", "git", r"\bgit\s+filter-(?:branch|repo)\b"),
    ("git_update_ref_delete", "git", r"\bgit\s+update-ref\s+-d\b"),
]
# Optional 4th tuple element gates eligibility to a specific shell dialect (e.g. POWERSHELL).
_DESTRUCTIVE = [(r[0], r[1], re.compile(r[2], re.I | re.S),
                 r[3] if len(r) > 3 else None) for r in _DESTRUCTIVE_RULES]

# Destructive rules with remote/external blast radius that cannot be covered by local snapshots.
_EXTERNAL_IRREVERSIBLE = {
    "tf_destroy": "infra_destroy",
    "kubectl_delete": "cluster_resource_delete",
    "cloud_delete": "cloud_resource_delete",
    "railway_drop": "remote_database",
    "railway_vol_del": "remote_volume",
    "git_force_push": "remote_vcs_history",
}

# Local destructive commands that cannot be reliably snapshotted (escalated across all environments).
_LOCAL_UNRECOVERABLE = {
    "service_control": "service_control",
    "account_control": "account_control",
    "rmdir_s": "recursive_force_delete",
    "del_force": "recursive_force_delete",
    "fs_mkfs": "disk_format",
    "ps_format_volume": "disk_format",
}

# Opaque remote execution (payload unknown before execution).
_REMOTE_EXEC = re.compile(
    r"(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?|node|ruby|perl)\b"
    r"|base64\s+-d[^|]*\|\s*(?:bash|sh)\b"
    r"|\beval\b"
    r"|\|\s*(?:bash|sh)\s+-c\b"
    # Dynamic one-liner interpreter execution that cannot be pre-inspected.
    r"|\bpython\d?\s+-c\b[^|]*(?:os\.system|os\.popen|subprocess|__import__|\beval\b|\bexec\b|pty\.spawn|commands\.get)",
    re.I,
)

# Tools that mutate files indirectly (formatters, generators, package managers).
_FILE_WRITERS = re.compile(
    r"\bprettier\b[^|;&]*--write"
    r"|\beslint\b[^|;&]*--fix"
    # Formatters write by default unless --check/--diff is present (gofmt requires -w).
    r"|\b(?:black|isort|rustfmt)\b(?![^|;&]*\s--?(?:check|diff))"
    r"|\bgofmt\b[^|;&]*\s-w\b"
    r"|\b(?:npm|yarn|pnpm)\s+(?:install|add|remove|i)\b"
    r"|\bpip\s+install\b"
    r"|\b(?:npx|node)\b[^|;&]*(?:codegen|generate|migrate)\b",
    re.I,
)

# Non-recoverable external surfaces (escalated; snapshots cannot cover).
# Permitted command prefix: leading NAME=value environment assignments and optional sudo.
_CMD_PREFIX = r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?"

_NONRECOVERABLE_SURFACES = [
    ("external_email", r"\b(sendgrid|mailgun|ses\s+send-email|smtp)\b|\bmail\s+-s\b"),
    ("external_payment", r"\b(stripe|paypal|braintree)\b[^|;&]*\b(charge|refund|payout|capture)\b"),
    ("external_message", r"\b(slack|discord|twilio)\b[^|;&]*\b(post|send|message|webhook)\b"
                         r"|hooks\.slack\.com|chat\.postMessage"),
    ("vcs_remote_state", r"\b(gh|hub)\s+(pr|issue|release)\s+(close|merge|delete|create)\b"
                         r"|\bgh\s+repo\s+delete\b|\bgh\s+api\b[^|;&]*-X\s*(?:DELETE|PUT)\b"),
    # HTTP mutating requests (DELETE/PUT/PATCH).
    ("http_api_write", r"\b(?:curl|wget|xh|http(?:ie)?)\b[^|;&]*"
                       r"\s(?:-X\s*|--request[= ])(?:DELETE|PUT|PATCH)\b"),
    ("credential_rotation", r"\brotat(?:e|ing)\b[^|;&]*\b(key|secret|credential|token)\b"
                            r"|\b(?:aws\s+iam|gcloud\s+iam|az\s+role)\b"),
    ("secret_write", r"\b(vault|aws\s+secretsmanager|aws\s+ssm)\b[^|;&]*\b(put|write|delete|set)\b"),
    ("object_storage", r"\b(?:aws\s+s3|gsutil|az\s+storage\s+blob)\b[^|;&]*\b(rm|delete|rb)\b"),
    ("message_queue", r"\b(?:aws\s+sqs|rabbitmqadmin|kafka-topics)\b[^|;&]*\b(purge|delete)\b"),
    ("remote_filesystem", r"\bssh\b[^|;&]*\brm\b|\brsync\b[^|;&]*--delete\b"),
    ("schema_migration", r"\b(alembic|flyway|liquibase|prisma\s+migrate|knex\s+migrate|sequelize\s+db:migrate)\b"
                         r"|\brails\s+db:migrate\b|\bmanage\.py\s+migrate\b"),
    # Content / deploy SaaS CLIs (destructive subcommands only).
    ("saas_deploy", r"\bshopify\s+theme\s+(?:push|delete)\b"
                    r"|\bvercel\s+(?:remove|rm)\b|\bvercel\b[^|;&]*--prod\b"
                    r"|\bnetlify\s+deploy\b[^|;&]*--prod\b|\bnetlify\s+sites:delete\b"
                    r"|\bfirebase\s+(?:hosting:disable|firestore:delete)\b"
                    r"|\bwrangler\b[^|;&]*\bdelete\b"),
    ("saas_cms", r"\bwp\s+(?:db\s+(?:reset|drop)|site\s+empty|post\s+delete|user\s+delete|option\s+delete)\b"
                 r"|\bcontentful\s+space\s+delete\b|\bcontentful\b[^|;&]*\bentry\b[^|;&]*\bdelete\b"),
    ("paas_destroy", r"\bheroku\s+(?:apps:destroy|pg:reset)\b"
                     r"|\bsupabase\s+db\s+reset\b"
                     r"|\bfly(?:ctl)?\s+(?:apps\s+destroy|destroy)\b"),

    # Container runtime destruction (volumes, images, containers, networks).
    ("container_runtime",
     _CMD_PREFIX + r"(?:docker|podman)(?:-compose)?\s+(?:"
     r"(?:rm|rmi)\b"
     r"|(?:volume|image|container|network|system|builder)\s+(?:rm|prune)\b"
     r"|(?:compose\s+)?down\b[^|;&]*\s--?v(?:olumes)?\b"
     r")"),

    # Datastore flush operations.
    ("datastore_flush", _CMD_PREFIX + r"redis-cli\b[^|;&]*\bflush(?:all|db)\b"),

    # Package registry removal (irreversible policy).
    ("package_registry",
     _CMD_PREFIX + r"(?:(?:npm|pnpm|yarn)\s+unpublish\b|cargo\s+yank\b|gem\s+yank\b)"),
]
_NONRECOVERABLE = [(label, re.compile(rx, re.I)) for label, rx in _NONRECOVERABLE_SURFACES]

# Writers that modify the explicit path operand they target (shared with recovery.py).
FILE_WRITER_TARGET_VERBS = ("prettier", "eslint", "black", "isort",
                            "gofmt", "rustfmt")

_SQL_READ = re.compile(r"^\s*SELECT\b", re.I)

# Mutating SQL statements matching statement grammar.
_SQL_MUTATING = re.compile(
    f"{_SQL_DELETE_RX}|{_SQL_INSERT_RX}|{_SQL_UPDATE_RX}"
    f"|(?:{_SQL_TRUNCATE_RX})|{_SQL_DDL_RX}",
    re.I,
)
_SQL_DELETE = re.compile(_SQL_DELETE_RX, re.I)
_SQL_UPDATE = re.compile(_SQL_UPDATE_RX, re.I)
_SQL_TRUNCATE = re.compile(_SQL_TRUNCATE_RX, re.I)


# --------------------------------------------------------------------------
# Pipeline splitting
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Shell dialects
# --------------------------------------------------------------------------
# Line continuation characters per dialect (backslash for POSIX, backtick for PowerShell).
_CONTINUATION = {POSIX: "\\", POWERSHELL: "`"}


_PS_ESCAPE_SEQUENCES = "nrt0abfv"       # only meaningful inside "double quotes"


def strip_ps_escapes(cmd: str) -> str:
    """Remove PowerShell backtick character-escapes outside double quotes:
        Remo`ve-Item x   ->   Remove-Item x
    Preserves recognized escape sequences (`n, `t, etc.) inside double quotes.
    """
    out: List[str] = []
    in_single = in_double = False
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "`" and not in_single and i + 1 < n:
            nxt = cmd[i + 1]
            if in_double and nxt in _PS_ESCAPE_SEQUENCES:
                out.append(ch)              # a real escape sequence: keep it
                out.append(nxt)
                i += 2
                continue
            out.append(nxt)                 # literal next character
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def join_continuations(cmd: str, dialect: str = POSIX) -> str:
    """Fold a multi-line command back into a single line across line continuations
    (\\ for POSIX, ` for PowerShell). Normalizes CRLF to LF.
    """
    cmd = cmd.replace("\r\n", "\n")
    ch = _CONTINUATION.get(dialect, "\\")
    out: List[str] = []
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == ch:
            # Continuation at end of line: skip blanks, require newline.
            j = i + 1
            while j < n and cmd[j] in " \t":
                j += 1
            if j < n and cmd[j] == "\n":
                out.append(" ")          # keep a word boundary where the join was
                i = j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# Same-line variable substitution
# Resolves in-line variable assignments within the same command string.
# --------------------------------------------------------------------------

# NAME=value assignment (optionally exported) at line start or after separator.
_POSIX_ASSIGN = re.compile(
    r"""(?:^|(?<=[;&|]))\s*(?:export\s+)?
        ([A-Za-z_]\w*)=("[^"]*"|'[^']*'|[^\s;&|<>]*)""",
    re.VERBOSE)
# PowerShell $name = value assignment (including $env:).
_PS_ASSIGN = re.compile(
    r"""(?:^|(?<=[;|]))\s*
        \$((?:env:)?[A-Za-z_]\w*)\s*=\s*("[^"]*"|'[^']*'|[^\s;|<>]+)""",
    re.VERBOSE)

_POSIX_REF = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_PS_REF = re.compile(r"\$\{((?:env:)?[A-Za-z_]\w*)\}|\$((?:env:)?[A-Za-z_]\w*)")

_ASSIGN = {POSIX: _POSIX_ASSIGN, POWERSHELL: _PS_ASSIGN}
_REF = {POSIX: _POSIX_REF, POWERSHELL: _PS_REF}

# Disallow substitution values containing command substitutions, operators, or redirects.
_UNSAFE_VALUE = re.compile(r"[$`;&|<>\n]")


def _assignment_survives(cmd: str, end: int) -> bool:
    """Return False if the assignment was piped or backgrounded in a subshell."""
    rest = cmd[end:].lstrip(" \t")
    if rest.startswith("&&") or rest.startswith("||"):
        return True
    return not rest.startswith("&") and not rest.startswith("|")


def substitute_assignments(cmd: str, dialect: str = POSIX) -> str:
    """Resolve variables assigned earlier in the same command string.
    Returns the command unchanged unless all variable references resolve cleanly.
    """
    assign_re, ref_re = _ASSIGN.get(dialect), _REF.get(dialect)
    if not assign_re or "$" not in cmd:
        return cmd

    # Track assignments and skip left-hand assignment spans during substitution.
    values: List[tuple] = []          # (position, name, value)
    skip: List[tuple] = []            # (start, end) of assignment left-hand sides
    for m in assign_re.finditer(cmd):
        raw = m.group(2)
        skip.append((m.start(), m.start(2)))
        value = raw[1:-1] if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0] else raw
        if not value or _UNSAFE_VALUE.search(value):
            continue                  # refused: leave the name unknown
        if not _assignment_survives(cmd, m.end(2)):
            continue                  # ran in a subshell; the value is gone
        values.append((m.start(), m.group(1), value))

    if not values:
        return cmd

    resolved_all = True

    def replace(m):
        nonlocal resolved_all
        if any(a <= m.start() < b for a, b in skip):
            return m.group(0)         # this IS an assignment target
        name = m.group(1) or m.group(2)
        # Most recent assignment preceding this reference.
        latest = [v for pos, n, v in values if n == name and pos < m.start()]
        if not latest:
            resolved_all = False
            return m.group(0)
        return latest[-1]

    out = ref_re.sub(replace, cmd)
    return out if resolved_all else cmd


# --------------------------------------------------------------------------
# Nested shells
# Unwraps subshell commands (e.g. bash -c, powershell -Command, cmd /c).
# --------------------------------------------------------------------------

_POWERSHELL_EXE = re.compile(r"^\s*(?:[\w:.\\/ ()-]*[\\/])?(?:powershell|pwsh)(?:\.exe)?\b",
                             re.I)
_CMD_EXE = re.compile(r"^\s*(?:[\w:.\\/ ()-]*[\\/])?cmd(?:\.exe)?\s+/[ck]\b", re.I)
# Matches POSIX shells launching commands via clustered -c flags (-c, -lc, -cl, etc.).
_POSIX_SH = re.compile(
    r"^\s*(?:[\w./-]*/)?(?:bash|sh|dash|zsh)"
    r"(?:\s+(?:--[\w-]+|-[A-Za-z]+))*"
    r"\s+-[A-Za-z]*c[A-Za-z]*\b")

# PowerShell -Command and -EncodedCommand prefix abbreviations.
_PS_COMMAND_FLAG = re.compile(r"^-(?:c|co|com|comm|comma|comman|command)$", re.I)
_PS_ENCODED_FLAG = re.compile(r"^-(?:e|en|enc|enco|encod|encode|encoded|"
                              r"encodedcommand)$", re.I)

_MAX_NESTING = 3        # bounded: `a -c "b -c 'c -c ...'"` must terminate


def _strip_quotes(s: str) -> str:
    s = s.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


# Redirection tokens terminating nested command payload.
_REDIRECTION_TOKEN = re.compile(r"^\d*(?:>>|>|<)")


def _payload_tokens(toks: List[str]) -> str:
    """Extract script payload from -c / -Command arguments up to output redirection."""
    if not toks:
        return ""
    first = toks[0]
    quoted = len(first) >= 2 and first[0] in "\"'" and first[-1] == first[0]
    # Handle single quoted script token or fall through to concatenate tokens.
    if quoted and (len(toks) == 1 or _REDIRECTION_TOKEN.match(toks[1])):
        return _strip_quotes(first)
    out = []
    for tok in toks:
        if _REDIRECTION_TOKEN.match(tok):
            break
        out.append(tok)
    return _strip_quotes(" ".join(out))


def _decode_encoded(payload: str) -> Optional[str]:
    """Decode PowerShell -EncodedCommand base64 UTF-16LE / UTF-8 payload."""
    import base64
    try:
        raw = base64.b64decode(payload.strip(), validate=True)
    except Exception:
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text.isprintable() or "\n" in text:
            return text
    return None


def unwrap_nested(cmd: str) -> Optional[Tuple[str, str]]:
    """Unwrap one level of `<shell> -c <payload>`, returning (payload, dialect) or None."""
    if _POWERSHELL_EXE.match(cmd):
        try:
            toks = shlex.split(cmd, posix=False)
        except ValueError:
            return None
        for i, tok in enumerate(toks[1:], start=1):
            if _PS_COMMAND_FLAG.match(tok) and i + 1 < len(toks):
                return _payload_tokens(toks[i + 1:]), POWERSHELL
            if _PS_ENCODED_FLAG.match(tok) and i + 1 < len(toks):
                decoded = _decode_encoded(_strip_quotes(toks[i + 1]))
                return (decoded, POWERSHELL) if decoded else None
        return None

    m = _CMD_EXE.match(cmd)
    if m:
        # cmd.exe commands use POSIX splitting semantics.
        return _tokenised_payload(cmd[m.end():]), POSIX

    m = _POSIX_SH.match(cmd)
    if m:
        return _tokenised_payload(cmd[m.end():]), POSIX
    return None


def _tokenised_payload(rest: str) -> str:
    """Extract payload tokens, falling back to stripping quotes on tokenization error."""
    try:
        return _payload_tokens(shlex.split(rest, posix=False))
    except ValueError:
        return _strip_quotes(rest)


def effective_command(cmd: str, dialect: str = POSIX) -> Tuple[str, str]:
    """Return the innermost unwrapped command and its effective dialect."""
    for _ in range(_MAX_NESTING):
        nested = unwrap_nested(cmd)
        if not nested or not nested[0].strip():
            break
        cmd, dialect = nested
    return cmd, dialect


def effective_segments(cmd: str, dialect: str = POSIX,
                       substitute: bool = False) -> List[Tuple[str, str]]:
    """Recursively split and unwrap nested command segments with their effective dialects."""
    return _effective_segments(cmd, dialect, substitute, 0)


def _effective_segments(cmd: str, dialect: str, substitute: bool,
                        depth: int) -> List[Tuple[str, str]]:
    cmd = join_continuations(cmd, dialect)
    if dialect == POWERSHELL:
        # Strip character escapes after continuations have been folded.
        cmd = strip_ps_escapes(cmd)
    if substitute:
        cmd = substitute_assignments(cmd, dialect)
    out: List[Tuple[str, str]] = []
    for seg in split_segments(cmd, dialect) or [cmd]:
        nested = unwrap_nested(seg) if depth < _MAX_NESTING else None
        if nested and nested[0].strip():
            out.extend(_effective_segments(nested[0], nested[1],
                                           substitute, depth + 1))
        else:
            out.append((seg, dialect))
    return out


@functools.lru_cache(maxsize=512)
def _split_segments_cached(cmd: str, dialect: str) -> Tuple[str, ...]:
    cmd = join_continuations(cmd, dialect)
    segments: List[str] = []
    buf: List[str] = []
    quote = None
    i, n = 0, len(cmd)
    while i < n:
        ch = cmd[i]
        nxt = cmd[i + 1] if i + 1 < n else ""
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in ("&", "|") and nxt == ch:  # && or ||
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in ("|", ";", "\n"):  # single pipe, semicolon, newline
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        if ch == "&" and dialect != POWERSHELL:
            # Single & separator/background operator in POSIX (excluding &>, >&, <&, or \&).
            is_redirect = False
            if nxt == ">":
                is_redirect = True
            else:
                for b in reversed(buf):
                    if b.isspace():
                        continue
                    if b in (">", "<"):
                        is_redirect = True
                    break

            num_slashes = 0
            for b in reversed(buf):
                if b == "\\":
                    num_slashes += 1
                else:
                    break
            is_escaped = (num_slashes % 2 == 1)

            if not is_redirect and not is_escaped:
                segments.append("".join(buf))
                buf = []
                i += 1
                continue

        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return tuple(s.strip() for s in segments if s.strip())


def split_segments(cmd: str, dialect: str = POSIX) -> List[str]:
    """Split a command line on shell separators (| || && ; newline, and single & in POSIX)
    while respecting single and double quotes. Returns trimmed, non-empty segments.
    """
    return list(_split_segments_cached(cmd, dialect))


def redirect_target(cmd: str) -> Optional[str]:
    """Return the file a truncating output redirection ('> file') overwrites, or None.
    Quote- and escape-aware. Skips append, fd duplications, and /dev/* sinks.
    """
    n = len(cmd)
    i = 0
    quote = None
    while i < n:
        ch = cmd[i]
        if quote:
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "\\":                       # escaped char is literal
            i += 2
            continue
        if ch == ">":
            nxt = cmd[i + 1] if i + 1 < n else ""
            prev = cmd[i - 1] if i > 0 else ""
            if nxt == ">":                   # '>>' append - not destructive
                i += 2
                continue
            # Truncating redirects (1>, 2>, &>); fd duplications (2>&1, >&2) are skipped.
            if nxt == "&":                   # 2>&1, >&2 - duplication, not truncation
                i += 2
                continue
            # Read target token, skipping spaces and leading '|' (>| noclobber override).
            j = i + 1
            while j < n and cmd[j] in " \t|":
                j += 1
            q = None
            buf: List[str] = []
            while j < n:
                c = cmd[j]
                if q:
                    if c == q:
                        q = None
                    else:
                        buf.append(c)
                    j += 1
                    continue
                if c in ("'", '"'):
                    q = c
                    j += 1
                    continue
                if c in " \t|;&<>\n\r":
                    break                       # \r: CRLF, or the name absorbs it
                buf.append(c)
                j += 1
            tgt = "".join(buf)
            if not tgt or tgt.startswith("/dev/"):
                i += 1                       # sink or empty - keep scanning
                continue
            return tgt
        i += 1
    return None


# --------------------------------------------------------------------------
# Classification result
# --------------------------------------------------------------------------

@dataclass
class Classification:
    """What a command is. Describes; does not decide."""
    is_destructive: bool = False
    is_mutating: bool = False
    is_sql_read: bool = False
    is_sql_mutating: bool = False
    is_file_writer: bool = False
    remote_exec: bool = False
    is_pipeline: bool = False
    matched_rule: Optional[str] = None
    action_type: str = "shell"
    nonrecoverable_surface: Optional[str] = None
    segments: List[str] = field(default_factory=list)
    # Count of segments performing destructive operations (multi-destructive pipelines escalate).
    destructive_segments: int = 0

    @property
    def needs_recovery(self) -> bool:
        """True when proceeding should be gated on a recovery point."""
        return self.is_mutating or self.is_destructive


def _classify_segment(cmd: str, dialect: str = POSIX) -> dict:
    matched, atype = None, "shell"
    for rid, action_type, rx, only_in in _DESTRUCTIVE:
        if only_in is not None and only_in != dialect:
            continue
        if rx.search(cmd):
            matched, atype = rid, action_type
            break

    # Fallback: truncating output redirection ('> file') overwriting target from byte 0.
    if matched is None and redirect_target(cmd):
        matched, atype = "fs_redirect_truncate", "shell"

    is_sql_read = bool(_SQL_READ.search(cmd))
    is_sql_mutating = bool(_SQL_MUTATING.search(cmd))
    is_file_writer = bool(_FILE_WRITERS.search(cmd))
    is_destructive = matched is not None

    # Non-recoverable surfaces count as mutations.
    surface = None
    for label, rx in _NONRECOVERABLE:
        if rx.search(cmd):
            surface = label
            break
    # External/remote destructive rules cannot be covered by local snapshot.
    if surface is None and matched in _EXTERNAL_IRREVERSIBLE:
        surface = _EXTERNAL_IRREVERSIBLE[matched]
    # Local unrecoverable commands escalate across all environments.
    if surface is None and matched in _LOCAL_UNRECOVERABLE:
        surface = _LOCAL_UNRECOVERABLE[matched]

    is_mutating = is_destructive or is_sql_mutating or is_file_writer or (surface is not None)

    if is_sql_read or is_sql_mutating:
        atype = "sql"
    elif is_file_writer:
        atype = "filewrite"

    return {
        "is_destructive": is_destructive,
        "is_mutating": is_mutating,
        "is_sql_read": is_sql_read,
        "is_sql_mutating": is_sql_mutating,
        "is_file_writer": is_file_writer,
        "matched_rule": matched,
        "action_type": atype,
        "nonrecoverable_surface": surface,
    }


def classify(cmd: str, dialect: str = POSIX) -> Classification:
    """Classify a single command (no pipeline awareness)."""
    s = _classify_segment(cmd, dialect)
    return Classification(
        is_destructive=s["is_destructive"],
        is_mutating=s["is_mutating"],
        is_sql_read=s["is_sql_read"],
        is_sql_mutating=s["is_sql_mutating"],
        is_file_writer=s["is_file_writer"],
        remote_exec=bool(_REMOTE_EXEC.search(cmd)),
        is_pipeline=False,
        matched_rule=s["matched_rule"],
        action_type=s["action_type"],
        nonrecoverable_surface=s["nonrecoverable_surface"],
        segments=[cmd.strip()],
    )


def classify_pipeline(cmd: str, dialect: str = POSIX) -> Classification:
    """Classify a possibly chained / piped command. Each segment is classified
    on its own and the pipeline inherits the strongest signal. Opaque remote
    execution is detected on the full string because the pipe *is* the payload.
    """
    # Judge each segment in its own effective dialect.
    pairs = effective_segments(cmd, dialect)
    segments = [seg for seg, _ in pairs]
    seg_results = [_classify_segment(seg, d) for seg, d in pairs]
    if not seg_results:
        segments = [cmd]
        seg_results = [_classify_segment(cmd, dialect)]

    def any_of(key):
        return any(s[key] for s in seg_results)

    matched_rule = next((s["matched_rule"] for s in seg_results if s["matched_rule"]), None)
    surface = next((s["nonrecoverable_surface"] for s in seg_results if s["nonrecoverable_surface"]), None)
    action_type = next((s["action_type"] for s in seg_results if s["is_destructive"]),
                       seg_results[0]["action_type"])

    return Classification(
        destructive_segments=sum(1 for s in seg_results if s["is_destructive"]),
        is_destructive=any_of("is_destructive"),
        is_mutating=any_of("is_mutating"),
        is_sql_read=any_of("is_sql_read"),
        is_sql_mutating=any_of("is_sql_mutating"),
        is_file_writer=any_of("is_file_writer"),
        # Inspect full command string and all effective segments for remote execution.
        remote_exec=bool(_REMOTE_EXEC.search(cmd))
        or any(_REMOTE_EXEC.search(s) for s in segments),
        is_pipeline=len(seg_results) > 1,
        matched_rule=matched_rule,
        action_type=action_type,
        nonrecoverable_surface=surface,
        segments=[s.strip() for s in segments] or [cmd.strip()],
    )


def is_file_writer_command(cmd: str) -> bool:
    """Test if command matches mutating file-writer pattern (shared with recovery.py)."""
    return bool(_FILE_WRITERS.search(cmd))


def is_sql_preview_candidate(cmd: str) -> bool:
    """True if the command is a DELETE / UPDATE / TRUNCATE we can preview."""
    return bool(_SQL_DELETE.search(cmd) or _SQL_UPDATE.search(cmd) or _SQL_TRUNCATE.search(cmd))
