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

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------
# Rule tables
# --------------------------------------------------------------------------

# (rule_id, action_type, pattern). First match wins, order matters.
_DESTRUCTIVE_RULES = [
    ("sql_drop", "sql", r"\bDROP\s+(?:DATABASE|TABLE|SCHEMA)\b"),
    ("sql_truncate", "sql", r"\bTRUNCATE\b"),
    ("sql_delete", "sql", r"\bDELETE\s+FROM\b"),
    ("tf_destroy", "infra", r"\bterraform\s+destroy\b"),
    ("kubectl_delete", "infra", r"\bkubectl\s+delete\s+(?:namespace|ns|pv|pvc|deploy(?:ment)?|sts)\b"),
    ("cloud_delete", "infra", r"\b(?:aws|gcloud|az)\b[\w\s.-]*\b(?:delete|terminate|destroy|rb)\b"),
    ("railway_drop", "infra", r"railway\s+run.*production.*(?:DROP|DELETE|TRUNCATE)"),
    ("railway_vol_del", "infra", r"railway\s+volume\s+delete"),
    ("git_force_push", "git", r"\bgit\s+push\b.*(?:--force|-f)\b"),
    ("git_reset_hard", "git", r"\bgit\s+reset\s+--hard\b"),
    # rm with both recursive and force, in either flag order (-rf or -fr),
    # bounded so it does not leak across a pipe / chain separator. Listed first
    # so this specific, higher-signal id wins for the -rf case.
    ("rm_rf", "shell", r"\brm\b(?=[^|;&]*\b-?[a-z]*r[a-z]*\b)(?=[^|;&]*\b-?[a-z]*f[a-z]*\b)[^|;&]*"),
    # Any *top-level* rm, not only -rf. A plain `rm app.db` deletes a file just
    # as irrecoverably from the shell's point of view, and "delete this file" is
    # the single most common destructive thing an agent does. Anchored to the
    # start of the segment (like the operand extractor) so subcommands such as
    # `git rm`, `docker rm`, `npm rm` do NOT match - those are not local-file
    # deletions and would only produce false escalations.
    # Leading `NAME=value ` env-var assignments (a shell prefix) are allowed
    # before rm, so `X=1 rm app.db` is caught like `rm app.db` (#006). Only
    # assignment tokens are permitted - an arbitrary word prefix is NOT, so
    # `git rm` / `docker rm` / `npm rm` still do not match.
    ("rm_local", "shell", r"^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?rm\b[^|;&]*"),
    # PowerShell recursive-force delete: Remove-Item (alias `ri`) carrying BOTH a
    # Recurse-like flag and a Force-like flag, in any order, full or abbreviated
    # (-Recurse/-rec/-r and -Force/-fo/-f). The two lookaheads disambiguate
    # cleanly by requiring the recurse token to start "-r" and the force token to
    # start "-f", so a lone `-Force` (which contains an "r") does NOT satisfy the
    # recurse lookahead - only the real `-Recurse -Force` nuke matches. Placed
    # before rmdir/del so this higher-signal id wins. NOT in _LOCAL_UNRECOVERABLE:
    # recovery.py resolves its target and guard.py snapshots it when possible, so
    # it is honestly recoverable when the target is a single, existing, in-project
    # path (see decide.py for the still-unrecovered hard-stop).
    ("ps_remove_item_rf", "shell",
     r"\b(?:Remove-Item|ri)\b(?=[^|;&]*\s-r[a-z]*\b)(?=[^|;&]*\s-f[a-z]*\b)[^|;&]*"),
    # Any top-level Remove-Item (alias `ri`) - the PowerShell twin of rm_local.
    # Closes the parity gap: `Remove-Item app.db` and `Remove-Item -Recurse x`
    # (no -Force) were previously missed on Windows while `rm app.db` was caught
    # on POSIX. Recoverable (recovery.py resolves the -Path/-LiteralPath/
    # positional operand and snapshots it), so NOT in _LOCAL_UNRECOVERABLE.
    # Listed AFTER ps_remove_item_rf so the -Recurse -Force nuke keeps its id.
    ("ps_remove_item", "shell", r"^\s*(?:Remove-Item|ri)\b[^|;&]*"),
    # ---- PowerShell content destroyers -----------------------------------
    # Windows had ONE rule (Remove-Item) while POSIX had a dozen. These close
    # the parity gap. Deliberately narrow, in three ways:
    #
    #  * APPEND IS NOT DESTROY. Add-Content and `Out-File -Append` only add to
    #    the end of a file, exactly like `>>` versus `>`. Add-Content is absent
    #    from this table entirely; Out-File carries a negative lookahead.
    #  * -Force IS THE DESTRUCTIVE PART for move/copy/rename. Without it those
    #    cmdlets REFUSE to overwrite an existing destination, so flagging the
    #    bare form would be a false positive. Same discipline as git -d vs -D.
    #  * SHORT ALIASES ARE OMITTED on purpose. PowerShell aliases Set-Content to
    #    `sc`, but `sc.exe` is the Windows Service Control tool and `sc query` is
    #    an ordinary read - matching it would flag safe commands. `mi`/`cpi`/
    #    `rni`/`ren` are likewise too short to match safely. Accepted trade:
    #    an agent writing the short form is missed. A false positive that gets
    #    the guard uninstalled costs more than a miss.
    ("ps_clear_content", "shell", r"^\s*(?:Clear-Content|clc)\b[^|;&]*"),
    ("ps_set_content", "shell",
     r"^\s*(?:Set-Content|Out-File)\b(?![^|;&]*\s-(?:Append|NoClobber)\b)[^|;&]*"),
    ("ps_move_force", "shell", r"^\s*Move-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_copy_force", "shell", r"^\s*Copy-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_rename_force", "shell", r"^\s*Rename-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    ("ps_new_item_force", "shell", r"^\s*New-Item\b(?=[^|;&]*\s-Force\b)[^|;&]*"),
    # Whole-volume operations. No snapshot can cover these, so they hard-stop -
    # the Windows counterpart of mkfs.
    ("ps_format_volume", "shell", r"\b(?:Format-Volume|Clear-Disk)\b"),
    ("rmdir_s", "shell", r"\brmdir\b.*\/[sS]"),
    ("del_force", "shell", r"\bdel\b.*\/[fFsS]"),
    ("mv_overwrite", "shell", r"\bmv\s+(?:-[a-z]*f[a-z]*\s+)?\S+\s+\S+"),
    # A small, bounded set of other local data-destroyers a cooperative agent
    # can run by mistake. These are LOCAL (no external blast radius): they are
    # snapshotted when the target can be resolved, and escalated honestly when
    # it cannot. This is deliberately NOT an attempt to enumerate every
    # dangerous command - string-level coverage is explicitly out of scope.
    ("fs_shred", "shell", r"\bshred\b"),
    ("fs_truncate", "shell", r"\btruncate\b[^|;&]*\s-s\b"),
    ("fs_dd_of", "shell", r"\bdd\b[^|;&]*\bof=\S+"),
    # Filesystem format: mkfs / mkfs.<fstype> wipes an entire device. Placed with
    # the other fs_ destroyers; marked non-recoverable below (a whole-device
    # format cannot be honestly snapshotted).
    ("fs_mkfs", "shell", r"\bmkfs(?:\.\w+)?\b"),
    ("fs_find_delete", "shell", r"\bfind\b[^|;&]*\s-delete\b"),
    ("git_clean", "git", r"\bgit\s+clean\b[^|;&]*-[a-z]*d"),
    # Destructive git that loses work / rewrites history / prunes recovery. NOT
    # "all git" - read-only and normal-flow git (status/diff/log/add/commit/
    # push/pull/checkout <branch>) is deliberately left alone to keep the
    # perimeter honest and avoid flooding review. Each has no local file operand,
    # so decide.py escalates them (no snapshot to stand behind).
    ("git_worktree_remove", "git", r"\bgit\s+worktree\s+remove\b[^|;&]*(?:--force|\s-f)\b"),
    # branch delete: only -D (force) is destructive; -d refuses on unmerged work,
    # so it is SAFE. Match a capital D case-sensitively via (?-i:...) even though
    # the table is compiled with re.I - so `-d` is NOT swept in.
    ("git_branch_delete", "git", r"\bgit\s+branch\b[^|;&]*\s(?-i:-\w*D\w*)\b"),
    ("git_checkout_discard", "git", r"\bgit\s+checkout\b[^|;&]*?(?:\s--\s|\s\.(?:\s|$))"),
    ("git_restore", "git", r"\bgit\s+restore\b"),
    ("git_stash_drop", "git", r"\bgit\s+stash\s+(?:drop|clear)\b"),
    # `git stash pop` applies then drops the stash; a conflict during apply can
    # leave the working tree mangled and the stash consumed. Real incident
    # (raw-data #009b). `git stash apply` is left alone - it keeps the stash.
    ("git_stash_pop", "git", r"\bgit\s+stash\s+pop\b"),
    ("git_reflog_expire", "git", r"\bgit\s+reflog\s+expire\b"),
    ("git_gc_prune", "git", r"\bgit\s+gc\b[^|;&]*--prune=\S+"),
    ("git_filter_branch", "git", r"\bgit\s+filter-(?:branch|repo)\b"),
    ("git_update_ref_delete", "git", r"\bgit\s+update-ref\s+-d\b"),
]
_DESTRUCTIVE = [(rid, a, re.compile(rx, re.I | re.S)) for rid, a, rx in _DESTRUCTIVE_RULES]

# Destructive rules whose blast radius is EXTERNAL / remote. A local snapshot
# can never truthfully cover them, so they are treated as non-recoverable
# surfaces and escalated regardless of the local environment label. (Trou 1:
# without this, a force-push or terraform destroy in a project whose env
# resolves to "development" would be allowed unattended.)
# Local destructive rules (rm/mv/reset --hard/shred/...) are intentionally NOT
# here - those are recoverable by a local snapshot.
_EXTERNAL_IRREVERSIBLE = {
    "tf_destroy": "infra_destroy",
    "kubectl_delete": "cluster_resource_delete",
    "cloud_delete": "cloud_resource_delete",
    "railway_drop": "remote_database",
    "railway_vol_del": "remote_volume",
    "git_force_push": "remote_vcs_history",
}

# Local destructive commands this tool cannot honestly make reversible as built.
# `rmdir /s` and `del /s|/f` remove a whole tree with no recycle bin, and the
# operand extractor does not resolve their target, so no recovery point is ever
# captured. Left unmarked they would be treated as ordinary local deletes -
# exactly the case an agent hits in a dev/test/staging workspace. Marking them
# as a non-recoverable surface makes the decision engine escalate them in EVERY
# environment with an honest reason and the structural-approval override: a real
# hard-stop, matching what we state publicly. A human structural-approval token
# remains the one legitimate
# override (an agent cannot forge it), consistent with the external
# non-recoverable surfaces above.
#
# `Remove-Item -Recurse -Force` (ps_remove_item_rf) is deliberately NOT here.
# recovery.py now extracts its target (a single -Path/-LiteralPath/positional
# operand) and guard.py snapshots it when it exists inside the project root, so
# it can be honestly recoverable. This module has no filesystem access (it only
# describes the command), so it cannot know in advance whether that snapshot
# will succeed - decide.py is where the still-unrecovered case (missing,
# ambiguous, multi-drive, or out-of-root target) escalates as a hard-stop in
# every environment, since an unrecoverable mutation is never waved through on
# the strength of an environment label.
_LOCAL_UNRECOVERABLE = {
    "rmdir_s": "recursive_force_delete",
    "del_force": "recursive_force_delete",
    "fs_mkfs": "disk_format",
    "ps_format_volume": "disk_format",
}

# Opaque remote execution: code is fetched and run in one step. It cannot be
# previewed or snapshotted because the payload is not known before it runs.
_REMOTE_EXEC = re.compile(
    r"(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?|node|ruby|perl)\b"
    r"|base64\s+-d[^|]*\|\s*(?:bash|sh)\b"
    r"|\beval\b"
    r"|\|\s*(?:bash|sh)\s+-c\b"
    # Opaque dynamic execution via a one-liner interpreter call. We do NOT try
    # to defeat obfuscation (that arms race is out of scope); we only recognise
    # that a `python -c` carrying os.system/eval/exec/__import__/subprocess/pty
    # cannot be previewed, exactly like curl|bash, and therefore must escalate.
    r"|\bpython\d?\s+-c\b[^|]*(?:os\.system|os\.popen|subprocess|__import__|\beval\b|\bexec\b|pty\.spawn|commands\.get)",
    re.I,
)

# Tools that mutate files indirectly (formatters, generators, package managers).
# They rarely look destructive, but they rewrite the working tree - snapshot the
# path first so the change is visible and reversible.
_FILE_WRITERS = re.compile(
    r"\bprettier\b[^|;&]*--write"
    r"|\beslint\b[^|;&]*--fix"
    r"|\b(?:black|isort|gofmt|rustfmt)\b"
    r"|\b(?:npm|yarn|pnpm)\s+(?:install|add|remove|i)\b"
    r"|\bpip\s+install\b"
    r"|\b(?:npx|node)\b[^|;&]*(?:codegen|generate|migrate)\b",
    re.I,
)

# Surfaces a local snapshot cannot truthfully cover. A mutation here is NOT
# made "reversible" by copying a file - it must be escalated honestly (P2).
# (label, pattern)
_NONRECOVERABLE_SURFACES = [
    ("external_email", r"\b(sendgrid|mailgun|ses\s+send-email|smtp)\b|\bmail\s+-s\b"),
    ("external_payment", r"\b(stripe|paypal|braintree)\b[^|;&]*\b(charge|refund|payout|capture)\b"),
    ("external_message", r"\b(slack|discord|twilio)\b[^|;&]*\b(post|send|message|webhook)\b"
                         r"|hooks\.slack\.com|chat\.postMessage"),
    ("vcs_remote_state", r"\b(gh|hub)\s+(pr|issue|release)\s+(close|merge|delete|create)\b"
                         r"|\bgh\s+repo\s+delete\b|\bgh\s+api\b[^|;&]*-X\s*(?:DELETE|PUT)\b"),
    ("credential_rotation", r"\brotat(?:e|ing)\b[^|;&]*\b(key|secret|credential|token)\b"
                            r"|\b(?:aws\s+iam|gcloud\s+iam|az\s+role)\b"),
    ("secret_write", r"\b(vault|aws\s+secretsmanager|aws\s+ssm)\b[^|;&]*\b(put|write|delete|set)\b"),
    ("object_storage", r"\b(?:aws\s+s3|gsutil|az\s+storage\s+blob)\b[^|;&]*\b(rm|delete|rb)\b"),
    ("message_queue", r"\b(?:aws\s+sqs|rabbitmqadmin|kafka-topics)\b[^|;&]*\b(purge|delete)\b"),
    ("remote_filesystem", r"\bssh\b[^|;&]*\brm\b|\brsync\b[^|;&]*--delete\b"),
    ("schema_migration", r"\b(alembic|flyway|liquibase|prisma\s+migrate|knex\s+migrate|sequelize\s+db:migrate)\b"
                         r"|\brails\s+db:migrate\b|\bmanage\.py\s+migrate\b"),
    # Content / deploy SaaS CLIs (Approach A) - the always-on string-layer twin of
    # the egress guard. Narrow, DESTRUCTIVE-SUBCOMMAND-ONLY (like git -d/-D): never
    # the whole tool, never the read/preview forms. External -> escalate.
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
]
_NONRECOVERABLE = [(label, re.compile(rx, re.I)) for label, rx in _NONRECOVERABLE_SURFACES]

_SQL_READ = re.compile(r"^\s*SELECT\b", re.I)
_SQL_MUTATING = re.compile(r"\b(UPDATE|INSERT|DELETE|DROP|TRUNCATE|ALTER|CREATE|REPLACE)\b", re.I)
_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\b", re.I)
_SQL_UPDATE = re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.I)
_SQL_TRUNCATE = re.compile(r"\bTRUNCATE\b", re.I)


# --------------------------------------------------------------------------
# Pipeline splitting
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Shell dialects
# --------------------------------------------------------------------------
#
# bash and PowerShell agree that a command can continue on the next line, and
# disagree on how to write it. The character is not interchangeable: a trailing
# backtick in bash opens a command substitution, and a trailing backslash in
# PowerShell is a literal backslash ending the command. Joining on the wrong one
# would MERGE two separate commands, which can stop an anchored rule such as
# rm_local (`^\s*rm`) from matching - a silent miss, the worst outcome. So the
# caller states which shell the text came from; this module never guesses.
POSIX = "posix"
POWERSHELL = "powershell"
_CONTINUATION = {POSIX: "\\", POWERSHELL: "`"}


def join_continuations(cmd: str, dialect: str = POSIX) -> str:
    """Fold a multi-line command back into one line.

        bash            rm -rf \\        PowerShell     Remove-Item `
                          /tmp/build                        -Recurse C:\\build

    Both are ONE command. Without this, split_segments treats the newline as a
    separator, cuts the command in two, and the operand extractor loses the path
    that lives on the second line - so nothing is snapshotted. Present in bash
    today, not only in PowerShell.

    Idempotent: joining an already-joined string changes nothing.

    Windows line endings are normalised first. Without that, the look-ahead
    below meets the CR of a CRLF pair, decides this is not end-of-line, and the
    whole fix silently does nothing on the one platform it was written for.
    """
    cmd = cmd.replace("\r\n", "\n")
    ch = _CONTINUATION.get(dialect, "\\")
    out: List[str] = []
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == ch:
            # A continuation only counts at end of line: skip trailing blanks
            # and require a newline immediately after.
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
#
# The guard reads the TEXT of a command; it never runs it. So whenever the path
# is not literally in the text, the target cannot be resolved and the action
# escalates. Measured on 2026-08-24, four shapes cause that:
#
#     rm $(cat list.txt)        the shell would run `cat` to find out. We must
#                               not, so this stays unresolvable - permanently.
#     python cleanup.py         the paths are inside another file.
#     rm $TARGET                set in an earlier, separate command. On Linux
#                               the agent's bash session persists, so the value
#                               exists somewhere we cannot reach from the hook
#                               process. On Windows it does not even exist:
#                               Claude Code spawns a fresh `powershell
#                               -NoProfile` per tool call, so nothing survives.
#     T=notes.txt; rm $T        THE ASSIGNMENT AND THE USE ARE IN THE SAME
#                               STRING. Nothing has to be executed, guessed, or
#                               asked for. This one is simply readable, and
#                               this function reads it.
#
# Only the last shape is handled here, deliberately. Globs and brace expansion
# are already resolved in recovery._path_operands; the first three cannot be
# resolved by any pre-execution guard and continue to escalate.
# --------------------------------------------------------------------------

# NAME=value, optionally exported, at the start of the line or after a
# separator. The value is a quoted string or a run of unremarkable characters.
_POSIX_ASSIGN = re.compile(
    r"""(?:^|(?<=[;&|]))\s*(?:export\s+)?
        ([A-Za-z_]\w*)=("[^"]*"|'[^']*'|[^\s;&|<>]*)""",
    re.VERBOSE)
# $name = value. `env:` is included because that is the form an agent actually
# uses on Windows ($env:TARGET = "x"), observed live.
_PS_ASSIGN = re.compile(
    r"""(?:^|(?<=[;|]))\s*
        \$((?:env:)?[A-Za-z_]\w*)\s*=\s*("[^"]*"|'[^']*'|[^\s;|<>]+)""",
    re.VERBOSE)

_POSIX_REF = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_PS_REF = re.compile(r"\$\{((?:env:)?[A-Za-z_]\w*)\}|\$((?:env:)?[A-Za-z_]\w*)")

_ASSIGN = {POSIX: _POSIX_ASSIGN, POWERSHELL: _PS_ASSIGN}
_REF = {POSIX: _POSIX_REF, POWERSHELL: _PS_REF}

# A value we refuse to substitute. Every character here can change the SHAPE of
# the command rather than merely filling in a word:
#
#   $ and `   the value is itself unresolved, or contains a command
#             substitution. Substituting would turn "I cannot tell" into
#             something that LOOKS resolved. That is the exact lie this
#             project exists to prevent.
#   ; & |     one command would silently become two, and the classifier would
#             then judge a command line that was never written.
#   < > \n    redirection and line structure, same reasoning.
#
# When a value is refused the name is simply left unknown, which leaves its
# references unresolved, which makes the whole substitution fail closed below.
_UNSAFE_VALUE = re.compile(r"[$`;&|<>\n]")


def _assignment_survives(cmd: str, end: int) -> bool:
    """False when the assignment runs in a subshell and its value never
    reaches the command that uses it.

        T=a | tee x ; rm $T      the assignment is one stage of a PIPELINE,
        T=a & b      ; rm $T     and backgrounding forks - both run it in a
                                 subshell, so the parent's T is never set.
                                 Substituting would name a file the shell
                                 never touched, and report a snapshot of it.

        T=a && rm $T             `&&` and `||` are sequencing, not forking.
        T=a || rm $T             The value survives. So does `T=a > out`.
        T=a ;  rm $T

    An unquoted value cannot CONTAIN these characters - the value pattern
    stops before them - so `_UNSAFE_VALUE` never sees them and this check is
    the only thing standing between the two cases. Doubled operators are
    sequencing; single ones fork.
    """
    rest = cmd[end:].lstrip(" \t")
    if rest.startswith("&&") or rest.startswith("||"):
        return True
    return not rest.startswith("&") and not rest.startswith("|")


def substitute_assignments(cmd: str, dialect: str = POSIX) -> str:
    """Resolve variables assigned earlier in the SAME command string.

        T=notes.txt; rm $T              ->  T=notes.txt; rm notes.txt
        $t = "notes.txt"; rm $t         ->  $t = "notes.txt"; rm notes.txt

    Returns the command UNCHANGED unless every variable reference in it could
    be resolved. That is the honesty rule for this function, and it is the
    whole reason it is safe to use:

        rm $T $OTHER      with only T known

    Substituting T alone yields `rm notes.txt $OTHER`, where $OTHER is now an
    ordinary-looking operand that happens not to exist. Two operands collapse
    to their common directory, and the guard would consider snapshotting a
    directory for a command it still cannot read. Partial knowledge presented
    as complete is worse than admitted ignorance, so a single unresolved
    reference discards the whole substitution and the action escalates exactly
    as it does today.

    Nothing is executed. Values are read out of the string itself.
    """
    assign_re, ref_re = _ASSIGN.get(dialect), _REF.get(dialect)
    if not assign_re or "$" not in cmd:
        return cmd

    # Where each name was last assigned, and the spans of the assignments
    # themselves. A PowerShell assignment's left side ($t = ...) matches the
    # reference pattern too, so those spans have to be skipped or the target
    # of the assignment would be substituted with its own value.
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
        # The value in force HERE: the last assignment to this name that
        # appears before this reference. Later assignments have not run yet.
        latest = [v for pos, n, v in values if n == name and pos < m.start()]
        if not latest:
            resolved_all = False
            return m.group(0)
        return latest[-1]

    out = ref_re.sub(replace, cmd)
    return out if resolved_all else cmd


# --------------------------------------------------------------------------
# Nested shells
#
# Observed live on Windows, 2026-08-26. Claude Code's Bash tool is GIT BASH,
# not PowerShell - `pwd` returns /c/Users/... - so the seven PowerShell rules
# looked like the wrong investment. They were not; they were never being
# HANDED the right string. Asked to use Remove-Item, the agent ran:
#
#     Bash(powershell.exe -Command "Remove-Item test.txt")
#
# _PS_REMOVE_RE is anchored at the start, the command starts with
# `powershell.exe`, and seven correct rules sat dormant while the delete went
# through. The filesystem guard caught it; the string layer never saw it.
#
# Third time the same shape: the rules were right and the plumbing never asked
# them (see also `mv` missing from the shell-guard pre-filter, and dispatch
# running on the line instead of the segment).
#
# WHAT THIS CANNOT DO, stated plainly: unwrapping is string work, so it
# inherits the string layer's frontier. `powershell -c "R''emove-Item x"`
# defeats it, and always will - obfuscation is the behavioural layer's job.
# -EncodedCommand is the exception worth handling, because base64 is DECODED,
# not evaluated: no execution, no guessing.
# --------------------------------------------------------------------------

_POWERSHELL_EXE = re.compile(r"^\s*(?:[\w:.\\/ ()-]*[\\/])?(?:powershell|pwsh)(?:\.exe)?\b",
                             re.I)
_CMD_EXE = re.compile(r"^\s*(?:[\w:.\\/ ()-]*[\\/])?cmd(?:\.exe)?\s+/[ck]\b", re.I)
_POSIX_SH = re.compile(r"^\s*(?:[\w./-]*/)?(?:bash|sh|dash|zsh)\s+-c\b")

# PowerShell accepts abbreviations: -Command, -Comm, -c. Same for
# -EncodedCommand / -enc / -e. Matching the documented prefixes rather than the
# full words, because the short forms are what people actually type.
_PS_COMMAND_FLAG = re.compile(r"^-(?:c|co|com|comm|comma|comman|command)$", re.I)
_PS_ENCODED_FLAG = re.compile(r"^-(?:e|en|enc|enco|encod|encode|encoded|"
                              r"encodedcommand)$", re.I)

_MAX_NESTING = 3        # bounded: `a -c "b -c 'c -c ...'"` must terminate


def _strip_quotes(s: str) -> str:
    s = s.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _decode_encoded(payload: str) -> Optional[str]:
    """PowerShell's -EncodedCommand is base64 UTF-16LE. Decoding is not
    evaluating - nothing runs, so this is safe for a pre-execution guard."""
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
    """One level of `<shell> -c <payload>`, or None.

    Returns (payload, dialect_of_payload). The dialect is the point: a
    PowerShell payload has to be judged by the PowerShell rules and split with
    PowerShell quoting, whichever shell was holding it.
    """
    if _POWERSHELL_EXE.match(cmd):
        try:
            toks = shlex.split(cmd, posix=False)
        except ValueError:
            return None
        for i, tok in enumerate(toks[1:], start=1):
            if _PS_COMMAND_FLAG.match(tok) and i + 1 < len(toks):
                return _strip_quotes(" ".join(toks[i + 1:])), POWERSHELL
            if _PS_ENCODED_FLAG.match(tok) and i + 1 < len(toks):
                decoded = _decode_encoded(_strip_quotes(toks[i + 1]))
                return (decoded, POWERSHELL) if decoded else None
        return None

    m = _CMD_EXE.match(cmd)
    if m:
        # cmd.exe's own verbs are closest to POSIX for splitting purposes; the
        # dialect only decides quoting and continuation, and cmd uses neither
        # PowerShell's backtick nor a distinct grammar we model.
        return _strip_quotes(cmd[m.end():]), POSIX

    m = _POSIX_SH.match(cmd)
    if m:
        return _strip_quotes(cmd[m.end():]), POSIX
    return None


def effective_command(cmd: str, dialect: str = POSIX) -> Tuple[str, str]:
    """The command actually being run, and the dialect to judge it in.

    Used by BOTH classify_pipeline and recovery.extract_path_operand. They
    must agree on what the command IS, or one decides a rename is destructive
    while the other looks for the operand in different text - the failure the
    shared `redirect_target` already exists to prevent.

    A wrapper with no recognisable payload is returned unchanged, so nothing
    that is not a nested shell is disturbed.
    """
    for _ in range(_MAX_NESTING):
        nested = unwrap_nested(cmd)
        if not nested or not nested[0].strip():
            break
        cmd, dialect = nested
    return cmd, dialect


def split_segments(cmd: str, dialect: str = POSIX) -> List[str]:
    """Split a command line on shell separators (| || && ; newline) while
    respecting single and double quotes. Returns trimmed, non-empty segments.

    This is a pragmatic splitter, not a full shell parser; it exists so a
    destructive step hidden after a safe one in a chain is still classified.

    Line continuations are folded first, so a command written across two lines
    is judged as the single command it is.
    """
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
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


def redirect_target(cmd: str) -> Optional[str]:
    """Return the file a truncating output redirection ('> file') overwrites, or
    None. Quote- and escape-aware (the same technique as split_segments): a '>'
    inside quotes or backslash-escaped is literal text, not the operator, so
    `echo "a>b"` is safe while `echo "a>b" > app.db` targets app.db. Skips '>>'
    (append), fd-prefixed redirects (2> &>), and /dev/* sinks. Shared by
    _classify_segment (is it destructive?) and recovery.extract_path_operand
    (what to snapshot), so the two never disagree."""
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
            if prev.isdigit() or prev == "&":  # 2> / &> fd-prefixed - out of scope
                i += 1
                continue
            # Read the target token, quote-aware, skipping spaces and a leading
            # '|' (the '>|' noclobber-override form).
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

    @property
    def needs_recovery(self) -> bool:
        """True when proceeding should be gated on a recovery point."""
        return self.is_mutating or self.is_destructive


def _classify_segment(cmd: str) -> dict:
    matched, atype = None, "shell"
    for rid, action_type, rx in _DESTRUCTIVE:
        if rx.search(cmd):
            matched, atype = rid, action_type
            break

    # Fallback: a truncating output redirection ('> file') has no command verb
    # for the regex rules above to catch, but it overwrites the file from byte 0.
    # Only fires when no stronger rule already matched. Recoverable (the target
    # is snapshotted via recovery.extract_path_operand), so it is NOT added to
    # _LOCAL_UNRECOVERABLE.
    if matched is None and redirect_target(cmd):
        matched, atype = "fs_redirect_truncate", "shell"

    is_sql_read = bool(_SQL_READ.search(cmd))
    is_sql_mutating = bool(_SQL_MUTATING.search(cmd))
    is_file_writer = bool(_FILE_WRITERS.search(cmd))
    is_destructive = matched is not None

    # A non-recoverable surface (external effect, migration, credential, ...)
    # is itself a mutation, even when no other rule fires.
    surface = None
    for label, rx in _NONRECOVERABLE:
        if rx.search(cmd):
            surface = label
            break
    # External/remote destructive rules cannot be covered by a local snapshot.
    if surface is None and matched in _EXTERNAL_IRREVERSIBLE:
        surface = _EXTERNAL_IRREVERSIBLE[matched]
    # Local recursive-force deletes we cannot honestly recover: escalate in every
    # environment (there is no low-blast exception that could wave them through).
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


def classify(cmd: str) -> Classification:
    """Classify a single command (no pipeline awareness)."""
    s = _classify_segment(cmd)
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
    # `powershell -Command "Remove-Item x"` IS a Remove-Item. Judge the payload
    # and judge it in ITS dialect - recovery.extract_path_operand does exactly
    # the same, or the two would disagree about what the command even is.
    cmd, dialect = effective_command(cmd, dialect)
    cmd = join_continuations(cmd, dialect)
    segments = split_segments(cmd, dialect)
    seg_results = [_classify_segment(seg) for seg in segments]
    if not seg_results:
        seg_results = [_classify_segment(cmd)]

    def any_of(key):
        return any(s[key] for s in seg_results)

    matched_rule = next((s["matched_rule"] for s in seg_results if s["matched_rule"]), None)
    surface = next((s["nonrecoverable_surface"] for s in seg_results if s["nonrecoverable_surface"]), None)
    action_type = next((s["action_type"] for s in seg_results if s["is_destructive"]),
                       seg_results[0]["action_type"])

    return Classification(
        is_destructive=any_of("is_destructive"),
        is_mutating=any_of("is_mutating"),
        is_sql_read=any_of("is_sql_read"),
        is_sql_mutating=any_of("is_sql_mutating"),
        is_file_writer=any_of("is_file_writer"),
        remote_exec=bool(_REMOTE_EXEC.search(cmd)),
        is_pipeline=len(seg_results) > 1,
        matched_rule=matched_rule,
        action_type=action_type,
        nonrecoverable_surface=surface,
        segments=[s.strip() for s in segments] or [cmd.strip()],
    )


def is_sql_preview_candidate(cmd: str) -> bool:
    """True if the command is a DELETE / UPDATE / TRUNCATE we can preview."""
    return bool(_SQL_DELETE.search(cmd) or _SQL_UPDATE.search(cmd) or _SQL_TRUNCATE.search(cmd))
