"""Snapshot the whole workspace when we cannot tell what a command will destroy.

--------------------------------------------------------------------------
THE GAP THIS FILLS
--------------------------------------------------------------------------
The guard reads the TEXT of a command and never runs it, so when the path is
not in the text the target cannot be resolved. classify.substitute_assignments
now handles the one readable case (`T=notes.txt; rm $T`), and _path_operands
already expands globs and braces. What is left is genuinely unreadable:

    rm $(cat list.txt)      resolving it means RUNNING cat. A pre-execution
                            guard that executes the thing it is guarding has
                            stopped being one.
    rm $TARGET              assigned in an earlier, separate command, in a
                            shell session the hook process cannot reach.
    rm -rf "$BUILD_DIR"/*   same, with a path we can see only half of.

Today these ESCALATE - block, with no recovery point. That is honest, and it
is also the branch that gets a tool uninstalled, because "I do not understand
your command, so you may not run it" is not a trade most people accept twice.

WHAT THIS DOES NOT FIX, stated plainly because the two are easy to confuse.
`python cleanup.py` is not classified as destructive at all, so it never
reaches this module - it is ALLOWED today, with no recovery and no block. That
is a CLASSIFICATION gap (we cannot tell the command is dangerous), not a
RESOLUTION gap (we know it is dangerous but not what it targets). Checkpointing
only answers the second. The first is what the syscall guard on Linux and the
WinFsp guard on Windows exist for: they watch the operation, not the sentence.

This module offers the other answer:

    "I cannot tell WHAT you will destroy, so I preserve EVERYTHING you could
     destroy - and if I cannot do that either, then no."

It is the FIX #5 discipline (never claim a partial recovery) generalised from
one operand to the whole workspace.

--------------------------------------------------------------------------
WHY .git IS INCLUDED HERE AND EXCLUDED EVERYWHERE ELSE
--------------------------------------------------------------------------
recovery.IGNORED_DIRS omits .git from ordinary snapshots, which is right: a
targeted snapshot of one directory does not need the repository database.

A checkpoint makes a much larger claim - "everything you could destroy is
preserved" - and a script that deletes .git would falsify it. The rule applied
here is: can this be rebuilt from what the checkpoint DOES hold?

    .git            NO. It is history. Nothing else in the tree contains it.
                    INCLUDED, even though it is often the largest thing there.
    node_modules    yes, from package.json          excluded
    __pycache__     yes, from the .py files         excluded
    .demo_cli       our own workspace; snapshotting the recovery directory
                    into itself is a recursion, not a backup.  excluded

The cost is honest and should be stated plainly: on a repository with a large
.git, checkpointing is slow. That is why it is opt-in. A feature someone
disables knowingly is far better than one that quietly lies.

--------------------------------------------------------------------------
WHAT IT REFUSES
--------------------------------------------------------------------------
A checkpoint that did not complete is NEVER reported as a recovery. Over the
size cap, outside the project, a root that _too_broad rejects - each returns a
`skipped` reason and no entry, and the action escalates exactly as it does
today. The module can only ever turn an escalation into a recovery; it can
never turn a refusal into an allow on the strength of a partial copy.

It also refuses surfaces a directory copy cannot possibly recover: a remote
database, a force-pushed branch. Copying the working tree does not bring back
history on a server, and offering it as if it did would be the same lie in a
larger coat.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from . import recovery
from .classify import Classification
from .config import Config

# Everything recovery skips EXCEPT .git - see the module docstring. Derived
# rather than retyped, so adding an entry to IGNORED_DIRS reaches this too.
# recovery.py carries a warning about three copies of this list drifting apart;
# this is a deliberate difference, expressed as a difference.
CHECKPOINT_IGNORE = frozenset(recovery.IGNORED_DIRS - {".git"})

# Reasons a checkpoint was not taken. Data, not prose: the receipt renders
# them, and tests assert on them.
DISABLED = "disabled"
NO_ROOT = "no_project_root"
TOO_BROAD = "too_broad"
TOO_LARGE = "too_large"
TOO_MANY_FILES = "too_many_files"
FAILED = "copy_failed"


@dataclass(frozen=True)
class CheckpointResult:
    """Either an entry or a reason - never both, never neither."""
    entry: Optional[dict] = None
    skipped: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.entry is not None


def enabled(cfg: Config) -> bool:
    """Opt-in, and off by default.

    Copying a whole workspace before a command is a real cost, and a guard that
    becomes slow without being asked is a guard that gets removed. Shadow-first
    is the same discipline the rest of the tool uses.
    """
    return bool((getattr(cfg, "checkpoint", None) or {}).get("enabled", False))


def should_checkpoint(c: Classification, target, cfg: Config,
                      recovery_captured: bool = False) -> bool:
    """True only in the precise gap this module exists for.

    All four conditions matter:

    1. enabled            opt-in.
    2. c.needs_recovery   something is actually going to be destroyed. A read
                          never gets a checkpoint.
    3. not recovery_captured
                          a precise snapshot already exists. Copying the whole
                          workspace on top of it would be pure waste - the
                          checkpoint is the FALLBACK, never the first choice.
    4. no nonrecoverable surface
                          THE IMPORTANT ONE. `git push --force` destroys
                          history on a server; a remote database lives on
                          another machine. A copy of the local working tree
                          recovers neither, and letting one stand in for a
                          recovery would be exactly the lie this tool exists to
                          prevent. Those must keep escalating.
    """
    if not enabled(cfg):
        return False
    if not c.needs_recovery:
        return False
    if recovery_captured or target is not None:
        return False
    return not c.nonrecoverable_surface


def capture(cfg: Config, action: str) -> CheckpointResult:
    """Snapshot the project root, or say why not.

    Reuses recovery.snapshot's directory branch, so the entry is an ordinary
    recovery entry and `undo`, `log`, `diff` and `verify` need no special case
    - the same property snapshot_bytes was built for on the WinFsp side.
    """
    root = os.path.abspath(cfg.project_root or "")
    if not root or not os.path.isdir(root):
        return CheckpointResult(skipped=NO_ROOT)
    # $HOME and the filesystem root are refused however small they measure.
    # Someone whose project_root is their home directory gets an escalation,
    # not a copy of everything they own.
    if recovery._too_broad(root):
        return CheckpointResult(skipped=TOO_BROAD)

    # One walk, two budgets. Bytes bound disk space, files bound TIME, and
    # only the byte half was ever checked here - so a tree that tripped the
    # file cap INSIDE snapshot() came back as "copy_failed", which names
    # neither the cause nor the knob and describes a copy that never began.
    cap = recovery._max_snapshot_bytes()
    file_cap = recovery._max_snapshot_files()
    nbytes, nfiles = recovery._walk_cost(root, cap, file_cap, CHECKPOINT_IGNORE)
    if nbytes > cap:
        return CheckpointResult(skipped=TOO_LARGE)
    if file_cap is not None and nfiles > file_cap:
        return CheckpointResult(skipped=TOO_MANY_FILES)

    entry = recovery.snapshot(
        recovery.Target(kind="dir", ref=root, label="checkpoint"),
        cfg.recovery_dir, "snapshot", action=action,
        ignore_dirs=CHECKPOINT_IGNORE,
    )
    # snapshot() returns None on its own internal refusals (a re-check of the
    # cap, a copy error). Never convert that into an entry.
    return CheckpointResult(entry=entry) if entry else CheckpointResult(skipped=FAILED)


def reason_text(skipped: str, cfg: Config) -> str:
    """Why no checkpoint, in words the person reading the receipt can act on."""
    cap_mb = recovery._max_snapshot_bytes() // (1024 * 1024)
    file_cap = recovery._max_snapshot_files()
    return {
        DISABLED: "Checkpointing is off; enable [checkpoint] in .demo_cli.toml.",
        NO_ROOT: "No project root to checkpoint.",
        TOO_BROAD: f"Refusing to checkpoint {cfg.project_root} - too broad to "
                   f"copy honestly (home or filesystem root).",
        TOO_LARGE: f"Workspace exceeds the {cap_mb} MB checkpoint cap; raise "
                   f"DEMO_CLI_MAX_SNAPSHOT_MB or resolve the target explicitly.",
        TOO_MANY_FILES: f"Workspace holds more than {file_cap:,} files; capturing "
                        f"it would outlast the agent's hook timeout, and a hook "
                        f"killed mid-copy lets the command run unguarded with no "
                        f"warning. Raise DEMO_CLI_MAX_SNAPSHOT_FILES and the hook "
                        f"timeout together, or resolve the target explicitly.",
        FAILED: "Checkpoint copy did not complete; no recovery was taken.",
    }.get(skipped, "No checkpoint was taken.")
