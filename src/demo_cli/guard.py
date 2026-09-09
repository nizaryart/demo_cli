"""The Guard: the out-of-band reference monitor that ties the pieces together.

Flow for one command:

    classify -> resolve target (no default) -> build context (declared-first)
    -> compare declared intent to context -> snapshot the real target
    -> preview affected rows -> verify structural approval -> decide
    -> append a hash-chained receipt

Two modes:
    shadow   observe only - evaluate, snapshot, and record, but never block.
             The recommended way to adopt: prove value with zero workflow risk.
    enforce  gate - a blocking disposition prevents the action from proceeding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import os

from . import approval, checkpoint, preview as preview_mod, recovery
from .classify import (POSIX, Classification, classify_pipeline,
                       is_sql_preview_candidate)
from .config import Config, config_error_message, load_config
from .context import Context, Intent, build_context, compare_intent
from .decide import (ALLOW, ASK, BLOCKING, CONTEXT_MISMATCH, DRY_RUN, ESCALATE,
                     REVERSIBLE, Decision, decide)
from .receipts import Receipt, append_receipt


# PowerShell rules whose target is created rather than destroyed when the path
# is absent. Clear-Content is NOT here: it errors on a missing file rather than
# creating one, so there is nothing to reinterpret.
_CREATES_IF_MISSING = {"ps_set_content", "ps_new_item_force",
                       "ps_move_force", "ps_copy_force", "ps_rename_force"}


@dataclass
class GuardResult:
    command: str
    classification: Classification
    context: Context
    decision: Decision
    mode: str
    target: Optional[recovery.Target] = None
    recovery_entry: Optional[dict] = None
    preview_count: Optional[int] = None
    preview_rows: list = field(default_factory=list)
    preview_cols: list = field(default_factory=list)
    mismatches: List[Tuple[str, str, str]] = field(default_factory=list)
    affected_paths: List[str] = field(default_factory=list)
    receipt: Optional[Receipt] = None

    @property
    def allowed(self) -> bool:
        """Whether the action may proceed unattended."""
        if self.mode == "shadow":
            return True
        return self.decision.decision not in BLOCKING and not self.decision.is_ask

    @property
    def permission(self) -> str:
        """Map the disposition to a Claude Code permissionDecision."""
        d = self.decision.decision
        if d in BLOCKING:
            return "deny"
        if d in ASK:
            return "ask"
        return "allow"


class Guard:
    def __init__(self, config: Optional[Config] = None, mode: Optional[str] = None):
        self.config = config or load_config()
        self.mode = mode or self.config.mode

    def _refuse_broken_config(self, command: str, agent_id: str,
                              session_id: str) -> GuardResult:
        """Block, loudly and actionably, when .demo_cli.toml cannot be read.

        A config that is MISSING means "no opinion" and falls back to defaults.
        A config that is PRESENT but unreadable means the user asked for
        protection we cannot deliver - so we refuse rather than proceed
        unguarded. This is fail-closed on the USER'S config, and it does not
        change the separate rule that our OWN bugs still fail open.
        """
        c = Classification(is_destructive=False, is_mutating=False,
                           matched_rule="config_unreadable", segments=[command])
        ctx = build_context(command, cwd=self.config.project_root)
        decision = Decision(
            ESCALATE,
            config_error_message(self.config),
            recoverable=False,
            next_steps=[
                f"Fix {self.config.source_path}",
                "or delete it to fall back to shadow mode (observe only)",
                "a UTF-8 BOM is the usual cause when PowerShell wrote the file",
            ],
        )
        receipt = Receipt(
            action_raw=command, action_type="config", target_environment=ctx.environment,
            decision=decision.decision, reason=decision.reason, mode=self.mode,
            matched_rule="config_unreadable", classification="safe",
            context=ctx.as_dict(), agent_id=agent_id, session_id=session_id,
        )
        try:
            append_receipt(self.config.receipts_path, receipt)
        except Exception:
            pass          # the receipt is evidence, not a precondition for refusing
        return GuardResult(command=command, classification=c, context=ctx,
                           decision=decision, mode=self.mode, receipt=receipt)

    def evaluate(
        self,
        command: str,
        target_path: Optional[str] = None,
        explicit_db: Optional[str] = None,
        db_url: Optional[str] = None,
        intent: Optional[Intent] = None,
        actual_env: Optional[str] = None,
        approval_token: Optional[str] = None,
        agent_id: str = "unknown",
        session_id: str = "unknown",
        dialect: str = POSIX,
    ) -> GuardResult:
        """`dialect` says which shell wrote this text - POSIX or POWERSHELL.
        It decides how line continuations are folded, and the two spellings are
        not interchangeable (see classify.join_continuations). The adapters know
        it from the tool name; everything else keeps the POSIX default."""
        intent = intent or Intent()
        command = command.strip()

        if self.config.config_error:
            return self._refuse_broken_config(command, agent_id, session_id)

        c = classify_pipeline(command, dialect)

        # Writing to a path that does NOT yet exist CREATES it - there is nothing
        # to destroy. classify.py is filesystem-blind (string only), so the
        # correction happens here, where we can stat.
        #
        # Extended past `>` to the PowerShell cmdlets with the same shape:
        # Set-Content / Out-File / New-Item make a new file, and a
        # Move/Copy/Rename -Force onto a free name clobbers nothing.
        #
        # The distinction that matters: a name that RESOLVES but is absent from
        # disk means creation, so the flag is cleared. A name that does not
        # resolve at all is AMBIGUOUS and keeps its classification, so it still
        # escalates - never quietly waved through.
        if c.matched_rule == "fs_redirect_truncate":
            # RESOLVED-AND-ABSENT IS THE ONLY CASE THAT CLEARS. This used to be
            # `redirect_target(command)` on the raw line, and `if not rt or
            # not exists(rt)` - so "I could not find the target" cleared the
            # flag exactly like "the target is new". The comment above has
            # always said the opposite, and the code was the thing that was
            # wrong: five spellings of a truncating redirect reached ALLOW
            # against an existing file with no snapshot and no receipt
            # (2026-09-08). recovery.resolve_redirect_target reads the same
            # effective, substituted segments the classifier judged, so the
            # two can no longer disagree about what the command touches.
            rt, resolved = recovery.resolve_redirect_target(command, dialect)
            if resolved and not os.path.exists(rt):
                c.is_destructive = False
                c.is_mutating = False
                c.matched_rule = None
        elif c.matched_rule in _CREATES_IF_MISSING:
            # Same three-way split as the redirect branch above: only
            # RESOLVED-AND-ABSENT means "creates". An unresolvable name -
            # $env:APPDATA\notes.txt, $(Get-Date).txt - used to come back as a
            # literal that os.path.exists denied, and was read as creation.
            named, resolved = recovery.ps_named_target(command)
            if resolved and not os.path.exists(named):
                c.is_destructive = False
                c.is_mutating = False
                c.matched_rule = None

        # The concrete file list an rm / mv will touch (brace/glob-expanded),
        # surfaced so the preview can PRINT it - the file count the agent was
        # actually asking for (claude-code#76626). Empty for non rm / mv.
        affected_paths = recovery.expanded_operands(command)

        # Whether the USER named a target, captured before the block below
        # overwrites target_path with whatever extraction found. The two mean
        # very different things and sharing one name has already cost a fix.
        user_named_target = target_path is not None

        # Trou 2: when no target was supplied explicitly, resolve the real
        # filesystem operand of an rm / mv so the snapshot actually fires on the
        # auto-fire path (the flagship "rm -> undo" moment). Bounded to the
        # project root so we never try to copy a home/system tree, and honest
        # about multi-path rm (extract_path_operand returns None -> escalate).
        if not target_path and not explicit_db and not db_url:
            cand = recovery.extract_path_operand(command, dialect)
            if cand:
                ap = os.path.abspath(cand)
                root = os.path.abspath(self.config.project_root or os.getcwd())
                try:
                    within = os.path.commonpath([ap, root]) == root
                except ValueError:
                    within = False
                # Refuse the project root itself as a capture surface: a two-file
                # rm at the top level collapses to a common root of the whole
                # project, and silently deep-copying the entire tree on every such
                # rm is neither honest nor cheap. Escalate instead - same spirit
                # as _too_broad refusing $HOME / the filesystem root.
                if within and ap != root and os.path.exists(ap):
                    target_path = ap

        target = recovery.resolve_target(command, explicit_db, db_url, target_path)

        # Trou #004: refuse a PARTIAL snapshot. For a filesystem delete/move whose
        # full operand set we could NOT resolve to an in-root capture (multiple
        # targets, or $()/backtick/globstar expansion we cannot evaluate), the
        # operand extractor returns None. resolve_target may still find a stray
        # .db name - but that covers only PART of what the command destroys. A
        # partial snapshot dressed up as REVERSIBLE is the exact lie this tool
        # exists to prevent, so drop the target and let the mutation escalate
        # honestly instead of claiming a recovery we did not fully take.
        #
        # THE SAME REFUSAL, FOR REDIRECTS. is_fs_delete covers rm / mv /
        # Remove-Item only, so a truncating redirect whose target set could
        # not be resolved walked straight past this and kept whatever stray
        # target resolve_target had found. `echo a > app.db; echo b > o2.db`
        # snapshotted app.db - picked up independently by the sqlite name
        # heuristic - and reported REVERSIBLE while o2.db was truncated with
        # nothing captured. An unearned REVERSIBLE, which is the one failure
        # this tool treats as unacceptable (2026-09-08).
        #
        # resolve_redirect_target already computes exactly the right answer
        # here: (None, False) for two redirecting segments. It was simply
        # being discarded by a path that never asked.
        # MORE THAN ONE SEGMENT DESTROYS SOMETHING, and a snapshot covers one.
        #
        # F2 closed the file-verb half of this in recovery.py - `rm a; mv b c`
        # no longer resolves a target. This is the half recovery.py cannot see:
        # a git or SQL destruction paired with a file delete. The operand
        # extractor resolves old.txt quite correctly, and the receipt then
        # claims a recovery point for a command that also dropped a table.
        #
        #     DROP TABLE users; rm old.txt      -> was REVERSIBLE
        #     git reset --hard; rm old.txt      -> was REVERSIBLE
        #
        # An explicit --target is left alone: the user named what they wanted
        # captured, and overriding that would be its own kind of dishonesty.
        multi_destructive = (c.destructive_segments > 1
                             and not user_named_target
                             and not explicit_db and not db_url)

        unresolved_redirect = (
            c.matched_rule == "fs_redirect_truncate"
            and not recovery.resolve_redirect_target(command, dialect)[1])
        if target is not None and (
                (target_path is None
                 and (recovery.is_fs_delete(command) or unresolved_redirect))
                or multi_destructive):
            target = None

        label = target.label if target else None

        # Declared-first environment: config target match feeds the context.
        config_env = self.config.declared_env(label)
        ctx = build_context(command, target_label=label,
                            declared_env=actual_env, config_env=config_env,
                            cwd=self.config.project_root)

        mismatches = compare_intent(intent, ctx)

        # Snapshot the *real* target, honouring the per-target recovery strategy.
        rule = self.config.match_target(label)
        strategy = rule.recovery if rule else "snapshot"

        # Managed / remote Postgres: a pg_dump over the wire is not a recovery
        # point we can stand behind for a system we don't control, so treat it
        # as a non-recoverable surface (honest escalation) instead of claiming
        # reversibility. Local Postgres (localhost) still snapshots normally.
        remote_pg = bool(target and target.kind == "postgres" and recovery.is_remote_pg(target.ref))
        if remote_pg and not c.nonrecoverable_surface:
            c.nonrecoverable_surface = "managed_database"

        # An ignored directory the command reaches into must be captured after
        # all - otherwise the snapshot silently omits part of the damage while
        # the entry looks complete. See recovery.unignorable_dirs.
        reached = recovery.unignorable_dirs(command, dialect)
        keep_out = (None if not reached
                    else frozenset(recovery.IGNORED_DIRS) - reached)
        entry = (recovery.snapshot(target, self.config.recovery_dir, strategy,
                                   action=command, ignore_dirs=keep_out)
                 if (c.needs_recovery and not remote_pg) else None)

        # LAST RESORT, never a first choice. Reached only when the command
        # mutates something and no target could be resolved at all - `rm
        # $(cat list.txt)`, `python cleanup.py`. Instead of escalating on "I
        # cannot tell WHAT you will destroy", preserve everything it could
        # destroy. If that copy cannot be made honestly, checkpoint.capture
        # returns no entry and the escalation stands exactly as before.
        #
        # Placed here, BEFORE decide(): decide is still merely told whether a
        # recovery exists. It never learns a checkpoint was involved, so it
        # cannot reason its way into claiming one that did not happen.
        checkpoint_skipped, checkpoint_taken = None, False
        if checkpoint.should_checkpoint(c, target, self.config,
                                        recovery_captured=entry is not None):
            ck = checkpoint.capture(self.config, action=command)
            entry, checkpoint_skipped, checkpoint_taken = ck.entry, ck.skipped, ck.ok

        recovery_captured = entry is not None

        # Preview affected rows for previewable SQL on a recoverable target.
        preview_count, preview_rows, preview_cols = None, [], []
        if recovery_captured and is_sql_preview_candidate(command):
            preview_count, preview_rows, preview_cols = preview_mod.preview(command, target)

        # Structural approval (only meaningful for the non-recoverable case).
        approval_ok = False
        key = self.config.approver_key
        if approval_token and key:
            approval_ok = approval.verify(command, approval_token, key)

        decision = decide(
            c, ctx.environment, recovery_captured,
            mismatches=mismatches, approval_ok=approval_ok, preview_count=preview_count,
        )

        # Say which kind of recovery this is. A whole-workspace checkpoint is
        # COARSE - undo restores the entire tree to its snapshot state, rolling
        # back unrelated edits made afterwards. Someone reading the receipt has
        # to be able to tell that from a one-file snapshot, and someone whose
        # action was blocked has to be told why the checkpoint was refused.
        reason = decision.reason
        if checkpoint_taken:
            reason = (f"{reason} Recovery is a whole-workspace checkpoint "
                      f"(coarse): the target could not be resolved from the "
                      f"command text, so everything it could destroy was "
                      f"preserved. Undo restores the entire tree.")
        elif checkpoint_skipped:
            reason = f"{reason} {checkpoint.reason_text(checkpoint_skipped, self.config)}"

        receipt = Receipt(
            action_raw=command,
            action_type=c.action_type,
            target_environment=ctx.environment,
            decision=decision.decision,
            reason=reason,
            mode=self.mode,
            matched_rule=c.matched_rule,
            classification="destructive" if c.is_destructive else ("mutating" if c.is_mutating else "safe"),
            recovery_point=entry["recovery_point"] if entry else None,
            nonrecoverable_surface=c.nonrecoverable_surface,
            dry_run_affected_rows=preview_count,
            context=ctx.as_dict(),
            declared_intent=intent.as_dict(),
            context_mismatches=[list(m) for m in mismatches],
            pipeline_segments=c.segments if c.is_pipeline else [],
            remote_exec=c.remote_exec,
            agent_id=agent_id,
            session_id=session_id,
        )
        append_receipt(self.config.receipts_path, receipt)

        return GuardResult(
            command=command, classification=c, context=ctx, decision=decision, mode=self.mode,
            target=target, recovery_entry=entry,
            preview_count=preview_count, preview_rows=preview_rows, preview_cols=preview_cols,
            mismatches=mismatches, affected_paths=affected_paths, receipt=receipt,
        )

    def evaluate_file_edit(
        self,
        file_path: str,
        tool_name: str = "Edit",
        intent: Optional[Intent] = None,
        agent_id: str = "unknown",
        session_id: str = "unknown",
    ) -> GuardResult:
        """Evaluate an agent file mutation (Edit / Write / MultiEdit / Notebook).

        This is the second door: agents mangle files through file-write tools,
        not only through Bash. We snapshot the *existing* file before it is
        overwritten so the change is reversible, and record a receipt. Creating
        a brand-new file has nothing to overwrite, so it proceeds with no
        snapshot. If an existing file cannot be snapshotted, we escalate rather
        than claim a recovery we did not take.
        """
        from .classify import Classification

        intent = intent or Intent()
        if self.config.config_error:
            return self._refuse_broken_config(f"{tool_name} {file_path}",
                                              agent_id, session_id)
        ap = os.path.abspath(file_path)
        exists = os.path.exists(ap)
        is_dir = exists and os.path.isdir(ap)

        c = Classification(
            is_mutating=True, action_type="filewrite",
            matched_rule=f"file_{tool_name.lower()}", segments=[ap],
        )

        target = recovery.Target("dir" if is_dir else "file", ap, ap) if exists else None
        label = target.label if target else None
        config_env = self.config.declared_env(label)
        ctx = build_context(f"{tool_name} {ap}", target_label=label,
                            config_env=config_env, cwd=self.config.project_root)

        rule = self.config.match_target(label)
        strategy = rule.recovery if rule else "snapshot"
        entry = (recovery.snapshot(target, self.config.recovery_dir, strategy,
                                   action=f"{tool_name} {os.path.basename(ap)}")
                 if exists else None)
        recovery_captured = entry is not None

        if not exists:
            decision = Decision(ALLOW, "New file; creation has nothing to overwrite.",
                                recoverable=False)
        elif recovery_captured:
            decision = Decision(REVERSIBLE, "File snapshotted before the edit; reversible.",
                                recoverable=True)
        else:
            decision = Decision(
                ESCALATE,
                "Could not snapshot the file before editing; no recovery path.",
                recoverable=False,
                next_steps=["Check the file is readable and within the project root."],
            )

        receipt = Receipt(
            action_raw=f"{tool_name} {ap}",
            action_type="filewrite",
            target_environment=ctx.environment,
            decision=decision.decision,
            reason=decision.reason,
            mode=self.mode,
            matched_rule=c.matched_rule,
            classification="mutating",
            recovery_point=entry["recovery_point"] if entry else None,
            context=ctx.as_dict(),
            declared_intent=intent.as_dict(),
            agent_id=agent_id,
            session_id=session_id,
        )
        append_receipt(self.config.receipts_path, receipt)

        return GuardResult(
            command=f"{tool_name} {ap}", classification=c, context=ctx,
            decision=decision, mode=self.mode, target=target, recovery_entry=entry,
            receipt=receipt,
        )
