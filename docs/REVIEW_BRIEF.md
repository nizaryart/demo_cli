# Reviewer brief — demo_cli

Read this before reviewing. It exists because 12.4k lines carry decisions that
look wrong and are not, and a review that spends its first pass on those finds
nothing real. Everything below is stated so you can attack it, not so you can
accept it.

- **Repository:** `nizaryart/DEMO_LOADING`, branch `wepwn/redteam`, tag `v1.0.6`
- **Size:** 12,429 lines of source across 28 modules, 8,410 lines of test
- **Suite:** 826 passing, identical on Linux and Windows from the same commit
- **Platforms:** Linux (primary) and Windows 10 / PowerShell 5.1. No macOS.

---

## 1. The one invariant

```
mutating_actions_must_be_recoverable_and_match_the_declared_context
```
`src/demo_cli/decide.py:52`

Every decision resolves to one of five dispositions:

| | meaning |
|---|---|
| `ALLOW` | non-mutating; nothing to do |
| `DRY_RUN` | mutating, but the command will not commit |
| `REVERSIBLE` | mutating, **and a recovery point was actually captured** |
| `CONTEXT_MISMATCH` | declared environment does not match the resolved one |
| `ESCALATE` | mutating and not provably recoverable → refuse |

**The only failure that matters is an unearned `REVERSIBLE`.** A user who
believes their work is recoverable and finds it is not is the product failing
at its single job. An unearned `ESCALATE` breaks the same invariant in the
other direction and is a nuisance, not a defect worth a finding.

So: **do not report over-blocking.** Report anything that lets the tool claim
a recovery it does not have.

---

## 2. Threat model

**In scope — cooperative agents making mistakes.** An LLM that runs
`rm -rf $BUILD_DIR` with `BUILD_DIR` unset, deletes the wrong glob, or drops a
table it misread. The agent is not adversarial; it is confidently wrong.

**Out of scope — an agent deliberately evading classification.** Base64
payloads, `eval`, character-class obfuscation. No pre-execution hook solves
that and the project does not claim to. Findings of the form "I can bypass the
classifier by writing the command differently" are already-known and by
design; the behavioural layer exists precisely because the string layer cannot
be a security boundary.

**The distinction that matters for you:** an *honest* command that is
misjudged into a false `REVERSIBLE` is a real finding. A *crafted* command
that evades the classifier is not.

**Also out of scope:** a local user attacking their own machine as
Administrator/root. The privilege separation assumes the agent has fewer
privileges than the guard, and `setup` arranges that.

---

## 3. The four layers, and what each is *not* for

| Layer | Sees | Entry point | Linux | Windows |
|---|---|---|---|---|
| String | the command text, pre-execution | `hooks/claude_code.py`, `cursor.py`, `codex.py` | yes | yes |
| Shell | commands typed in the agent's `!` mode | `BASH_ENV` + bash `DEBUG` trap | yes | **absent** |
| Behavioural | the operation as it happens | `syscall_guard.py` (ptrace) / `fsmount.py` (WinFsp) | `demo_cli run` | mounted |
| Egress | the HTTP request | `egress_addon.py` (mitmproxy) | yes | yes |

Two different gaps, deliberately answered by different layers:

- **Classification gap** — `python cleanup.py` is opaque. The text reveals
  nothing. Only the behavioural layer can answer it.
- **Resolution gap** — `rm $(cat list.txt)` is known-dangerous but its target
  cannot be resolved before it runs. `checkpoint.py` answers this one by
  capturing the project root, or refusing.

The string layer is a *classifier*, not a sandbox. Judge it on whether it
misjudges honest input, never on whether it can be fooled.

---

## 4. Trust boundaries

**Windows — the one that carries weight:**

```
C:\project        the WinFsp mount (an NTFS reparse point). Agent writes here.
C:\project.real   the backing. ACL: Administrators + SYSTEM only.
```

The separation **is a privilege difference and nothing else**. An unelevated
agent cannot open the backing, so every write it makes goes through the guard.
This holds exactly as long as the agent is less privileged than the guard.

Attack this. Specifically: reaching the backing by another name (junction,
`\\?\`, device path, UNC, 8.3 short name, a volume shadow copy), racing the
mount at startup or teardown, and whether the ACL survives operations that
normally drop ACLs.

**Linux:** no equivalent separation. `demo_cli run` is opt-in per command and
the ledger is ordinary user-owned files. Root on Linux is game over and is out
of scope.

**The ledger:** two hash chains — `main` (hook, CLI, egress, written through
the mount) and `fs` (the filesystem guard, written in the backing). They are
separate because a byte-range lock taken through WinFsp and one taken on NTFS
are **different locks**, so one file was being interleaved and torn. Each
receipt records `peer_head`: the other chain's head hash at write time. That
closes truncation, which a lone chain cannot detect — cut the tail and what
remains verifies perfectly.

Known and stated: someone who controls **both** files can rewrite both
consistently. The chain is tamper-**evident**, not tamper-proof. Off-machine
anchoring of the head hashes is the intended answer and is not implemented.

---

## 5. Looks wrong, is deliberate — do not re-report

Each of these has an incident behind it.

**`rm_rf` is unanchored and over-fires.** `classify.py:39` matches `rm` with
`-r` and `-f` anywhere in a segment, so `echo "run rm -rf later"` is flagged.
The cost was accepted for coverage, and `tests/test_nested_redirection.py`
pins it so nobody "fixes" it without seeing what else changes. It is also why
two nested-shell bugs survived for weeks: the unanchored rule kept firing on a
mangled payload, so the command still looked destructive and only its *operand*
went missing.

**`del_force` requires `/f` or `/s`.** `classify.py:97`. Narrow on purpose —
the perimeter is destructive *forms*, never whole command families.

**`is_locked()` returns `Optional[bool]`.** `protect.py:475`. `None` means "I
cannot tell" and is not `False`. Reporting "not locked" for an unreadable ACL
is a false alarm; reporting "locked" is a false all-clear. Same pattern in
`mountstate.MountStatus.running` and `deps.Dep.present`.

**`lock_directory()` runs `icacls` twice and never passes `/C`.**
`protect.py:381`. One combined call with `/T` strips inherited access from
every existing child and has its `(OI)(CI)` grant rejected on files, leaving
them with an **empty DACL** — unreadable by anyone including their owner.
`/C` then swallows the error and icacls exits 0. Found live 2026-08-25.

**`ensure_workspace()` refuses rather than creates.** `config.py:149`. It used
to call `os.makedirs`, which creates parents — and on a protected project the
parent *is* the mount point, which exists only while the guard runs. Running
the diagnostic while the guard was down left a real directory where the mount
belonged and the guard could never return. A diagnostic that bricked what it
diagnosed.

**The Claude Code adapter fails open on its own errors; the Cursor adapter
fails closed.** `hooks/claude_code.py:96` vs `hooks/cursor.py:21`. Different
hosts, different defaults: Cursor fails open by default so the adapter must
invert it; Claude Code must never be bricked by a bug in this tool. The
*decision* is always fail-closed in both.

**`_mount_checks` refuses to name a cause** for a guard that is not running.
`cli.py`. It says "see the winfsp lines above". Three separate diagnostics in
this project reported a permissions cause for a non-permissions failure, and
the generalisation is recorded: *a diagnostic that can only name one cause
will name it wrongly.*

**`recovery._too_broad()` refuses `$HOME`, filesystem root, drive roots, and
the project root itself.** A two-file `rm` at the top of a repo collapses to a
common root of the whole tree; silently deep-copying it on every such delete
is neither honest nor cheap, so it escalates.

**`checkpoint.capture()` returns `skipped=<reason>` rather than a partial
capture.** A checkpoint that did not complete is never reported as
`REVERSIBLE`.

**`fsmount.absolute_target()` exists because WinFsp speaks mount-relative
paths.** Recording `notes.txt` in the ledger meant `undo` resolved it against
whatever directory it ran from and restored the file *outside* the mount while
reporting RESTORED.

---

## 6. Where I would look first

Written by the person who built most of this, so treat it as a starting point,
not a boundary — and note that **every real defect in this project has been
found by running the tool, not by reading it.** Nothing here was found by
reading either.

1. **`cli.py` is 2,467 lines** and holds command handlers alongside diagnostic
   logic. Highest density of untested branches; the newest code (`cmd_protect`'s
   relock repair, `_relock_target`) is days old and exercised on hardware only
   a handful of times.
2. **`recovery.py` (1,234 lines)** — operand extraction, glob and brace
   expansion, the multi-path collapse rule, and the size cap. The place where a
   false `REVERSIBLE` is most likely to originate: anything that makes
   `extract_path_operand` return a path it should not resolve.
3. **`_relock_target`** applies an Administrators-only ACL. A false positive
   locks unrelated data away. It requires demo_cli's own mount record to name
   the exact backing — check whether that record can be influenced.
4. **`protect.rerun_elevated`** — `ShellExecuteExW` argument construction, what
   the elevated child inherits, and whether any argument crosses a trust
   boundary. It gained `lpDirectory = os.getcwd()` on 2026-09-02.
5. **`receipts.append_receipt` locking** across the WinFsp/NTFS split, and
   `peer_head` staleness. The cache is keyed on `(st_size, st_mtime_ns)` after
   a time-based cache was found to leave the newest entries unanchored.
6. **`guarded.child_env`** — what is passed down to the agent process.
7. **`config.redirect_to_mount` / `DEMO_CLI_FS_GUARD`** — the guard must not
   redirect itself. Getting this wrong makes the fs layer write to the wrong
   ledger, which happened once.

---

## 7. Already known — do not spend time here

- Windows has no `!`-mode shell capture (no PowerShell `DEBUG` trap equivalent)
- Codex on Windows is untested; assume no protection there
- `demo_cli log` renders `0B` for a recovery point it cannot stat through an
  ACL — "0 bytes" and "cannot see it" share a rendering
- `guarded` stops the proxy it started only on a clean exit; `teardown` does
  not check the port
- **`CREATE_NO_WINDOW` is unverified on Windows.** `_mount_detached` was changed
  on 2026-08-29 from `DETACHED_PROCESS | CREATE_NO_WINDOW` to
  `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`, because Windows documents the
  first flag as ignored when the second is set — so the guard ran with a
  visible console a user could close, killing it. The reasoning is recorded;
  the fix has never been re-tested on hardware. Treat the *consequence* as one
  observation, not as established
- Directory restore is coarse by design: the whole captured directory reverts
- Single undo depth per recovery point
- Databases: SQLite and Postgres only
- Shell parsing is pattern-based, not a full AST; ambiguous parses escalate
- The `Not elevated, so the backing will NOT be locked` warning prints before
  `setup` elevates and then locks anyway — known wording defect

---

## 8. What a finding needs

1. The concrete input or machine state
2. The wrong outcome, specifically — and whether it produces a false
   `REVERSIBLE`, which is the severity axis that matters here
3. Verification against the code before reporting

A plausible-sounding finding that does not hold costs more than it saves. This
project has a standing rule that a claim needs evidence, and it applies to
reviews of it too.
