# demo_cli

**Claude Code and Cursor *ask* you to confirm dangerous commands, or *block* them. Their checkpoints cover the agent's own file edits — not shell commands or databases, which is where the destructive ones live.**

demo_cli snapshots the real target **before** a destructive command runs, so a wrong call is reversible with one command. **Confirming ≠ recovering.**

Before `rm -rf`, `rmdir /s /q`, `Remove-Item -Recurse -Force`, `git reset --hard`, or `DROP TABLE` executes, demo_cli captures what's about to be destroyed and writes a hash-chained receipt of the decision. If the agent gets it wrong, `demo_cli undo` brings it back. When it *can't* prove recovery (`terraform destroy`, `git push --force`, remote/cloud resources, or a recursive-force delete with no recoverable target), it hard-blocks instead of faking safety.

The whole design in one line: **recovery is the default; blocking is the fallback for the truly unrecoverable, not the default for everything.**

![demo_cli snapshots before an agent's rm, lets it run, and undoes it in one command](https://cdn.wepwn.ma/images/demo/demo_recover.gif)

*A real session. The agent's delete is **not** blocked, it runs, the files really are gone, and one command brings them back. It echoes [claude-code#76626](https://github.com/anthropics/claude-code/issues/76626), where an agent ran `rm -f Reports/report_*.txt Reports/report_*.png` intending only to count the files. A CLI delete never lands in the recycle bin, and if the files aren't in git the only paths left are luck and file-carving tools like Recuva, which recover some fraction, not reliably all. A recovery point taken **before** the command removes the guesswork: it restores exactly the captured state.*

### Start in shadow mode, it changes nothing

Default mode is observe-only: it logs what it *would* have caught and touches nothing. Run it a week on a low-stakes project, read the receipts, then decide whether to let it act.

```bash
# one line: installs demo_cli and its prerequisites, then verifies the install.
# it touches no project of yours - wiring one up is `demo_cli setup`, below.
# pinned to a release tag, not a moving branch. read it first: install.sh
curl -fsSL https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.7.0/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.7.0/install.ps1 | iex
```

It ends by running `demo_cli doctor`, which names every missing prerequisite
with the exact command that fixes it, and fails **loud** if `demo_cli` is not
reachable on the PATH your agent's shell will actually have — the one case
where Claude Code skips protection silently.

The installer **refuses to run elevated**, on both platforms. `pipx` installs
per user, so an elevated install puts `demo_cli` on the administrator's PATH
and leaves it missing from the shell where your agent runs: the hook
registers, `doctor` looks green, and nothing is ever gated. The one step that
genuinely needs Administrator (the WinFsp driver on Windows) raises its own
prompt when it gets there.

(Yes, it's `curl | sh`, the exact opaque-execution pattern demo_cli itself
escalates. Read it first: [install.sh](install.sh), ~180 lines.) Prefer to do
it by hand? See [Install](#install) below.

### Why you can trust it

- **No telemetry, it phones nobody.** There is no network I/O anywhere in the
  codebase. Verify it yourself — this returns nothing:
  `grep -rn "urlopen\|requests\|httpx\|socket\|http.client" src/`
  (`urllib.parse` does appear twice, for string handling only: building the
  prefilled GitHub issue link, and reading the hostname out of a DB connection
  string to tell local from remote. Neither opens a connection.)
- **One small, readable, MIT-licensed codebase**, read exactly what it does before you run it.
- **Hash-chained receipts**, every decision linked to the one before it and
  independently verifiable (`demo_cli verify`). What that does and does not
  buy you is set out under [What the receipt chain proves](#what-the-receipt-chain-proves)
  — the honest summary is that it detects an *edit*, and detecting a *rewrite*
  needs a head hash you have recorded somewhere else.

When it captures a recovery point, the hook prints it where you can see it — the
snapshot id, the one-line undo, and (on a wrong call) a prefilled report link.
No telemetry: the only signal it ever sends is the one you choose to send by
clicking. If it saves you something, a ⭐ on the repo is how it survives.

### "Why not just use git / Claude Code checkpoints?"

git and Claude Code's rewind can't recover an `rm -rf` outside the repo, a dropped database, or an overwrite of an untracked file, they don't snapshot before shell commands run. That's the exact gap demo_cli fills.

> **Threat model:** cooperative agents making mistakes, not adversarial evasion. An agent actively trying to evade protection is out of scope, no hook solves that.

`1.7.0`. Four guard layers on Linux, three on Windows (no shell layer there yet).

Built around one invariant:

> A mutating action must be recoverable **and** match its declared context, otherwise it is escalated, never silently allowed, and never falsely reported as "recovered".

---

## Why this is not just another blocking hook

Most safety hooks for AI agents do one thing: pattern-match a dangerous command
and **block** it. That stops the obvious disasters, but it also stops the agent
mid-task, so you either loosen the rules until they stop catching things, or
you babysit the session.

demo_cli starts from the opposite default: **recovery, not blocking.**

- For anything it can prove it captured (a file, a directory, a local DB), it
  **snapshots first and lets the agent keep working.** If the agent gets it
  wrong, `demo_cli undo <id>` brings it back. The work finishes; the mistake is
  reversible.
- It only **blocks** when something genuinely *can't* be recovered: an external
  or irreversible effect (`terraform destroy`, `git push --force`, an object-store
  delete), or a recursive-force delete that leaves no recoverable target. A
  Windows `Remove-Item -Recurse -Force` with a single, existing, in-project
  target is snapshotted and allowed, same as `rm -rf`; `rmdir /s` and `del /s`
  remain a hard-stop in every environment until they get the same honest
  target extraction. There, it escalates honestly instead of pretending it
  captured a recovery point.

Blocking is the fallback for the un-recoverable, not the default for everything.
That's the whole design.

### Four layers, because a command line is not the whole truth

The hook reads the command **text**. That is enough for `rm -rf ./build`, and
not enough for `python cleanup.py` — which is opaque, or `rm $(cat list.txt)`
— which is obviously dangerous and whose target cannot be resolved before it
runs. Those are two different gaps, and they need different answers.

| Layer | What it sees | How | Linux | Windows |
|---|---|---|---|---|
| **String** | the command, before it runs | agent hook (Claude Code, Cursor, Codex) | yes | yes |
| **Shell** | commands you type yourself in the agent's `!` mode | bash `DEBUG` trap via `BASH_ENV` | yes | — |
| **Behavioural** | what is *actually* being destroyed, at the moment it happens | `ptrace` / a WinFsp filesystem guard | `demo_cli run` | mounted |
| **Egress** | the HTTP request an obfuscated command cannot hide | mitmproxy addon | yes | yes |

The behavioural layer is the one that answers the opaque command. On Linux it
traces syscalls; on Windows the project directory becomes a user-mode
passthrough filesystem, so a delete is seen as an *operation* rather than
inferred from a string. Neither is a substitute for the other layer — a
snapshot taken because the kernel told you a file was about to be truncated is
worth more than one taken because a regex matched.

**Windows has no shell layer** and this is stated, not hidden: there is no
`DEBUG` trap in PowerShell, so commands you type in `!` mode there are not
captured. `demo_cli doctor` reports coverage honestly rather than implying
four layers everywhere.

### And when it cannot recover, it says so

![demo_cli refuses an rsync to a remote host and explicitly refuses to claim a recovery point](https://cdn.wepwn.ma/images/demo/demo_honest.gif)

*An `rsync --delete` to a production host over SSH. No snapshot on your machine
can reach the far end of that connection, so demo_cli does not take one and does
not pretend it did. The most important line a safety tool can print is the one
admitting what it did not do.*

---

## How it works with Claude Code

Claude Code supports [PreToolUse hooks](https://docs.claude.com/en/docs/claude-code/hooks):
a shell command that runs **before each tool call**, receives the full tool input
as JSON on stdin, and returns a permission decision. demo_cli is that command.

```
Claude Code is about to run: Bash(rm -rf dist/)
                              ↓
              demo_cli hook  (fires automatically)
                              ↓
         classify → resolve target → snapshot → decide
                              ↓
        { "permissionDecision": "allow" }   ← allow, with a recovery point
        { "permissionDecision": "deny"  }   ← blocked, reason surfaced to agent
        { "permissionDecision": "ask"   }   ← paused, human decides
```

**One property worth knowing:** a PreToolUse hook returning `deny` stops the tool
**even when the session is running `--dangerously-skip-permissions` or
`bypassPermissions`**, that mode skips the interactive prompts, not the hooks.
So the recovery-and-escalation layer holds even in a fully autonomous run. (The
one way it does *not* fire: if the `demo_cli` binary isn't on PATH in the shell
where `claude` launched, Claude Code silently proceeds with no check, see
[Known issues](#known-issues-beta). Run `demo_cli doctor` to confirm.)

demo_cli gates **both** tool categories Claude Code uses to modify your project:
- `Bash` - shell commands (`rm`, `git reset --hard`, `terraform destroy`, …)
- `Edit` / `Write` / `MultiEdit` / `NotebookEdit` - direct file mutations

A file or directory is snapshotted **before** it is touched. If the agent
destroys something, `demo_cli undo <id>` brings it back.

---

## How it works with Cursor

Cursor supports [hooks](https://cursor.com/docs/hooks): scripts it runs at named
points in the agent loop. demo_cli registers a `beforeShellExecution` hook that
receives the command as JSON on stdin (`command`, `cwd`, …) and returns a
permission decision.

```bash
demo_cli install-hook --cursor          # writes .cursor/hooks.json (project)
demo_cli install-hook --cursor --scope global   # or ~/.cursor/hooks.json
demo_cli install-hook --cursor --print  # inspect the snippet without writing
```

The installed hook looks like this:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "demo_cli hook-cursor", "failClosed": true }
    ]
  }
}
```

Two Cursor-specific properties, both handled deliberately:

- **`failClosed: true` is mandatory.** By default Cursor *fails open*: a hook
  that crashes, times out, or emits invalid JSON lets the command through.
  `failClosed: true` inverts that, a guard that cannot run blocks instead. The
  adapter also fails closed *inside* the script: if it holds a real command it
  cannot evaluate, it returns `deny` (the opposite of the Claude Code adapter's
  fail-open on internal error). The one exception is Cursor's known empty-stdin
  defect on some remote workspaces, where there is no command to judge, so it
  steps aside rather than brick the session.
- **Only `deny` is reliably honored today.** Cursor's own allow-list can
  override an `allow`/`ask` from a hook. That is fine here: the whole move is to
  *deny the unrecoverable*, which is exactly the decision Cursor respects. So a
  recursive-force delete on Cursor is stopped by the same rule that stops it in
  Claude Code.

Scope for this beta: the Cursor adapter gates **shell commands** only
(`beforeShellExecution`). File-edit gating is Claude Code only for now.

---

## How it works with Codex

Codex supports hooks through `~/.codex/hooks.json`. demo_cli registers a
`PreToolUse` handler that gates both `Bash` and Codex's `apply_patch`.

```bash
demo_cli install-hook --codex
```

Two things learned the hard way, and worth knowing before you trust any hook
installer:

- **Codex's config is nested** — a group with an optional `matcher`, containing
  handlers tagged `type: "command"`. Written in the flat form, Codex parses it,
  silently discards it, and reports nothing. The installer said "Installed" and
  there was no hook, no error and no protection.
- **Installed is not active.** After that, `demo_cli doctor` stopped trusting
  configuration files as evidence. It reports, per host, whether a receipt has
  ever actually been written by an agent — the only proof that the guard is in
  the loop.

---

## How it works on Windows

The behavioural layer on Linux is `ptrace`. Windows has no equivalent that
avoids signing your own kernel driver, so demo_cli uses **[WinFsp](https://winfsp.dev)**,
whose driver ships already signed, and implements the guard in user mode on top
of it — the same arrangement as shelling out to `mitmdump` or `pg_dump` rather
than bundling them.

```
your agent writes to       C:\project          <- the mount (a reparse point)
                                 |
                           WinFsp driver (signed, third-party)
                                 |
                           demo_cli's filesystem guard   <- sees the operation,
                                 |                          snapshots, then
your real files live in    C:\project.real     <- passes it through
                           ACL: Administrators + SYSTEM only
```

**The project directory keeps its path.** `setup` moves your files to
`<project>.real` and mounts the guard at the original location, so nothing in
your tooling has to change and there is no unguarded path to write through.
The backing directory is locked to three entries: Administrators and SYSTEM
at full control, and **OWNER RIGHTS (`S-1-3-4`) at `(RC)`** — read the ACL and
nothing else.

That third entry is the one that makes the lock work, and it is not obvious.
Granting a directory to Administrators does not stop *its owner*, and moving a
project preserves ownership — so the user still owns the backing afterwards,
and an owner holds `READ_CONTROL` and `WRITE_DAC` **implicitly**, not through
any ACE. There is nothing in the ACL to remove. An explicit OWNER RIGHTS entry
replaces those implicit rights with whatever it says. Verified on Windows 10,
unelevated, with the lock applied: reading the files is denied, granting
yourself access is denied, moving the directory is denied, and reading the ACL
still works — which is what lets `doctor` tell you the lock is there without
asking for a password.

**Which is why you launch the agent unelevated.** The guard holds exactly as
long as the agent has fewer privileges than it does. `setup` arranges that,
`guarded` keeps it, and `doctor` warns you if the shell you are standing in
would break it.

Two things this does **not** cover, stated because a lock you misjudge is
worse than one you know the edges of:

* **A handle opened before `protect` ran stays valid.** Windows checks
  permissions when a file is opened, not on every read and write. Start the
  guard before the agent, not after.
* **The lock is shaped by who owns the project.** If you created it in an
  elevated shell, Windows made *Administrators* the owner — the OWNER RIGHTS
  entry then caps a principal you are not, you are denied everything including
  the ACL, and `demo_cli` reports the lock state as *unknown* rather than
  guessing. Stronger, but noisier. A project you made normally is the case
  described above.

### Prerequisites

Install **WinFsp** with the Developer feature, then the Python binding:

```powershell
winget install --id WinFsp.WinFsp --custom "ADDLOCAL=ALL"
pipx inject demo-cli winfspy
```

`install.ps1` does both for you and confirms the result by reading the
registry rather than trusting an exit code. If you skip WinFsp entirely,
everything else still works — you get the string and egress layers, and
`doctor` says so plainly instead of failing.

### Guarding a project

```powershell
cd C:\Users\you\Desktop      # NOT inside the project - a process's cwd
                             # holds the directory open and it cannot move
demo_cli setup C:\path\to\project
```

`setup` writes the config, installs a hook for every host present, **moves
your files** (printing exactly what it will do and asking first), locks the
backing, registers a logon task so the guard returns after a reboot, and
mounts. Then:

```powershell
demo_cli guarded claude          # start the agent with every available layer up
demo_cli doctor                  # coverage, prerequisites, and what is missing
demo_cli teardown <project>      # reverse all of it, in any machine state
```

`teardown` stops the guard, removes the logon task, moves your files back and
removes the hooks. It deliberately leaves the config and receipts — they are
your audit trail.

### The receipt ledger is split, and cross-linked

The hook writes through the mount; the filesystem guard writes underneath it.
Those are different lock domains — a byte-range lock taken through WinFsp and
one taken on NTFS are not the same lock — so a single append-only file gets
interleaved and torn. demo_cli keeps two chains and **anchors each receipt to
the other chain's head hash at the moment it was written**.

That is not bookkeeping. A lone hash chain cannot detect truncation of its own
tail: cut the last N entries and what remains verifies perfectly. An anchor in
the other chain proves those entries existed. `demo_cli verify` reports both
chains, the cross-links it resolved, and distinguishes five outcomes — VERIFIED,
DAMAGED, OUT OF ORDER, TAMPERED, and NO RECEIPTS — instead of collapsing an
empty ledger into "tampered".

---

## Install

Requires Python 3.9+. The filesystem guard on Windows additionally requires
[WinFsp](https://winfsp.dev) — see [Prerequisites](#prerequisites). Everything
else works without it.

> **Pin to a release, not to `beta`.** The commands below reference a fixed,
> tagged release so you get exactly the code you reviewed. `@beta` is a moving
> branch and can change under you; use it only if you specifically want the
> latest unreleased commit. Replace `v1.7.0` below with the
> [latest release](https://github.com/nizaryart/DEMO_LOADING/releases) if a newer one exists.

**Manual, verify before you run (recommended).** Read the source and confirm the
artifact's checksum before anything executes. Nothing is piped into a shell:

```bash
# 1. read the release notes + published SHA-256 on the release page:
#    https://github.com/nizaryart/DEMO_LOADING/releases/tag/v1.7.0
#
# 2. install that exact tag (pipx puts demo_cli on your global PATH so
#    Claude Code finds it from any project directory):
pipx install "git+https://github.com/nizaryart/DEMO_LOADING.git@v1.7.0"
demo_cli --version        # should print 1.7.0

# 3. wire the hook into this project (shadow mode by default) and confirm it fires
demo_cli init && demo_cli install-hook && demo_cli doctor
```

Step 3 sets up the **string layer** only, and moves nothing. For every layer
this machine can run — including the filesystem guard, which relocates your
project — use `demo_cli setup <project>` instead. It prints what it will move
and asks before it does.

**From a clone (read everything first, verify the tag):**

```bash
git clone https://github.com/nizaryart/DEMO_LOADING.git
cd DEMO_LOADING
git checkout v1.7.0
git verify-tag v1.7.0   # if the release is signed; otherwise skip
pipx install -e .
demo_cli --version
```

**One line (convenience only).** This is `curl | sh`, the exact opaque
fetch-and-run pattern demo_cli itself escalates. It's here because it's
convenient, not because it's the safe way. Read the script first:
[install.sh](install.sh) / [install.ps1](install.ps1). They prepare the
machine — Python, pipx, WinFsp, demo_cli — and touch no project of yours.

```bash
curl -fsSL https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.7.0/install.sh | sh
```
```powershell
irm https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.7.0/install.ps1 | iex
```

Every path ends by running `demo_cli doctor`, which fails **loud** if the hook
is installed but not reachable on your PATH — the one case where Claude Code
would otherwise skip protection silently.

> **Note:** if you install inside a virtualenv, that venv must be active in
> every shell where you launch `claude`. Otherwise the `demo_cli hook` command
> is not found and Claude Code proceeds without a safety check. `demo_cli doctor`
> catches this.

---

## Quickstart

```bash
# inside your project
demo_cli init            # write .demo_cli.toml (shadow mode by default)
demo_cli install-hook    # register the PreToolUse hook in .claude/settings.json
demo_cli status          # confirm: hook installed, mode shadow, 0 receipts
```

Now launch Claude Code and ask it to do something destructive. demo_cli fires
automatically, no extra commands needed. Afterwards:

```bash
demo_cli log             # see every recovery point: id, when, kind, size, action
demo_cli diff <id>       # what exactly changed
demo_cli undo <id>       # restore to the state before that action
demo_cli verify          # confirm the receipt log was not tampered with
```

To evaluate a command manually (useful for testing or CI):

```bash
demo_cli check "DELETE FROM users WHERE plan = 'free'" --db app.db
demo_cli check "rm -rf dist/" --quiet
demo_cli check "terraform destroy" --actual-env production --json
```

---

## Modes

**shadow** (default), observe, snapshot, and record, but never block. The
recommended way to start: prove the value with zero workflow disruption. In
shadow mode the hook writes to stderr when it captures a snapshot or sees a
blocking decision, so the value is visible without affecting Claude Code's flow.

**enforce** - the hook actively gates tool calls:

| Disposition | Hook response | When |
|---|---|---|
| `ESCALATE` | `deny` | non-recoverable blast radius (infra destroy, force push, …) |
| `CONTEXT_MISMATCH` | `ask` | declared env does not match the resolved env |
| `REVERSIBLE` / `DRY_RUN` | `allow` | snapshotted first, recoverable |
| `ALLOW` | `allow` | non-mutating, no action needed |

Switch mode in `.demo_cli.toml` or per call:

```bash
demo_cli check "rm -rf dist" --mode enforce
```

Start in shadow. Move to enforce on a project once you trust what it's doing.

---

## Configuration

Run `demo_cli init` to scaffold `.demo_cli.toml` at the project root.

```toml
mode = "shadow"            # "shadow" observes only; "enforce" gates actions

[workspace]
dir = ".demo_cli"          # receipts + recovery points (gitignored)

# Optional: gate SaaS / external API calls on the wire
# [egress]
# port = 8080              # proxy listen port (default: 8080)
# mode = "shadow"          # "shadow" logs SaaS calls; "enforce" blocks destructive calls
# strict_unknown_hosts = false
# saas_hosts = ["api.stripe.com", "api.github.com"]
# no_proxy = ["localhost", "127.0.0.1"]

# Optional: hide sensitive credential files from VFS directory listings and direct reads
# [cloak]
# enabled = true
# patterns = ["*.env", ".env*", ".demo_cli.toml", "*.key"]

# Optional: scrub child environment variables when running guarded subshells
# [env]
# strip = ["AWS_*", "*_SECRET*", "*_TOKEN", "DATABASE_URL"]
# preserve = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]

# Optional: whole-workspace checkpoint fallback when targets cannot be resolved
# [checkpoint]
# enabled = false

[approval]
key_env = "DEMO_CLI_APPROVER_KEY"

# Declare targets manually or via: demo_cli target add <pattern> --env production
[[target]]
match = "production"       # substring or glob (*.db) matched against the resolved target ref
env = "production"         # production | staging | development
recovery = "snapshot"      # snapshot | none
```

Environment is resolved in priority order: an explicit `--actual-env` flag,
then a `[[target]]` match in this file, then a heuristic over the command text.
A production database is reached via a connection string, not by a file called
`prod.db`, the declared target is always the source of truth.

---

## Command reference

| Command | What it does |
|---|---|
| `check "<cmd>"` | evaluate a command; flags: `--db`, `--db-url`, `--target`, `--mode`, `--intent-env`, `--actual-env`, `--reason`, `--approval-token`, `--json`, `--quiet` |
| `target` (alias `targets`) | manage declared environment targets; subcommands: `add <pattern>`, `list` |
| `log` (alias `receipts`) | list captured recovery points (id, when, kind, size, action); `--last N` |
| `undo [id]` | restore a recovery point by id, or the latest |
| `diff [id]` | show what changed since a recovery point |
| `verify` | walk both receipt chains and their cross-links → VERIFIED, DAMAGED, OUT OF ORDER, TAMPERED, or NO RECEIPTS |
| `report` | summarise recorded decisions |
| `receipt [id]` | print a copy-pasteable proof card for a receipt (latest, or by id); `--list` shows recent receipt ids |
| `status` | mode, hook state, receipts, chain integrity, recovery count |
| `doctor` | every prerequisite with the command that fixes it (git, pg tools, mitmdump, the WinFsp driver and the winfspy binding *separately*), config, workspace, hook registration per host, PATH, an end-to-end hook self-test, the backing ACL, and whether an agent has ever actually been gated here |
| `prune` | delete old recovery artefacts (`--keep N`, `--older-than DAYS`); receipts are never pruned |
| `init` | scaffold `.demo_cli.toml` |
| `install-hook` | write PreToolUse entries into `.claude/settings.json` (add `--cursor` for `.cursor/hooks.json`) |
| `hook` | (internal) called by Claude Code; reads tool JSON on stdin, writes permission decision on stdout |
| `hook-cursor` | (internal) called by Cursor; reads `beforeShellExecution` JSON on stdin, writes permission decision on stdout |
| `hook-codex` | (internal) called by Codex; gates `Bash` and `apply_patch` |

**Every layer, and the machine underneath it**

| Command | What it does |
|---|---|
| `setup [project]` | one command to make a project guarded: config, hooks for every host present, relocation, backing lock, logon task, mount. Always asks before moving files |
| `teardown [project]` | reverse everything `setup` did, in any machine state. Leaves config and receipts as your audit trail |
| `guarded <agent…>` | launch an agent with every available layer started, print coverage first, and re-check on a heartbeat so a layer that drops mid-session is announced |
| `run <cmd…>` | run one command under the behavioural (syscall) guard **[Linux]** |
| `install-shell-guard` | catch commands typed in the agent's `!` mode, via `BASH_ENV` **[Linux]** |
| `protect <project>` | relocate a project so its path becomes the guarded mount; on an already-protected project, re-apply the backing lock without moving anything **[Windows]** |
| `unprotect <project>` | move it back and remove the lock **[Windows]** |
| `mount` / `unmount` | start or stop the filesystem guard directly **[Windows]** |
| `egress` | gate destructive external/SaaS API calls on the wire (needs `mitmdump`); `--trust-ca` / `--untrust-ca` manage mitmproxy's CA in your **user** store on Windows |

Exit codes for `check`: `0` allow, `1` context mismatch, `2` escalate.

---

## What it covers, and what it does not

**Snapshot targets:** sqlite files, postgres (via `pg_dump`/`pg_restore`),
individual files, directories (capped at `DEMO_CLI_MAX_SNAPSHOT_MB`, default 256 MB).

**Shell expansion is resolved before the decision is made.** The command reaches
the hook *before* the shell has touched it, so `Reports/*.png` and
`file{1,2,3}.txt` arrive as literal strings, and a naive `os.path.exists()` on
them returns false. demo_cli expands globs and braces itself (`{a..z}`, `{a,b}{1,2}`,
nested, bounded), so it sees the operands the shell will actually pass to `rm`.
Skipping this is how a mass delete slips through with no snapshot taken.

**Affected files are printed before the action runs.** `check` renders an
**Affected files (preview)** section listing the concrete paths an `rm` / `mv`
will touch (also in `--json` as `affected_paths`). In the incident above, the
agent's stated goal was to *count* the files matching `Reports/report_*`, and the
expansion of that glob **is** that count, so the preview answers the question the
agent was asking and makes an accidental mass delete impossible to approve blind,
in the same operation.

**Multi-path deletes are captured when full capture is provable.** Several paths
that collapse into one capturable *subdirectory* snapshot **that directory**, a
superset of the blast radius, so recovery stays provable rather than partial.
Paths that do not collapse to one bounded directory still escalate.

**Capture surfaces that are always refused,** however small they measure:
`$HOME`, the filesystem root, a Windows drive root, and the **project root
itself**. A two-file `rm` at the top of a repo collapses to a common root of the
whole project, and silently deep-copying the entire tree on every such delete is
neither honest nor cheap, so it escalates instead.

**Escalated honestly, never falsely snapshotted:** terraform/kubectl/cloud
destroy commands, `git push --force`, remote filesystem changes, object-storage
deletions, external side effects (email, payments, webhooks), credential rotation,
and any database reached over a non-local connection string. demo_cli will not
claim a recovery it cannot provide.

**`Remove-Item -Recurse -Force` (PowerShell) is captured when its target is
provable.** Including the `ri` alias and abbreviated `-r`/`-fo` flags in any
order: `-Path`, `-LiteralPath`, or a single positional operand that exists
inside the project root is snapshotted first and allowed, same as `rm -rf`.
A missing, ambiguous, multi-target, wildcard, or out-of-root target still has
no honest recovery point to stand behind and is denied - in every
environment, including `development`/`staging`.

**`rmdir /s` and `del /s|/f` remain a hard-stop in every environment.** These
wipe a whole tree with no recycle bin and, unlike `Remove-Item`, the operand
extractor does not yet resolve their target, so there is no honest recovery
point to stand behind. A human structural-approval token is the one
legitimate override; an agent cannot forge it.

**Out of scope for this beta:**
- Adversarial agents deliberately evading classification
- Reversing already-sent external effects
- Reversing an action after it has already been undone once (single undo depth per recovery point)
- Adapters for agents other than Claude Code, Cursor and Codex (Aider, Cline, planned)
- **Codex on Windows is untested.** The adapter is proven on Linux; whether
  Codex's hooks fire on Windows has not been established either way. Until it
  is, assume no protection there and use Claude Code

**Shell parsing is pattern-based, not a full AST (roadmap).** Commands are matched
with expansion (globs, braces) and structural rules, not a complete shell grammar.
Deeply nested substitution, unusual quoting, and exotic syntax are handled
*conservatively* — they fall to the honest escalate path rather than a confident
capture. A full command-level AST is on the roadmap; until it lands, ambiguous
parses are treated as unrecoverable, not waved through.

**Database coverage is SQLite and Postgres only.** MySQL, MongoDB, and other
engines are not yet snapshotted; a destructive command against them has no local
recovery point and escalates rather than being captured.

---

## What the receipt chain proves

Every receipt carries the hash of the one before it, so **editing any entry
breaks the chain from that point on** and `demo_cli verify` says so. On
Windows there are two chains — the hook writes one, the filesystem guard the
other — and each receipt records the other chain's head at the moment it was
written, which is how a truncated tail gets caught.

Being precise about the limits, because a proof card invites a stranger to
check and they deserve to know what they are checking:

- **A whole-file rewrite is not detected by the chain alone.** Someone who can
  write the ledger can rebuild it consistently. The answer is the chain head
  `verify` prints: record it somewhere the machine does not control — a commit
  message, a CI log, a message to yourself — and compare later. That is the
  only thing that detects a rewrite, and it is a step you have to take.
- **Cross-links only reach backwards.** A receipt anchors to the other chain's
  head *as it was when it was written*, so entries added after the other
  chain's last write are not yet vouched for by anything. `verify` now reports
  that count rather than leaving you to infer coverage. On Linux there is one
  chain, so this applies to all of it.
- **Damage and deletion can look alike.** A line that will not parse might be
  an interrupted write or might be a removed entry with something typed over
  it. `verify` reports what it can read and refuses to guess which — it will
  not tell you "nothing was edited" when it cannot know that.
- **The hash is unkeyed.** Anyone can compute a valid receipt hash. The chain
  proves entries are *consistent with each other*, not that they were written
  by this tool.

Read plainly: the ledger is strong evidence against casual editing and against
an agent covering its tracks. It is not proof against someone with write access
to the file and a reason to be careful — unless you have that head hash
recorded elsewhere.

---

## Known issues (beta)

- **PATH:** `demo_cli` must be resolvable in the shell where `claude` runs.
  Install with `pipx`, or keep the virtualenv active. Run `demo_cli doctor`
  to check. If the binary is not found, Claude Code silently skips the hook.
- **Directory restore is coarse.** Undoing a directory snapshot reverts the
  **whole captured directory** to its snapshot state. That coarseness is exactly
  what keeps recovery a provable superset rather than a partial guess, but it
  also means unrelated edits made inside that directory *after* the snapshot are
  reverted too. Run `demo_cli diff <id>` before `undo <id>`.
- **A multi-path `rm` at the project top level escalates.** If the paths collapse
  to a common root that is the project root itself (`rm a.py b.py` at the top of
  your repo), demo_cli refuses to deep-copy the whole tree and escalates. Paths
  that collapse to a real subdirectory (`rm Reports/*.txt Reports/*.png`) are
  captured and stay reversible.
- **`mv` is conservative:** most two-argument `mv` commands are flagged. Safe
  renames inside the project workspace will be narrowed in a future release.
- **A pathological brace expansion falls back to the literal token,** which means
  the honest escalate path rather than an unbounded expansion. Bounded by
  `_BRACE_MAX`.
- **The filesystem guard costs about 4ms per operation.** Measured on real
  hardware: 200 writes took 0.294s outside the mount and 1.131s inside. Fine
  for source trees, noticeable on a build directory — which is one reason
  `node_modules`, `.git` and `__pycache__` are ignored.
- **`demo_cli log` shows 0B for a recovery point it cannot read.** Run
  unelevated against an ACL-locked backing, `entry_size()` cannot stat the file
  and reports zero. "0 bytes" and "I cannot see it" are different facts and
  should not share a rendering.
- **No `!`-mode capture on Windows.** PowerShell has no `DEBUG` trap
  equivalent, so the shell layer is Linux-only. Commands you type yourself in
  the agent's `!` mode on Windows are not seen.
- **The egress proxy can outlive a hard kill.** `guarded` stops the proxy it
  started, but only on a clean exit, and `teardown` does not check the port.

---

## Library use

```python
from demo_cli import Guard

result = Guard(mode="enforce").evaluate("DELETE FROM users", explicit_db="app.db")
print(result.decision.decision)   # REVERSIBLE
print(result.permission)          # allow
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

**826 passing**, identical from the same commit on both platforms — Linux 826,
Windows 807 plus 19 platform-gated skips (the `ptrace` guard and the bash
`DEBUG`-trap shell guard, which have no Windows equivalent). No module is
forked per platform: every difference lives behind an `os.name` branch or a
small strategy function in one shared tree.

---

## Contributing

This is a public beta. The most useful reports are **real commands from real
agent sessions** that produced a wrong decision (false block or missed snapshot).
Open an issue with the command, your `.demo_cli.toml` (redact credentials), and
what you expected. Bug reports found through dogfooding, like the `rm app.db`
case that shaped 0.4.0b3, are exactly what the project needs right now.

To make that trivial, an in-context feedback prompt fires on a wrong-call-worthy
decision (a block, a context mismatch, or a snapshot): the tool prints a
`Wrong call? → report it` line with a **prefilled** GitHub issue (decision,
reason, matched rule, command already filled in). It is consent-based and
one-directional, a link handed to you, nothing phones home. It stays silent on
plain `ALLOW`s so it never becomes noise. `demo_cli receipt --share` turns any
receipt into a plain-text proof card you can paste into an issue or thread.
