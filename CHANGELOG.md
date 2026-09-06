# Changelog

## 1.0.6 - 2026-09-06 - installation, and diagnosing it honestly

* **The installer was shipping a different tool.** `install.sh` and
  `install.ps1` both pinned `git+https://github.com/WePwn/demo_cli.git@v0.4.0-beta.8`,
  a tag from 2026-07-19 that contains none of the work since: no filesystem
  guard, no `protect`/`setup`/`teardown`, no split ledger, neither classifier
  fix. Upstream's push is disabled by design, so that tag will never contain
  it. Anyone following the README would have installed July's code and filed
  reports against software that no longer exists. All URLs now point at the
  repository the code actually lives in, pinned to the current release tag.

* **The WinFsp driver and the `winfspy` binding are diagnosed separately.**
  `doctor` caught any `ImportError` from `import winfspy` and always answered
  `pipx inject demo-cli winfspy`. That is right when the binding is missing
  and wrong when the binding is fine and the *driver* is absent - the user
  runs it, pip reports success, nothing changes. The new `deps` module probes
  the two independently and gives four machine states four different answers,
  in dependency order, and prints the real exception rather than inventing a
  third cause when both are present and it still fails. This was the fourth
  instance in one week of a diagnostic that could name only one cause naming
  it wrongly (see 2026-09-02).

* **`doctor` checks the prerequisites it never checked.** `mitmdump` was not
  checked at all, so the egress layer could be entirely absent from a green
  report. Added, along with an elevation warning worded per platform (on
  Windows it names the ACL bypass; on Linux, where there is no ACL
  separation, it names the ledger instead) and a re-check of the backing
  directory's ACL, which `protect` applied once and nothing ever verified
  again.

* **`backing locked` was reported twice, with two severities.** The check
  existed in both `deps` and `cli._mount_checks`, and the copies had drifted
  - one `fail`, one `warn`, for the same directory in the same report. The
  surviving check keys on the backing directory existing rather than on a
  mount being recorded, so it also catches a protected project whose guard
  has never started.

* **`protect` re-applies the lock instead of refusing.** `doctor`'s
  remediation for an unlocked backing was `demo_cli protect <project>`, and
  `protect` refused it: *"<backing> already exists. Refusing to merge two
  trees."* The refusal is correct in general, but on an already-protected
  project there are not two trees - there is one tree seen twice, the mount
  and its backing - so nothing needs moving and only the lock can be missing.
  `protect` now detects that case from demo_cli's own mount record (never
  from the directory name, because a false positive would apply an
  Administrators-only ACL to unrelated data) and re-locks without moving
  anything. `setup` inherits the repair.

* **An elevated repair reports its own outcome.** `ShellExecuteExW` gives the
  elevated child its own console, which closes on exit, so a successful
  relock printed nothing and looked like a no-op. The parent now reads the
  ACL itself rather than relaying the child or trusting its exit code.

* **Remediations name the real path.** `demo_cli protect <project>` became
  `demo_cli protect C:\path\to\project   (re-applies the lock; moves
  nothing)`. A command the reader has to edit before running is one they can
  edit wrongly.

* **The installers prepare the machine and nothing else.** They no longer
  write a config or install a hook; that is `demo_cli setup`, run per project
  after reading what it will move. Both now **refuse to run elevated**: pipx
  installs per user, so an elevated install puts `demo_cli` on the
  Administrator's PATH and leaves it absent from the shell where the agent
  runs - the hook registers, `doctor` looks green, and nothing is ever gated.
  On Linux there is a second reason: root-owned receipts that the user's own
  unelevated `undo` cannot read.

* **One elevation prompt, at the point of need.** Only the WinFsp MSI
  requires Administrator; `winget` owns that prompt so the script itself
  stays unelevated, `--custom "ADDLOCAL=ALL"` reaches the MSI so the
  Developer feature the binding needs is present, and the result is confirmed
  by re-reading the registry rather than by an exit code.

* **The PATH check can now answer no.** Both scripts previously tested `PATH`
  after editing `PATH` themselves. They now check the *persisted* path - the
  user registry on Windows, the shell profiles on POSIX - because the shell
  that launches the agent is a different shell, and that is the one that has
  to find `demo_cli`.

* **Packaging.** `winfspy` is declared as an optional `[windows]` extra
  (`fsmount` genuinely imports it) rather than a hard dependency, so a
  machine without the driver still gets the string layer instead of a failed
  install. `mitmproxy` is deliberately *not* declared: the proxy is located
  with `shutil.which("mitmdump")`, so an extra would install the library and
  leave the binary off `PATH`.

* Tests: 826 passing (Linux 826; Windows 807 + 19 platform-gated skips), up
  from 779. New: `tests/test_deps.py`, `tests/test_installers.py` - including
  one that fails if the tag pinned in the install scripts ever disagrees with
  `version.release_tag()`, which is how 1.0.5 came to be published without
  the release it was cut for.

## 1.0.5 - 2026-09-05 - first versioned release of the red-team fork

Everything between `0.4.0b8` (2026-07-19) and this release landed unversioned
on the working branch over seven weeks. It is grouped by theme below, with
the date each piece was proven on real hardware rather than the date it was
written. Version numbering restarts at 1.0.x because this fork has diverged
substantially from upstream and a shared receipt must name unambiguously
which codebase verified it.

### Windows: a behavioural guard, not a port (2026-08-23 - 2026-08-25)

* **The filesystem guard.** `ptrace` has no Windows equivalent that avoids
  kernel driver signing, so the behavioural layer is implemented over
  **WinFsp**, whose kernel driver ships already signed. The project directory
  becomes a user-mode passthrough mount; deletes and truncations are seen as
  operations rather than inferred from command text, snapshotted, then passed
  through. This closes the same gap the syscall guard closes on Linux - what
  the string layer cannot read, the kernel already knows.
* Judgement and plumbing are split: `fsguard` holds the decisions and is
  testable on any platform, `fsmount` holds the `winfspy` subclass and is
  not. `fspassthrough` holds the backing-store operations.
* Measured cost on real hardware: 200 writes took 0.294s outside the mount
  and 1.131s inside - roughly 4ms of guard overhead per operation.

### Windows: making the guard unbypassable (2026-08-25 - 2026-08-29)

* **`protect` / `unprotect`.** The project is relocated to `<project>.real`
  and its original path becomes the mount, so the guard cannot be sidestepped
  by using the real path. The backing directory is locked to Administrators
  and SYSTEM, which is what makes an unelevated agent physically unable to
  reach around the mount.
* The ACL is applied in two passes. A single `icacls` call with `/T` strips
  inherited access from every existing child and has its `(OI)(CI)` grant
  rejected on files, leaving them with an empty DACL - unreadable by
  everyone, including their owner. Found live on 2026-08-25.
* **`setup` and `teardown`.** One command to make a project guarded - config,
  hooks for every host present, relocation, logon task, mount - and one to
  reverse all of it in any machine state. Setup will not move files without
  printing exactly what it will do and asking.
* **`guarded`** launches an agent with every available layer started and
  reports coverage before handing over the terminal, re-checking on a
  heartbeat so a layer that drops mid-session is announced.
* A reboot test on 2026-08-29 produced seven defects, three of them the same
  defect in different clothes. The most consequential: `doctor`'s
  workspace-writable check called `os.makedirs`, which creates parents - and
  on a protected project the parent *is* the mount point, so running the
  diagnostic while the guard was down left a real directory where the mount
  belonged and the guard could never return. A diagnostic that bricks what it
  diagnoses.

### Receipts: a tamper-evident ledger across two writers (2026-09-02)

* **Split chains.** The hook, CLI and egress layers write through the mount;
  the filesystem guard writes in the backing. These are different lock
  domains - a byte-range lock taken through WinFsp and one taken on NTFS are
  not the same lock - so a single append-only file was being interleaved and
  torn. Receipts now carry a `chain` field and are routed to separate files.
* **Cross-chain anchoring.** Each receipt records `peer_head`, the other
  chain's head hash at the moment of writing. A lone hash chain cannot detect
  truncation of its own tail; an anchor in the other chain proves the entry
  existed and closes it. Staleness weakens the claim without falsifying it.
* **`verify` distinguishes five outcomes** instead of two: VERIFIED, DAMAGED
  (a torn line, salvaged), OUT OF ORDER, TAMPERED (a self-hash mismatch,
  never excused), and NO RECEIPTS - because an empty ledger was previously
  reported as tampering.
* `verify` now prints which ledger it read. Run from the wrong directory it
  had silently verified a stray ledger and reported success.
* Proven by comparison, not assertion: two lab projects ran the same
  experiment on the same machine. The first corrupted its own audit trail
  twice; the second, after these changes, came through with 232 and 205
  entries intact and 237 cross-links resolved.

### Classifier (2026-09-02)

* **A trailing redirection no longer swallows a nested payload.**
  `powershell -Command "Remove-Item -Force notes.txt" 2>&1` joined the `2>&1`
  into the script text, so the payload began with a quote character and every
  anchored rule stopped matching. The `2>&1` belongs to the outer shell.
* **A nested shell is found anywhere in a pipeline.** Unwrapping ran once on
  the whole line before splitting, so `echo hi; powershell -Command
  "Remove-Item x"` was never judged at all.
* Both were found by an agent working a scripted lab exercise, then
  reproduced on Linux against bash and cmd - neither was Windows-specific.
  Both survived the suite because unanchored rules still fired on the mangled
  text, so the command still looked destructive and only its *operand* went
  missing: an honest escalation instead of a silent pass, which is why
  nothing was obviously broken.

### Recovery

* **`checkpoint`** (2026-08-25) captures the project root when an action is
  known to mutate but its target cannot be resolved - converting *"I cannot
  tell what you will destroy"* into *"then I preserve everything you could,
  or I refuse"*. It refuses rather than capturing partially.
* **Segment-based operand resolution** (2026-08-25) judges redirection per
  pipeline segment, with exactly-one-match discipline, so two redirecting
  targets escalate rather than snapshotting one and truncating the other
  unrecorded.
* The recovery index merges both chains' entries in timestamp order, so
  `undo` and `log` see one history regardless of which layer captured it.

### Egress (2026-07-27; Windows 2026-08-26)

* Destructive external and SaaS API calls are gated on the wire through a
  mitmproxy addon, which sees the HTTP method, host, path and body an
  obfuscated command can hide. On Windows, `egress --trust-ca` installs
  mitmproxy's CA into the **current user's** store - no elevation - and
  `--untrust-ca` removes it.

### Hosts

* **Codex adapter** (2026-08-17). Four defects were found within an hour of
  meeting a real Codex, none visible to 208 unit tests, the published docs,
  or the binary's own embedded JSON schemas. The worst: `install-hook
  --codex` wrote a config Codex parsed and silently discarded, while the
  installer printed "Installed" - no error, no hook, no protection.
* From that: **`doctor` reports whether a hook has ever actually fired**, per
  host, from the receipts. Config present, hook registered and binary on PATH
  are all paperwork; a receipt written by an agent is evidence. "Installed
  but inert" has been the dangerous state repeatedly in this project.
* `doctor` runs an end-to-end self-test through the same entry point the host
  uses, once per shell tool.

### Platform discipline

* No module was forked for Windows. One tree, every platform difference
  behind an `os.name` branch or a small strategy function - the constraint
  set at the start of the port and held through it.

### Packaging (2026-09-05)

* Version `0.4.0b8` -> `1.0.5`; repository, issue links and the install
  command embedded in every exported receipt repointed away from an upstream
  this work cannot reach.

## 0.4.0b8 - honesty + release hardening

* **The shared-receipt install command is pinned to the release tag.** A
  `receipt --share` card tells the recipient how to verify the hash chain
  themselves; that command still pointed at `@beta`, the moving branch the
  README explicitly warns against. It now derives the tag from the package
  version via `version.release_tag()` (`0.4.0b8` → `v0.4.0-beta.8`), so a
  stranger verifies against exactly the code the receipt was written by, and
  the command follows the next version bump instead of going stale. Locked by
  a regression test — this was previously unasserted, which is how it survived.
* **Fixed a self-defeating trust check in the README.** The no-telemetry claim
  invited readers to run `grep -rn "requests\|urllib\|http\|socket" src/`,
  which *returns hits*: `urllib.parse` is imported twice for pure string
  handling (building the prefilled issue link; reading a hostname out of a DB
  connection string to tell local from remote). The grep now covers actual
  network I/O (`urlopen`, `requests`, `httpx`, `socket`, `http.client`) and
  returns nothing, with the two benign `urllib.parse` uses named explicitly
  rather than hidden.
* **Corrected the opening comparison.** The README claimed Claude Code and
  Cursor "neither snapshot first." Their checkpointing *does* cover the agent's
  own file edits; what it does not cover is shell commands and databases. The
  line now says that, which is both accurate and the actual gap.
* **Relicensed to MIT.** The project is now MIT-licensed across `LICENSE`,
  `pyproject.toml`, and the README (previously Apache-2.0). MIT is more
  permissive and drops Apache-2.0's explicit patent grant.
* **Escalate everywhere: removed the SANDBOX low-blast exception.** An
  unrecoverable, non-recursive mutation in a `development`/`test`/`sandbox`/
  `staging` workspace previously returned `SANDBOX` (posture SAFE) and proceeded
  with no recovery point. It now escalates like everywhere else — an
  unrecoverable mutation is never waved through on the strength of an environment
  label. The stated invariant ("recoverable or escalate") is now true without
  exception. The `SANDBOX` disposition is gone.
* **Install is pinned to a release tag, not the moving `beta` branch.** The
  recommended path is manual and verify-first (read source + confirm the
  published SHA-256 before anything runs). `install.sh` / `install.ps1` and every
  README install snippet now reference `v0.4.0-beta.8`. `curl | sh` remains
  available but is clearly labelled convenience, not the safe path.
* **Corrected the recovery-demo caption.** It previously implied the referenced
  incident's files were "gone for good"; file-carving tools recover *some*
  fraction. The caption now states the honest case — carving is partial and luck,
  a recovery point taken *before* the command restores exactly the captured state.
* **Fail-open is now loud on every path.** A bug in demo_cli must never brick the
  agent, so the hook fails open on its own internal errors — but the one
  remaining silent path (unparseable hook input) now writes a visible stderr
  warning instead of a silent allow. Decisions themselves remain fail-closed.
* **Documented two standing limitations** in the README: shell parsing is
  pattern-based (a full command AST is roadmap; ambiguous parses are treated as
  unrecoverable), and database coverage is SQLite + Postgres only (other engines
  escalate rather than being captured).
* **Added `SECURITY.md`** with a responsible-disclosure contact.
* **Windows drive-letter detection is now cross-platform** (via `ntpath`), so a
  multi-drive delete is recognised as having no common capture root on any host,
  and the corresponding test runs everywhere instead of being Windows-only.

## 0.4.0b7 - Windows: PowerShell hook coverage + honest Remove-Item recovery

**Also fixed - receipt-chain locking was POSIX-only (fcntl), a silent no-op on Windows**, so concurrent writers could fork the tamper-evident chain. Replaced with a cross-platform sidecar lock (msvcrt.locking on Windows, fcntl.flock on POSIX) held across the whole read-hash to append to fsync section, with bounded retry and a ReceiptLockError rather than an unlocked write. Verified under 4 threads x 10 receipts and separate spawned processes.

Confirmed real-world failure: Claude Code on Windows fired
`Remove-Item -Recurse -Force ".\victim"` under `tool_name="PowerShell"`. The
folder was deleted with **no receipt and no recovery point** - the debug log
showed `Hooks: Found 0 total hooks in registry`. Four root causes, all closed:

* **The installed hook only matched `Bash`.** `install-hook` now also installs
  a `PowerShell` matcher block; an existing Bash-only install is upgraded
  in place (the Bash block is left untouched, not duplicated) rather than
  left silently half-covered.
* **`run_pretooluse` only evaluated `tool_name == "Bash"`.** PowerShell
  commands now route through the same `tool_input.command` evaluation path.
* **`recovery.py` only extracted targets for Unix `rm`/`mv`.** Added
  conservative `Remove-Item` target extraction: `-Path`, `-LiteralPath`, or a
  single positional operand. Anything else - missing, ambiguous, multiple
  targets, multiple drives, or a wildcard - is left unresolved by design, so
  the caller escalates instead of guessing.
* **`ps_remove_item_rf` was unconditionally nonrecoverable**, so it could
  never receive a snapshot even when its target was perfectly resolvable.
  It is now snapshotted and treated as an ordinary recoverable mutation
  (`REVERSIBLE`) when the target exists inside the project root; it still
  hard-stops (`ESCALATE`) in every environment, including
  `development`/`staging`, when it does not. `rmdir /s` and `del /s|/f`
  keep the old unconditional hard-stop - their target extraction isn't
  implemented yet.

The `doctor` self-test now drives a synthetic `PowerShell` payload through
the real hook entrypoint in addition to the existing `Bash` one, so a
Windows install where only the Bash matcher registered is caught before an
agent hits it for real.

## 0.4.0b6 - multi-path recovery, brace expansion, affected-files preview

This is where the auto-fire recovery path changed. (0.4.0b5 correctly stated
that *its* changes left snapshot/recovery untouched; the work below lands on top
of it.) It closes a live data-loss incident and finishes the shell-expansion
story the snapshot depends on.

### Multi-path `rm` now captures the common directory (was: escalate)
Forced by a live incident (`claude-code#76626`): an agent ran
`rm -f Reports/report_*.txt Reports/report_*.png` meaning only to count the
files. Every path was local, bounded, and trivially copyable - precisely the
case where full capture is *provable* - yet the old rule returned `None` for any
multi-path `rm` and escalated, and the files were permanently gone. Now, several
paths that collapse into one capturable directory snapshot **that directory**: a
superset of the blast radius, so recovery stays provable, never partial. Paths
that do not collapse to one bounded directory still return `None` and still
escalate. The size cap in `snapshot()` and the project-root bound in `guard()`
both still apply on top.

### Shell expansion, done the way the shell does it
The command reaches the hook *before* the shell has touched it, so globs and
braces arrive literally and `os.path.exists()` on them is `False` - which is why
the extractor used to see zero operands and capture nothing.

* **Globs** (`Reports/*.png`) are expanded so the real operands are seen.
* **Brace expansion** (`file{1,2,3}.txt`, `{a..z}`, `{a,b}{1,2}`, nesting) is now
  handled too - the same failure mode as globs, and unconditional in bash, so a
  brace-delete now fires the snapshot instead of slipping through. Bounded by
  `_BRACE_MAX`; a pathological expansion falls back to the literal token (i.e.
  the honest escalate path), never an unbounded blow-up.

### Affected-files preview
`expanded_operands(cmd)` is now wired into the rendered output: `check` prints an
**Affected files (preview)** section listing the concrete files an `rm` / `mv`
will touch. That is the uKER insight made real - the agent wanted a file count;
the expansion *is* the file count - shown in the same operation, so an accidental
mass-delete is impossible to approve blind. Also surfaced in `--json`
(`affected_paths`).

### Project-root capture refusal
A two-file `rm` at the top level of a project collapses to a common root of the
whole project; silently deep-copying the entire tree on every such `rm` is
neither honest nor cheap. The project root itself is now refused as a capture
surface (same spirit as refusing `$HOME` / the filesystem root) and escalates
instead. A common root that is a real *subdirectory* (the incident case) still
captures and stays reversible.

### Honesty notes pinned in the code
`extract_path_operand` now documents that it is **not** the honesty boundary by
itself - when a single operand exists among several, the result collapses to that
path even outside the project, and it is the guard's `within` check that refuses
it; do not reuse the function without that bound. `restore_entry` documents that
directory restore is **coarse** (it reverts the whole captured directory to its
snapshot state), which is what keeps recovery a provable superset.

Tests: **101 passing** (+9: brace expansion, expanded-operands gating, the
project-root refusal, and the multi-path/glob capture cases).

## 0.4.0b5 - shareable proof cards + in-context feedback prompt

Two adoption-phase features. No telemetry: the only feedback channel is what a
user chooses to send. Both additions honour that — nothing phones home.

### `receipt --share` — a shareable proof card
`demo_cli receipt [id] --share` renders a single receipt as a plain-text,
copy-pasteable card (the exact command caught, the decision, the hash chain,
and a one-line command anyone can run to verify the chain). `--list` shows
recent receipt ids; the id argument accepts the same 8-char prefix shown by
`log`/`undo`. The card is deliberately colour-free so it pastes cleanly into a
forum, PR, or issue, and it inherits the write-time redaction of `action_raw`.

Its correctness invariant carries into the shared artifact: an `ESCALATE` card
states *hard-stopped before it ran — no honest recovery point exists*, a
`REVERSIBLE` card states *recovery point captured*. The card never claims a
recovery it does not hold.

`receipts.py` gains read-side access to the ledger (`load_receipts`,
`find_receipt`) plus the card builder (`share_card`), all reusing the existing
`_canon`/hashing. `cli.py` gains the `receipt` subcommand.

### In-context feedback prompt
After a wrong-call-worthy decision (`ESCALATE`, `CONTEXT_MISMATCH`,
`REVERSIBLE`, `DRY_RUN`), `demo_cli check` prints one `Wrong call? → report it`
line carrying a **prefilled** GitHub issue (decision, reason, matched rule, and
command already filled in). Consent-based and one-directional — a link handed to
the user, no telemetry. Silent on plain `ALLOW`/`SANDBOX` so it never becomes
background noise. `render.py` gains `feedback_line`; `render_result` prints it
just above the mode line. (The hook/quiet stderr path is intentionally left
terse — the prompt rides the interactive `check` path only.)

Zero new dependencies. Scope closed to these two features; classifier, adapters,
snapshot, and recovery are untouched.

Tests: **89 passing** (4 new; on Windows,
`test_concurrent_appends_keep_chain_intact` remains a pre-existing best-effort
lock limitation, not from these changes — see Known issues).

---

## 0.4.0b4 - recursive-force hard-stop + Cursor adapter

Two builds shipped together.

### Recursive-force delete is a hard-stop in every environment
`Remove-Item -Recurse -Force` slipped through entirely (classified
non-mutating, allowed), and `rmdir /s` / `del /s` were waved through by the
low-blast SANDBOX path in a dev/staging workspace - the exact place an agent
runs. Both gaps are closed to match what is stated publicly.

`classify.py`: new `ps_remove_item_rf` rule matches `Remove-Item` (alias `ri`)
carrying both a Recurse-like and a Force-like flag, in any order, full or
abbreviated (`-r`/`-fo`); two disambiguating lookaheads mean a lone `-Force`
does not trigger it. A new `_LOCAL_UNRECOVERABLE` map gives `ps_remove_item_rf`,
`rmdir_s`, and `del_force` the `recursive_force_delete` surface, so the decision
engine escalates them in **every** environment. A human structural-approval
token remains the one legitimate override. `rm -rf` is unchanged - it still
snapshots its operand and stays reversible.

### Cursor adapter (`beforeShellExecution`)
`install-hook --cursor` writes a `beforeShellExecution` hook into
`.cursor/hooks.json` with `failClosed: true`. `demo_cli hook-cursor` reads
Cursor's stdin JSON (`command`, `cwd`) and returns
`{"continue": true, "permission": "allow" | "deny" | "ask"}`.

Cursor defaults to fail-open and reliably honors only `deny`, so the adapter
leans on deny-the-unrecoverable and fails **closed** on its own evaluation
error (the deliberate opposite of the Claude Code adapter). It steps aside only
when Cursor delivers no command at all (a known empty-stdin defect), so a
harness bug never bricks the session. Shell-command gating only in this beta;
file-edit gating stays Claude Code.

Tests: **85 passing** (22 new: 10 for the hard-stop, 12 for the Cursor adapter).

---

## 0.4.0b3 - dogfooding fix: plain `rm` now gated

Found during live testing against a real Claude Code session: an agent issuing
`rm app.db` (no `-rf`) slipped through undetected - classified non-mutating,
no snapshot, no recovery. Only `rm -rf` was previously caught.

**Fix** (`classify.py`): `rm_local` rule matches any top-level `rm` (plain,
`-f`, `-r`, `sudo rm`), anchored to the segment start so `git rm` / `docker rm`
/ `npm rm` produce no false positives. `rm -rf` still matches the more specific
`rm_rf` id. Operand is snapshotted before deletion → reversible.

Tests: **63 passing** (4 new).

---

## 0.4.0b2 - from "a check" to a safety net you can see

Three things kept the value invisible in earlier betas: only Bash was gated,
the recovery loop was not drivable, and shadow mode surfaced nothing.

### File edits are now gated (second door)
An agent can destroy data with `Edit`/`Write`/`MultiEdit`/`NotebookEdit` just
as easily as with `rm`. `Guard.evaluate_file_edit()` snapshots an existing file
before it is overwritten so the change is reversible. Creating a new file
proceeds without a snapshot. If a file cannot be snapshotted, the action
escalates honestly. `install-hook` now writes both matchers (`Bash` and
`Edit|Write|MultiEdit|NotebookEdit`).

### Drivable recovery loop
Every recovery point carries a short `id` and the action that caused it.
`demo_cli log` lists all points; `undo <id>` and `diff <id>` target a specific
one. `prune --keep N` / `--older-than DAYS` reclaims disk without touching the
receipt chain.

### Shadow mode surfaces its value
An ESCALATE / CONTEXT_MISMATCH decision, or a fresh snapshot, is written to
stderr (with the undo id) so it is not silently buried.

### UX
Three-tier posture band: `[+] SAFE` / `[!] REVIEW` / `[x] BLOCKED`.
`check --json` for pipelines, `check --quiet` for one-liners.
`status`, `doctor`, cosmetic fixes (branch, env source display).

### Robustness
POSIX flock on receipt append (parallel agents keep chain intact).
Directory snapshots bounded by `DEMO_CLI_MAX_SNAPSHOT_MB` (default 256 MB).
Recovery filenames include the id (fixes latent same-second filename collision).

Tests: **59 passing** (13 new over 0.4.0b1).

---

## 0.4.0b1 - initial beta

Core pipeline: classify → resolve target → build context → snapshot → decide →
receipt. Shadow mode by default. Claude Code PreToolUse hook (Bash only at this
stage). Hash-chained tamper-evident receipt log. sqlite / postgres / file / dir
snapshot and restore. Declared-first environment resolution.

Tests: **46 passing**.
