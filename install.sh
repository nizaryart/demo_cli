#!/usr/bin/env sh
# demo_cli installer (Linux / macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.0.7/install.sh | sh
#
# Yes, this is curl-pipe-sh - the exact opaque fetch-and-run pattern demo_cli
# itself escalates. Read it first. It is not long.
#
# WHAT IT DOES: makes this MACHINE ready to run demo_cli. Python, pipx,
# demo_cli itself, and a check that all of it survives a new terminal.
#
# WHAT IT DOES NOT DO: touch any project of yours. It never moves a file,
# never writes a config, never installs a hook, and it does not modify your
# shell. Those are `demo_cli setup` and `demo_cli install-shell-guard`, which
# you run yourself, per project, after reading what they change.
set -eu

TAG="v1.0.7"
REPO_BASE="git+https://github.com/nizaryart/DEMO_LOADING.git@${TAG}"

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
step() { printf '\n\033[36m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

say ""
say "demo_cli installer"
say "------------------"

# --------------------------------------------------------------------------
# 0. REFUSE TO RUN AS ROOT. Same reasoning as the Windows script.
#
# pipx installs per user. Under sudo that user is root, so demo_cli lands in
# root's ~/.local/bin and is absent from the shell where you launch your
# agent. The hook would be registered and would never fire, and nothing would
# say so - "installed but inert", manufactured by the installer.
#
# Root also owns the receipts and the recovery points it writes, so a later
# unelevated `demo_cli undo` cannot read its own ledger.
# --------------------------------------------------------------------------
if [ "$(id -u)" = "0" ]; then
  printf '\n\033[31m  Running as root. Stopping.\033[0m\n\n'
  warn "  pipx installs per user. Run this as root and demo_cli goes into"
  warn "  root's ~/.local/bin - invisible to the shell where you launch your"
  warn "  agent. The receipts and recovery points would be root-owned too, so"
  warn "  your own 'demo_cli undo' could not read them."
  say  ""
  say  "  Run it as your normal user. Nothing here needs root."
  say  ""
  exit 1
fi

# --------------------------------------------------------------------------
# 1. Python
# --------------------------------------------------------------------------
step "[1/4] python"
if   command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python  >/dev/null 2>&1; then PY=python
else die "Python 3.9+ not found. Install it, then re-run."
fi
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo '?')"
"$PY" -c 'import sys;sys.exit(0 if sys.version_info>=(3,9) else 1)' 2>/dev/null \
  || die "Python $PYVER is too old. demo_cli needs 3.9+."
ok "  python $PYVER  ($(command -v "$PY"))"

# --------------------------------------------------------------------------
# 2. pipx
# --------------------------------------------------------------------------
step "[2/4] pipx"
if command -v pipx >/dev/null 2>&1; then
  ok "  already installed"
else
  say "  not found - installing it for your user"
  "$PY" -m pip install --user -q pipx || die "could not install pipx. Try: $PY -m pip install --user pipx"
  "$PY" -m pipx ensurepath >/dev/null 2>&1 || true
  PIPX_BIN="$("$PY" -m site --user-base 2>/dev/null)/bin"
  case ":$PATH:" in *":$PIPX_BIN:"*) : ;; *) PATH="$PIPX_BIN:$PATH"; export PATH ;; esac
  command -v pipx >/dev/null 2>&1 || die "pipx installed but not runnable. Open a new terminal and re-run."
  ok "  installed"
fi

# --------------------------------------------------------------------------
# 3. demo_cli
#
# No [windows] extra here: winfspy is Windows-only and the behavioural layer
# on Linux is ptrace, which needs nothing installed. `demo_cli run <cmd>`
# works the moment demo_cli does.
# --------------------------------------------------------------------------
step "[3/4] demo_cli"
SPEC="${DEMO_CLI_LOCAL:-$REPO_BASE}"
pipx install --force "$SPEC" >/dev/null 2>&1 \
  || die "pipx install failed. Run it by hand to see why:
    pipx install \"$SPEC\""
ok "  installed"

# --------------------------------------------------------------------------
# 4. Does it survive a NEW terminal?
#
# The old script checked $PATH, which it had just edited itself, so it could
# only ever answer yes. What matters is the PATH of the shell you launch your
# agent from - which comes from your profile, not from this process.
# --------------------------------------------------------------------------
step "[4/4] reachable from a new terminal"
BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"

if ! command -v demo_cli >/dev/null 2>&1; then
  case ":$PATH:" in *":$BIN:"*) : ;; *) PATH="$BIN:$PATH"; export PATH ;; esac
fi
command -v demo_cli >/dev/null 2>&1 \
  || die "demo_cli is not runnable even with $BIN on PATH. Something is wrong with the pipx install."
ok "  this shell:    $(command -v demo_cli)"

# Is $BIN written into a profile, or only in this process? grep is crude but
# it matches what `pipx ensurepath` actually does, and a false "yes" here is
# the failure this check exists to prevent.
PERSISTED=no
for f in "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.zshrc" \
         "$HOME/.zprofile" "$HOME/.config/fish/config.fish"; do
  [ -f "$f" ] || continue
  if grep -qF -- "$BIN" "$f" 2>/dev/null; then PERSISTED=yes; break; fi
done
# A pipx bin dir that is already a system path needs no profile entry.
case "$BIN" in /usr/local/bin|/usr/bin) PERSISTED=yes ;; esac

if [ "$PERSISTED" = yes ]; then
  ok "  new terminals: yes ($BIN is on your PATH persistently)"
else
  warn "  new terminals: NO - $BIN is not in any shell profile."
  warn "  Until it is, the shell you launch your agent from will not find"
  warn "  demo_cli, the hook will silently never run, and nothing will say so."
  say  ""
  say  "      pipx ensurepath"
  say  ""
  say  "  then open a NEW terminal."
fi

# --------------------------------------------------------------------------
# Optional, and deliberately not installed or enabled for you.
# --------------------------------------------------------------------------
step "optional extras"
if command -v mitmdump >/dev/null 2>&1; then
  ok "  mitmdump found - the egress layer can run"
else
  say "  mitmdump not found. The egress layer (gating destructive external API"
  say "  calls) needs it. It is a large dependency and it intercepts TLS, so it"
  say "  is your call, not the installer's:"
  say ""
  say "      pipx inject --include-apps demo-cli mitmproxy"
  say ""
  say "  --include-apps matters: without it the library installs and the"
  say "  mitmdump BINARY still is not on PATH, which is what demo_cli looks for."
fi
command -v pg_dump >/dev/null 2>&1 || \
  say "  pg_dump not found - database snapshots are disabled. Only relevant if
  your agent touches a Postgres database."
say ""
say "  The shell guard (catching commands typed in your agent's '!' mode) is"
say "  NOT installed. It edits your bash environment via BASH_ENV, so it is an"
say "  explicit choice:"
say ""
say "      demo_cli install-shell-guard"

# --------------------------------------------------------------------------
say ""
say "-------------------------------------------------------------"
demo_cli doctor || true
say "-------------------------------------------------------------"
say ""
ok  "The machine is ready. No project has been touched."
say ""
say "To guard a project:"
say ""
say "    cd /path/to/your/project"
say "    demo_cli setup ."
say ""
say "To try the guard without any of that:"
say ""
say "    demo_cli check \"rm -rf ./build\""
say ""
