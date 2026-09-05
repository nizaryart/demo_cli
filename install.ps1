# demo_cli installer (Windows / PowerShell).
#
#   irm https://raw.githubusercontent.com/nizaryart/DEMO_LOADING/v1.0.6/install.ps1 | iex
#
# Yes, this is irm-pipe-iex - the exact opaque fetch-and-run pattern demo_cli
# itself escalates. Read it first. It is not long.
#
# WHAT IT DOES: makes this MACHINE ready to run demo_cli. Python, pipx, the
# WinFsp driver, the winfspy binding, demo_cli itself, and a check that all of
# it survives a new terminal.
#
# WHAT IT DOES NOT DO: touch any project of yours. It never moves a file,
# never writes a config, never installs a hook. That is `demo_cli setup`,
# which you run yourself, per project, after reading what it will move.
#
# Windows PowerShell 5.1 and PowerShell 7+.

$ErrorActionPreference = "Stop"
$TAG = "v1.0.6"

function Say  ($m){ Write-Host $m }
function OK   ($m){ Write-Host $m -ForegroundColor Green }
function Warn ($m){ Write-Host $m -ForegroundColor Yellow }
function Die  ($m){ Write-Host ""; Write-Host $m -ForegroundColor Red; exit 1 }
function Step ($m){ Write-Host ""; Write-Host $m -ForegroundColor Cyan }

Say ""
Say "demo_cli installer (Windows)"
Say "----------------------------"

# --------------------------------------------------------------------------
# 0. REFUSE TO RUN ELEVATED. This is not caution, it is correctness.
#
# pipx installs per USER. From an Administrator shell that user is the
# Administrator, so demo_cli lands on the admin profile's PATH and is simply
# absent from the normal shell where you launch your agent. The hook is
# registered, doctor (run elevated) looks green, and nothing is ever gated.
#
# "Installed but inert" has been the dangerous state six times in this
# project. An installer that manufactures it is worse than no installer.
#
# There is also a design reason. The Windows guard is a PRIVILEGE difference:
# the backing directory is Administrators-only, so an unelevated agent cannot
# reach around the mount. Teaching people to run demo_cli from an elevated
# shell erodes the thing the protection rests on. setup and protect elevate
# THEMSELVES, for the one step that needs it, and drop back.
# --------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  This shell is elevated. Stopping." -ForegroundColor Red
    Write-Host ""
    Warn "  pipx installs per user. Run from here and demo_cli goes onto the"
    Warn "  ADMINISTRATOR's PATH - invisible to the normal shell where you"
    Warn "  launch your agent. Everything would report installed, and nothing"
    Warn "  would ever be gated."
    Write-Host ""
    Say  "  Open a normal PowerShell window and run this again."
    Say  "  The one step that genuinely needs Administrator (the WinFsp driver)"
    Say  "  raises its own prompt when it gets there."
    Write-Host ""
    exit 1
}

# --------------------------------------------------------------------------
# 1. Python
# --------------------------------------------------------------------------
Step "[1/6] python"
$py = $null
foreach ($c in @("python","python3","py")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { Die "Python 3.9+ not found. Install it from python.org (tick 'Add to PATH'), then re-run." }
$pyver = & $py -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
$pyok  = & $py -c "import sys;print(1 if sys.version_info>=(3,9) else 0)" 2>$null
if ($pyok -ne "1") { Die "Python $pyver is too old. demo_cli needs 3.9+." }
OK "  python $pyver  ($((Get-Command $py).Source))"

# --------------------------------------------------------------------------
# 2. pipx
# --------------------------------------------------------------------------
Step "[2/6] pipx"
if (Get-Command pipx -ErrorAction SilentlyContinue) {
    OK "  already installed"
} else {
    Say "  not found - installing it for your user"
    $ErrorActionPreference = "Continue"
    & $py -m pip install --user -q pipx 2>&1 | Out-Null
    & $py -m pipx ensurepath 2>&1 | Out-Null
    $ErrorActionPreference = "Stop"
    $scripts = Join-Path (& $py -c "import site;print(site.getuserbase())") "Scripts"
    if (Test-Path $scripts) { $env:Path = "$scripts;$env:Path" }
    if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
        Die "could not install pipx. Try:  $py -m pip install --user pipx"
    }
    OK "  installed"
}

# --------------------------------------------------------------------------
# 3. The WinFsp driver - the only step that needs Administrator.
#
# It comes BEFORE demo_cli because the winfspy binding is built against it.
# Install them the other way round and the binding fails for a reason that
# looks like a packaging problem and is not.
#
# VERIFY BY PROBE, NEVER BY EXIT CODE. This project's standing lesson is that
# an installer reporting success is not evidence of anything; the registry is.
# --------------------------------------------------------------------------
function Find-WinFsp {
    foreach ($k in @("HKLM:\SOFTWARE\WOW6432Node\WinFsp", "HKLM:\SOFTWARE\WinFsp")) {
        if (Test-Path $k) {
            $d = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).InstallDir
            if ($d -and (Test-Path $d)) { return $d }
        }
    }
    if (Test-Path "C:\Program Files (x86)\WinFsp") { return "C:\Program Files (x86)\WinFsp" }
    return $null
}
function Find-WinFspDll ($dir) {
    if (-not $dir) { return $null }
    foreach ($n in @("winfsp-x64.dll","winfsp-x86.dll")) {
        $p = Join-Path (Join-Path $dir "bin") $n
        if (Test-Path $p) { return $p }
    }
    return $null
}

Step "[3/6] WinFsp (the filesystem guard's driver)"
$dll = Find-WinFspDll (Find-WinFsp)
if ($dll) {
    OK "  already installed  ($dll)"
} else {
    Say "  not installed."
    Say ""
    Say "  WinFsp is a signed, third-party kernel driver (winfsp.dev) that lets"
    Say "  demo_cli see file operations as they happen, rather than guessing"
    Say "  from the command text. Without it you still get the string layer and"
    Say "  the egress layer - but not the one that catches what the classifier"
    Say "  cannot read."
    Say ""
    Say "  Installing it needs Administrator. Nothing else here does."
    $ans = Read-Host "  Install WinFsp now? [Y/n]"
    if ($ans -eq "" -or $ans -match '^[Yy]') {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Say "  running winget (it will raise its own Administrator prompt)..."
            $ErrorActionPreference = "Continue"
            winget install --id WinFsp.WinFsp --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
            $ErrorActionPreference = "Stop"
            # Do NOT trust $LASTEXITCODE. Re-probe.
            $dll = Find-WinFspDll (Find-WinFsp)
        }
        if ($dll) {
            OK "  installed  ($dll)"
        } else {
            Warn "  automatic install did not work (winget missing, declined, or"
            Warn "  a different package id). Do it by hand - it takes a minute:"
            Say  ""
            Say  "      1. download the MSI:  https://winfsp.dev/rel/"
            Say  "      2. from an Administrator prompt:"
            Say  "           msiexec /i winfsp-<version>.msi ADDLOCAL=ALL"
            Say  ""
            Say  "      ADDLOCAL=ALL includes the Developer feature, which the"
            Say  "      winfspy binding needs. The default install may omit it."
            Say  ""
            Say  "  Then re-run this script. Continuing without the filesystem guard."
        }
    } else {
        Warn "  skipped. The filesystem guard will be unavailable; everything else works."
    }
}

# --------------------------------------------------------------------------
# 4. demo_cli itself
# --------------------------------------------------------------------------
Step "[4/6] demo_cli"
if ($env:DEMO_CLI_LOCAL) { $base = $env:DEMO_CLI_LOCAL }
else { $base = "git+https://github.com/nizaryart/DEMO_LOADING.git@$TAG" }

if ($dll) {
    # PEP 508 direct reference, so the [windows] extra applies to a git source.
    if ($base -like "git+*") { $spec = "demo_cli[windows] @ $base" } else { $spec = "$base[windows]" }
    Say "  installing with the [windows] extra (winfspy)"
} else {
    $spec = $base
    Say "  installing without the [windows] extra - no WinFsp on this machine"
}
$ErrorActionPreference = "Continue"
pipx install --force $spec 2>&1 | Out-Null
$code = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($code -ne 0) { Die "pipx install failed. Try it by hand to see why:`n    pipx install `"$spec`"" }
OK "  installed"

# --------------------------------------------------------------------------
# 5. Does it survive a NEW terminal?
#
# The old installer checked $env:Path, which it had just edited itself - so it
# could only ever answer yes. The question that matters is whether the PERSISTED
# user PATH carries pipx's bin directory, because that is the PATH the shell
# you launch your agent from will have.
# --------------------------------------------------------------------------
Step "[5/6] reachable from a new terminal"
$bin = $null
$ErrorActionPreference = "Continue"
$bin = (pipx environment --value PIPX_BIN_DIR) 2>$null
$ErrorActionPreference = "Stop"
if (-not $bin) { $bin = Join-Path $env:USERPROFILE ".local\bin" }

$persisted = @(
    [Environment]::GetEnvironmentVariable("Path","User"),
    [Environment]::GetEnvironmentVariable("Path","Machine")
) -join ";"
$onPersisted = ($persisted -split ";" | Where-Object { $_ -and ($_.TrimEnd('\') -ieq $bin.TrimEnd('\')) }).Count -gt 0

if (Get-Command demo_cli -ErrorAction SilentlyContinue) {
    OK "  this shell:   $((Get-Command demo_cli).Source)"
} else {
    if (Test-Path $bin) { $env:Path = "$bin;$env:Path" }
    if (Get-Command demo_cli -ErrorAction SilentlyContinue) { OK "  this shell:   $((Get-Command demo_cli).Source)" }
    else { Die "demo_cli is not runnable even after adding $bin to PATH. Something is wrong with the pipx install." }
}
if ($onPersisted) {
    OK "  new terminals: yes ($bin is in your user PATH)"
} else {
    Warn "  new terminals: NO - $bin is not in your persisted PATH."
    Warn "  Until it is, the shell you launch your agent from will not find"
    Warn "  demo_cli, the hook will silently never run, and you will not be told."
    Say  ""
    Say  "      pipx ensurepath"
    Say  ""
    Say  "  then CLOSE this window and open a new one."
}

# Now that demo_cli is installed, it can answer for winfspy better than we can.
if ($dll) {
    $ErrorActionPreference = "Continue"
    $probe = (demo_cli doctor 2>&1 | Out-String)
    $ErrorActionPreference = "Stop"
    if ($probe -match "winfspy binding\s+.*will not import") {
        Warn "  winfspy is installed and WinFsp is present, but it does not load."
        Warn "  Most often the MSI was installed without the Developer feature:"
        Say  "      msiexec /i winfsp-<version>.msi ADDLOCAL=ALL"
    }
}

# --------------------------------------------------------------------------
# 6. Optional, and deliberately not installed for you.
# --------------------------------------------------------------------------
Step "[6/6] optional extras"
if (Get-Command mitmdump -ErrorAction SilentlyContinue) {
    OK "  mitmdump found - the egress layer can run"
} else {
    Say "  mitmdump not found. The egress layer (gating destructive external"
    Say "  API calls) needs it. It is a large dependency and it intercepts TLS,"
    Say "  so it is your call, not the installer's:"
    Say ""
    Say "      pipx inject --include-apps demo-cli mitmproxy"
    Say ""
    Say "  --include-apps matters: without it the library installs and the"
    Say "  mitmdump BINARY still is not on PATH, which is what demo_cli looks for."
}
if (-not (Get-Command pg_dump -ErrorAction SilentlyContinue)) {
    Say "  pg_dump not found - database snapshots are disabled. Only relevant"
    Say "  if your agent touches a Postgres database."
}

# --------------------------------------------------------------------------
Say ""
Say "-------------------------------------------------------------"
demo_cli doctor
Say "-------------------------------------------------------------"
Say ""
OK  "The machine is ready. No project has been touched."
Say ""
Say "To guard a project - this MOVES its files, and tells you so first:"
Say ""
Say "    cd C:\path\to\your\project"
Say "    demo_cli setup ."
Say ""
Say "To try the guard without any of that:"
Say ""
Say "    demo_cli check `"Remove-Item -Recurse -Force .\build`""
Say ""
