"""Project configuration: `.demo_cli.toml`.

This is what makes the tool *declared, not guessed*, and what keeps state
project-local instead of wired into the install directory. A project opts its
real targets into protection by declaring them here:

    mode = "shadow"            # observe-only by default; "enforce" to gate

    [workspace]
    dir = ".demo_cli"          # receipts + recovery points live here, per project

    [approval]
    key_env = "DEMO_CLI_APPROVER_KEY"   # env var holding the structural-approval key

    [[target]]
    match = "production"       # substring matched against the resolved target ref
    env   = "production"
    recovery = "snapshot"      # snapshot | attest | none

Nothing here is required: with no config file the tool runs with safe defaults
(shadow mode, `.demo_cli/` under the project root, heuristic env detection).
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

def _read_toml_bytes(path):
    """Config file contents with any UTF-8 byte-order mark removed.

    Windows PowerShell 5.1's `Out-File -Encoding utf8` - the obvious way to
    write a config file on Windows - prefixes the file with a BOM (EF BB BF).
    TOML parsers reject it:

        TOMLDecodeError: Invalid statement (at line 1, column 1)

    which the hook then catches as an internal error and fails OPEN. The result
    is total, silent loss of protection: install-hook reports success, the hook
    fires, and the guard steps aside on every single command, with the only
    signal a stderr line the host discards. Found live on Windows, first command.

    A BOM is an encoding marker, not content, so stripping it is correct rather
    than lenient.
    """
    with open(path, "rb") as f:
        return f.read().lstrip(b"\xef\xbb\xbf")


try:  # Python 3.11+
    import tomllib as _toml

    def _load_toml(path):
        return _toml.loads(_read_toml_bytes(path).decode("utf-8"))
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.9/3.10
    try:
        import tomli as _toml

        def _load_toml(path):
            return _toml.loads(_read_toml_bytes(path).decode("utf-8"))
    except ModuleNotFoundError:  # pragma: no cover
        _toml = None

        def _load_toml(path):
            raise RuntimeError(
                "A .demo_cli.toml was found but no TOML parser is available. "
                "Install demo_cli on Python 3.11+, or `pip install tomli`."
            )

def config_error_message(cfg) -> str:
    """The one wording used everywhere a broken config is reported. Says what
    is wrong, where, why everything is blocked, and how to get out of it -
    a block with no way forward is its own kind of failure."""
    return (
        f"Cannot read {CONFIG_NAME}: {cfg.config_error}\n"
        "Every command is blocked while this file is unreadable, because you "
        "asked for protection and demo_cli cannot tell what you asked for.\n"
        "Fix the file, or delete it to fall back to shadow mode (observe only).\n"
        "If PowerShell wrote it, a UTF-8 BOM is the usual cause: "
        "Set-Content -Encoding utf8NoBOM, or `demo_cli init` to rewrite it."
    )


CONFIG_NAME = ".demo_cli.toml"
VALID_MODES = ("shadow", "enforce")
VALID_RECOVERY = ("snapshot", "attest", "none")


@dataclass
class TargetRule:
    match: str
    env: str = "unknown"
    recovery: str = "snapshot"

    def matches(self, ref: Optional[str]) -> bool:
        return bool(ref) and self.match.lower() in str(ref).lower()


DEFAULT_CLOAK_PATTERNS = [
    "*.env",
    ".env*",
    "*.key",
    ".demo_cli.toml",
]

DEFAULT_STRIP_ENV_PATTERNS = [
    "AWS_*",
    "*_SECRET*",
    "*_TOKEN",
    "DATABASE_URL",
    "DB_PASS*",
    "DEMO_CLI_APPROVER_KEY",
]

DEFAULT_PRESERVE_ENV = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "LANG",
    "LC_*",
    "TERM",
    "SHELL",
    "COMSPEC",
    "PATHEXT",
]


@dataclass
class Config:
    mode: str = "shadow"
    project_root: str = field(default_factory=os.getcwd)
    workspace_dir: str = ".demo_cli"
    approval_key_env: Optional[str] = None
    targets: List[TargetRule] = field(default_factory=list)
    egress: dict = field(default_factory=dict)  # [egress] table for the egress guard
    cloak: dict = field(default_factory=dict)   # [cloak] table for VFS file cloaking
    env_policy: dict = field(default_factory=dict)  # [env] table for environment scrubbing
    # [checkpoint] table. Off by default: copying the workspace before a
    # command is a real cost, and a guard that becomes slow without being asked
    # is a guard that gets uninstalled. See checkpoint.py.
    checkpoint: dict = field(default_factory=dict)
    source_path: Optional[str] = None  # path of the loaded config, if any
    # Set when a .demo_cli.toml EXISTS but could not be parsed. Deliberately a
    # field rather than an exception: an exception gets swallowed by the hooks'
    # catch-all and turns into fail-OPEN, which is how a BOM silently disabled
    # the whole guard on Windows. A value on the object cannot be caught by
    # accident - the guard has to look at it and decide.
    config_error: Optional[str] = None

    # ---- resolved paths (always project-local, never install-local) ----
    @property
    def workspace(self) -> str:
        return os.path.join(self.project_root, self.workspace_dir)

    @property
    def receipts_path(self) -> str:
        return os.path.join(self.workspace, "receipts.jsonl")

    @property
    def recovery_dir(self) -> str:
        return os.path.join(self.workspace, "recovery")

    @property
    def approver_key(self) -> Optional[str]:
        if not self.approval_key_env:
            return None
        return os.environ.get(self.approval_key_env) or None

    @property
    def cloak_enabled(self) -> bool:
        if isinstance(self.cloak, dict):
            return bool(self.cloak.get("enabled", True))
        return True

    @property
    def cloak_patterns(self) -> List[str]:
        if not self.cloak_enabled:
            return []
        if isinstance(self.cloak, dict) and "patterns" in self.cloak:
            p = self.cloak["patterns"]
            if isinstance(p, list):
                return [str(x) for x in p]
        return list(DEFAULT_CLOAK_PATTERNS)

    def is_cloaked(self, path: Optional[str]) -> bool:
        """Is `path` cloaked (hidden from VFS directory listings and direct access)?

        Exempts *.example and *.template files so the agent retains structural context.
        """
        if not path or not self.cloak_enabled:
            return False
        clean = path.replace("\\", "/").rstrip("/")
        base = os.path.basename(clean)
        lower_base = base.lower()
        if (lower_base.endswith(".example")
                or lower_base.endswith(".template")
                or ".example." in lower_base
                or ".template." in lower_base):
            return False
        patterns = self.cloak_patterns
        # Match both basename and full relative path
        for pattern in patterns:
            if fnmatch.fnmatch(base, pattern) or fnmatch.fnmatch(clean, pattern):
                return True
        return False

    def sanitized_env(self, base_env: Optional[dict] = None) -> dict:
        """Produce an environment scrubbed of sensitive secrets for child agent processes."""
        source = dict(os.environ if base_env is None else base_env)
        strip_patterns = list(DEFAULT_STRIP_ENV_PATTERNS)
        preserve_patterns = list(DEFAULT_PRESERVE_ENV)
        if isinstance(self.env_policy, dict):
            if "strip" in self.env_policy and isinstance(self.env_policy["strip"], list):
                strip_patterns = [str(x) for x in self.env_policy["strip"]]
            if "preserve" in self.env_policy and isinstance(self.env_policy["preserve"], list):
                preserve_patterns += [str(x) for x in self.env_policy["preserve"]]

        out = {}
        for k, v in source.items():
            if any(fnmatch.fnmatch(k, p) for p in preserve_patterns):
                out[k] = v
                continue
            if any(fnmatch.fnmatch(k, p) for p in strip_patterns):
                continue
            out[k] = v
        return out

    def match_target(self, ref: Optional[str]) -> Optional[TargetRule]:
        for t in self.targets:
            if t.matches(ref):
                return t
        return None

    def declared_env(self, ref: Optional[str]) -> Optional[str]:
        t = self.match_target(ref)
        return t.env if t else None

    def resolve_egress_port(self, cli_port: Optional[int] = None) -> Tuple[Optional[int], Optional[str]]:
        return resolve_egress_port(self, cli_port)


def resolve_egress_port(cfg: Optional[Config],
                        cli_port: Optional[int] = None) -> Tuple[Optional[int], Optional[str]]:
    """Resolve the egress proxy port from CLI args or .demo_cli.toml [egress] table.

    Precedence:
      1. Explicit CLI argument (--port <port>)
      2. Config file [egress] port = <port>
      3. Default 8080

    Returns:
      (port, None) if valid (1..65535)
      (None, error_message) if invalid
    """
    if cli_port is not None:
        try:
            p = int(cli_port)
            if not (1 <= p <= 65535):
                return None, f"invalid port {cli_port}: port must be between 1 and 65535."
            return p, None
        except (ValueError, TypeError):
            return None, f"invalid port {cli_port!r}: port must be an integer between 1 and 65535."

    if cfg and getattr(cfg, "egress", None) and isinstance(cfg.egress, dict) and "port" in cfg.egress:
        raw = cfg.egress["port"]
        try:
            p = int(raw)
            if not (1 <= p <= 65535):
                return None, f"invalid port {raw!r} in {CONFIG_NAME}: port must be between 1 and 65535."
            return p, None
        except (ValueError, TypeError):
            return None, f"invalid port {raw!r} in {CONFIG_NAME}: port must be an integer between 1 and 65535."

    return 8080, None


def ensure_workspace(cfg) -> Optional[str]:
    """Create <project_root>/.demo_cli, or say why it must not be created.

    Returns None on success, otherwise the reason - never raises, because
    every caller is a command that has other work to do.

    --------------------------------------------------------------------
    WHY A GUARD IN FRONT OF ONE makedirs CALL
    --------------------------------------------------------------------
    `os.makedirs(cfg.workspace, exist_ok=True)` creates the PARENTS too. When
    the project root does not exist, that quietly invents it - and on Windows
    a protected project's root is a MOUNT POINT that only exists while the
    guard is running. So any demo_cli command run while the guard was down
    left a real directory where the mount point belongs, and WinFsp will not
    mount over an existing directory. The guard could then never come back.

    Observed 2026-08-29 on the Windows project "demo". After a reboot, the
    logon task refused with "still exists and is not empty". The culprit was
    `demo_cli doctor` - the workspace-writable check - so the diagnostic
    bricked the thing it was diagnosing, and the directory's own timestamps
    are what proved it.

    The rule is general rather than Windows-shaped: a workspace under a path
    that does not exist is not this project's workspace, it is a new
    directory. Refusing costs one warning line; the alternative cost a
    filesystem guard that could not restart.
    """
    root = cfg.project_root
    if not os.path.isdir(root):
        return f"{root} does not exist - not creating it"
    try:
        os.makedirs(cfg.workspace, exist_ok=True)
    except OSError as e:
        return f"{cfg.workspace} could not be created ({e.strerror})"
    return None


BACKING_SUFFIX = ".real"


def redirect_to_mount(root: str) -> str:
    """A backing directory is not a project - it is the inside of one.

    THE THIRD LOCK DOMAIN. A protected project's files live in `<project>.real`,
    and that directory holds a real `.demo_cli.toml`, so `find_project_root`
    walking up from an Administrator shell standing there resolves the project
    to the BACKING. Every ledger write from that shell then goes straight to
    NTFS, while the hook's writes go through the WinFsp mount - a third set of
    byte-range locks that composes with neither of the other two.

    That is not hypothetical: reading logs from `labubu.real` in an elevated
    shell is what we did all through 2026-09-02, and a `demo_cli undo` or
    `verify` from that same prompt would have written there.

    Splitting the ledgers by writer does NOT fix this, because the split is by
    ROLE and a CLI command run from the backing still claims the main role.
    Without this the split would fix two domains of three and the corruption
    would continue at a lower rate - which is worse than not fixing it, since
    it would look solved.

    Only redirects while the guard is actually mounted. With no mount there is
    no second lock domain, the backing is the only copy of the files, and
    refusing to work there would lock a user out of their own recovery points.
    """
    # THE FILESYSTEM GUARD IS EXEMPT, and must be. It IS the mount; sending
    # its own ledger writes back through itself would route every append
    # through the operations handler that is making the append - reentrancy
    # into a filesystem from inside its own callback, on a winfspy thread
    # pool. The backing is the correct destination for that one process, and
    # it is the only writer there, which is the whole point of the split.
    if os.environ.get("DEMO_CLI_FS_GUARD"):
        return root
    if not root.endswith(BACKING_SUFFIX):
        return root
    project = root[:-len(BACKING_SUFFIX)]
    if not os.path.isdir(project):
        return root
    try:
        from . import mountstate
        if mountstate.status(Config(project_root=project)).running:
            return project
    except Exception:
        pass            # never let this bookkeeping block a command
    return root


def find_project_root(start: Optional[str] = None) -> str:
    """Walk up from `start` looking for a .demo_cli.toml or a .git directory.
    Falls back to CLAUDE_PROJECT_DIR, then the start directory."""
    start = os.path.abspath(start or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    cur = start
    while True:
        if os.path.exists(os.path.join(cur, CONFIG_NAME)) or os.path.isdir(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return start
        cur = parent


def load_config(start: Optional[str] = None) -> Config:
    """Load configuration from the nearest .demo_cli.toml, or return defaults."""
    root = redirect_to_mount(find_project_root(start))
    cfg = Config(project_root=root)
    path = os.path.join(root, CONFIG_NAME)
    if not os.path.exists(path):
        return cfg

    try:
        data = _load_toml(path)
    except Exception as exc:
        # A config that exists but cannot be read is NOT the same as no config.
        # No config means "no opinion" -> defaults. A broken one means the user
        # asked for protection and we cannot tell what they asked for, so the
        # guard refuses instead of quietly proceeding unprotected.
        cfg.source_path = path
        cfg.config_error = f"{path}: {exc}"
        return cfg
    cfg.source_path = path

    mode = str(data.get("mode", cfg.mode)).strip().lower()
    if mode in VALID_MODES:
        cfg.mode = mode

    ws = data.get("workspace", {})
    if isinstance(ws, dict) and ws.get("dir"):
        cfg.workspace_dir = str(ws["dir"])

    appr = data.get("approval", {})
    if isinstance(appr, dict) and appr.get("key_env"):
        cfg.approval_key_env = str(appr["key_env"])

    eg = data.get("egress", {})
    if isinstance(eg, dict):
        cfg.egress = eg

    cl = data.get("cloak", {})
    if isinstance(cl, dict):
        cfg.cloak = cl

    ep = data.get("env", {})
    if isinstance(ep, dict):
        cfg.env_policy = ep

    ck = data.get("checkpoint", {})
    if isinstance(ck, dict):
        cfg.checkpoint = ck

    for raw in data.get("target", []) or []:
        if not isinstance(raw, dict) or "match" not in raw:
            continue
        recovery = str(raw.get("recovery", "snapshot")).strip().lower()
        if recovery not in VALID_RECOVERY:
            recovery = "snapshot"
        cfg.targets.append(TargetRule(
            match=str(raw["match"]),
            env=str(raw.get("env", "unknown")).strip().lower(),
            recovery=recovery,
        ))
    return cfg
