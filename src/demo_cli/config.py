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

import os
from dataclasses import dataclass, field
from typing import List, Optional

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


@dataclass
class Config:
    mode: str = "shadow"
    project_root: str = field(default_factory=os.getcwd)
    workspace_dir: str = ".demo_cli"
    approval_key_env: Optional[str] = None
    targets: List[TargetRule] = field(default_factory=list)
    egress: dict = field(default_factory=dict)  # [egress] table for the egress guard
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

    def match_target(self, ref: Optional[str]) -> Optional[TargetRule]:
        for t in self.targets:
            if t.matches(ref):
                return t
        return None

    def declared_env(self, ref: Optional[str]) -> Optional[str]:
        t = self.match_target(ref)
        return t.env if t else None


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
    root = find_project_root(start)
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
