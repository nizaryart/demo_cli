"""Behavioral guard: run a command under a syscall monitor and snapshot the
files it is about to destroy - BEFORE the destructive syscall executes.

This is the "obfuscation-proof floor" (REC #6). The pre-execution string guard
(classify.py) reads the command text and is defeated by indirection - obfuscated
commands (#002), a payload hidden in a sourced file (#003), a parser-differential
that mis-counts what bash deletes (#004). This layer does not read the string at
all: it lets the command run under ptrace and reacts to what it *does*. You
cannot obfuscate a syscall - `rm`, however written, becomes `unlink()` on a
kernel-resolved absolute path.

Scope: LOCAL filesystem destruction only, on Linux (ptrace is a Linux feature).
External blast radius (remote DB, force-push) is invisible to a local syscall
monitor and stays on the string guard's escalate path. This is a prototype
mechanism (ptrace, per-syscall stop); the production floor is seccomp-unotify.

It reuses the existing machinery: recovery.snapshot / Target build the backup,
receipts.append_receipt records it (hash-chained), so `demo_cli undo` and
`demo_cli verify` work on these entries exactly like the pre-execution path.
"""
from __future__ import annotations

import ctypes
import errno
import os
import sys
from typing import Dict, List, Optional, Set

from . import recovery
from .config import Config, load_config
from .context import build_context
from .receipts import Receipt, append_receipt

# --------------------------------------------------------------------------
# ptrace / register plumbing (x86-64 Linux)
# --------------------------------------------------------------------------

PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SETOPTIONS = 0x4200

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010
PTRACE_O_EXITKILL = 0x00100000
_OPTIONS = (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)

AT_FDCWD = -100
O_TRUNC = 0o1000
O_CREAT = 0o100


class _Regs(ctypes.Structure):
    # struct user_regs_struct, x86-64 order.
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.ptrace.restype = ctypes.c_long
_libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]


def _ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    res = _libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    e = ctypes.get_errno()
    if res == -1 and e:
        raise OSError(e, os.strerror(e))
    return res


def _getregs(pid: int) -> _Regs:
    regs = _Regs()
    _ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs


def _setregs(pid: int, regs: _Regs) -> None:
    _ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))


def _arg(regs: _Regs, i: int) -> int:
    # syscall args 1..6 -> rdi rsi rdx r10 r8 r9
    return (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9)[i]


def _signed(u: int) -> int:
    return u - (1 << 64) if u >= (1 << 63) else u


def _read_cstr(pid: int, addr: int, limit: int = 4096) -> Optional[str]:
    """Read a NUL-terminated string from the tracee's memory via /proc/pid/mem."""
    if not addr:
        return None
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as mem:
            mem.seek(addr)
            chunk = mem.read(limit)
    except OSError:
        return None
    nul = chunk.find(b"\x00")
    raw = chunk[:nul] if nul != -1 else chunk
    try:
        return raw.decode("utf-8", "surrogateescape")
    except Exception:
        return None


# --------------------------------------------------------------------------
# Which syscalls destroy a file, and where the path argument lives
# --------------------------------------------------------------------------

# nr -> (name, path_arg_index, dirfd_arg_index_or_None)
_DELETE = {
    87:  ("unlink", 0, None),          # unlink(path)
    263: ("unlinkat", 1, 0),           # unlinkat(dirfd, path, flags)
    84:  ("rmdir", 0, None),           # rmdir(path)
    85:  ("creat", 0, None),           # creat(path, mode) - truncates if exists
    76:  ("truncate", 0, None),        # truncate(path, len)
    82:  ("rename", 1, None),          # rename(old, NEW) - dest overwritten
    264: ("renameat", 3, 2),           # renameat(olddirfd, old, newdirfd, NEW)
    316: ("renameat2", 3, 2),          # renameat2(olddirfd, old, newdirfd, NEW, flags)
}
# open-family: truncate an existing file when O_TRUNC is set.
# nr -> (name, path_arg_index, flags_arg_index, dirfd_arg_index_or_None)
_OPEN = {
    2:   ("open", 0, 1, None),         # open(path, flags, mode)
    257: ("openat", 1, 2, 0),          # openat(dirfd, path, flags, mode)
}


def _resolve(pid: int, regs: _Regs, path_idx: int, dirfd_idx: Optional[int]) -> Optional[str]:
    """Resolve the syscall's path argument to an absolute path, honouring a
    dirfd for the *at variants (AT_FDCWD or an open directory fd)."""
    p = _read_cstr(pid, _arg(regs, path_idx))
    if p is None:
        return None
    if os.path.isabs(p):
        return os.path.normpath(p)
    # relative: resolve against the tracee's cwd, or the dirfd for *at calls.
    base = None
    if dirfd_idx is not None:
        dirfd = _signed(_arg(regs, dirfd_idx))
        if dirfd != AT_FDCWD:
            try:
                base = os.readlink(f"/proc/{pid}/fd/{dirfd}")
            except OSError:
                base = None
    if base is None:
        try:
            base = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            base = os.getcwd()
    return os.path.normpath(os.path.join(base, p))


# --------------------------------------------------------------------------
# Scope filter (avoid the noise problem: only in-project, pre-existing files)
# --------------------------------------------------------------------------

_IGNORE_PARTS = {".git", "node_modules", "__pycache__", ".demo_cli", ".demo_cli_recovery"}


def _in_scope(path: str, root: str) -> bool:
    ap = os.path.abspath(path)
    try:
        if os.path.commonpath([ap, root]) != root:
            return False
    except ValueError:
        return False
    if ap == root:
        return False
    rel_parts = set(os.path.relpath(ap, root).split(os.sep))
    return not (rel_parts & _IGNORE_PARTS)


# --------------------------------------------------------------------------
# The supervisor
# --------------------------------------------------------------------------

def run_supervised(argv: List[str], config: Optional[Config] = None,
                   deny: bool = False) -> int:
    """Fork+exec argv under ptrace; snapshot any in-scope, pre-existing file a
    destructive syscall is about to touch, then let it proceed (snapshot-then-
    allow). With deny=True, the destructive syscall is turned into a no-op
    (-EPERM) instead. Returns the child's exit code."""
    if sys.platform != "linux":
        raise RuntimeError("syscall guard requires Linux (ptrace).")
    config = config or load_config()
    root = os.path.abspath(config.project_root or os.getcwd())
    env = build_context(" ".join(argv), cwd=root).environment

    pid = os.fork()
    if pid == 0:                                   # child
        _ptrace(PTRACE_TRACEME, 0)
        try:
            os.execvp(argv[0], argv)
        except OSError as exc:
            os.write(2, f"demo_cli run: cannot exec {argv[0]!r}: {exc}\n".encode())
            os._exit(127)

    # parent: the reference monitor
    os.waitpid(pid, 0)                             # initial exec-stop
    _ptrace(PTRACE_SETOPTIONS, pid, 0, _OPTIONS)
    _ptrace(PTRACE_SYSCALL, pid)

    created: Set[str] = set()                      # files the command itself created
    snapped: Set[str] = set()                      # dedupe snapshots per path
    child_rc = 0

    while True:
        try:
            wpid, status = os.waitpid(-1, 0)
        except ChildProcessError:
            break
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            if wpid == pid:
                child_rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
            continue

        sig = os.WSTOPSIG(status) if os.WIFSTOPPED(status) else 0
        if sig == (5 | 0x80):                       # syscall-stop (SIGTRAP|0x80)
            _maybe_snapshot(wpid, root, created, snapped, env, config, deny)
        # ptrace-event / SIGSTOP / SIGTRAP control stops are just resumed; a
        # prototype does not need full signal-forwarding fidelity.
        try:
            _ptrace(PTRACE_SYSCALL, wpid, 0, 0)
        except OSError:
            pass                                    # tracee already gone

    return child_rc


_ENOSYS = ctypes.c_ulonglong(-errno.ENOSYS).value   # rax value at syscall-ENTRY


def _maybe_snapshot(pid: int, root: str, created: Set[str], snapped: Set[str],
                    env: str, config: Config, deny: bool) -> None:
    """On a syscall stop: act only at ENTRY (rax == -ENOSYS, the reliable
    entry/exit discriminator) and only for a destructive file syscall on an
    in-scope, pre-existing file - snapshot it (and optionally deny)."""
    try:
        regs = _getregs(pid)
    except OSError:
        return
    if regs.rax != _ENOSYS:
        return                                       # syscall-exit stop - ignore
    nr = regs.orig_rax

    # Track files the command creates, so we never snapshot its own temp files.
    if nr in _OPEN:
        _name, p_idx, f_idx, d_idx = _OPEN[nr]
        flags = _arg(regs, f_idx)
        path = _resolve(pid, regs, p_idx, d_idx)
        if path:
            if (flags & O_CREAT) and not os.path.exists(path):
                created.add(os.path.abspath(path))
            if not (flags & O_TRUNC):
                return                             # not a truncation - nothing to do
            name = "openat_trunc"
        else:
            return
    elif nr in _DELETE:
        name, p_idx, d_idx = _DELETE[nr]
        path = _resolve(pid, regs, p_idx, d_idx)
    else:
        return

    if not path:
        return
    ap = os.path.abspath(path)
    if ap in created or ap in snapped:
        return
    if not _in_scope(ap, root):
        return
    if not os.path.exists(ap):
        return                                     # nothing to lose (or already handled)

    snapped.add(ap)
    if deny:
        # Block: turn the syscall into a no-op (invalid nr -> the kernel returns
        # -ENOSYS), so the destruction never happens. No snapshot needed - there
        # is nothing to recover.
        regs.orig_rax = ctypes.c_ulonglong(-1).value
        try:
            _setregs(pid, regs)
        except OSError:
            pass
        dec_entry = None
        decision, reason = "ESCALATE", f"{name} on {ap} blocked before it ran (behavioral guard)."
    else:
        target = recovery.Target("dir" if os.path.isdir(ap) else "file", ap, ap)
        strategy = (config.match_target(ap).recovery if config.match_target(ap) else "snapshot")
        dec_entry = recovery.snapshot(target, config.recovery_dir, strategy,
                                      action=f"{name} {os.path.basename(ap)}")
        if dec_entry:
            decision, reason = "REVERSIBLE", f"Snapshotted before {name}; reversible (behavioral guard)."
        else:
            decision, reason = "ESCALATE", f"Could not snapshot {ap} before {name}."

    append_receipt(config.receipts_path, Receipt(
        action_raw=f"[syscall] {name} {ap}",
        action_type="syscall",
        target_environment=env,
        decision=decision,
        reason=reason,
        mode="enforce-syscall",
        matched_rule=f"sys_{name}",
        classification="destructive",
        recovery_point=dec_entry["recovery_point"] if dec_entry else None,
        agent_id="syscall-guard",
        session_id="run",
    ))
    sys.stderr.write(f"demo_cli [syscall] {decision}: {name} {ap}"
                     + (f"  (undo: demo_cli undo {dec_entry['id']})" if dec_entry else "") + "\n")
