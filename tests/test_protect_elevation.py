"""The elevation path in protect.py, after the 2026-09-09 review.

Six findings, all in the twenty lines that ask Windows for Administrator:

  #6   icacls was a bare image name
  #7   the child was `shutil.which("demo_cli")` launched through `cmd /c`
  #8   the elevated log was a fixed, predictable, agent-writable path
  #10  GetExitCodeProcess's return value was discarded
  #13  the containment guards compared path TEXT
  #15  the process handle from SEE_MASK_NOCLOSEPROCESS was never closed

Five of the six are Windows-only code that cannot run here, so they are
pinned structurally - against the SOURCE, which is the thing that regresses.
That is weaker than execution and is used only where execution is impossible;
#13 and the log redirect are tested for real, by running them.
"""
import ast
import inspect
import io
import ntpath
import os
import subprocess
import sys
import tokenize

from demo_cli import protect as P


def code(obj) -> str:
    r"""Source with every comment and docstring removed.

    A structural test that greps raw source proves nothing, because the
    comment explaining a fix contains the very words the fix removed - which
    is how an earlier test in this suite passed by matching `# NOT os.execve`
    instead of the call. Strip the prose, assert against what runs.
    """
    src = obj if isinstance(obj, str) else inspect.getsource(obj)
    src = textwrap_dedent(src)
    lines = src.splitlines(keepends=True)

    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            r, c = tok.start[0] - 1, tok.start[1]
            lines[r] = lines[r][:c] + "\n"

    tree = ast.parse("".join(lines))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            for r in range(body[0].lineno - 1, body[0].end_lineno):
                lines[r] = "\n"
    return "".join(lines)


def textwrap_dedent(s: str) -> str:
    import textwrap
    return textwrap.dedent(s)


SRC = code(P)
ELEVATE = code(P.rerun_elevated)


# ---------------------------------------------------------------- #6 icacls

def test_icacls_is_an_absolute_path_and_not_a_name():
    """CreateProcess resolves a bare image name against the CURRENT DIRECTORY
    first on Windows, and the elevated child starts in the directory the user
    invoked from - which plan_protect's own refusal steers them to, and which
    the unelevated agent can write."""
    # Judged with Windows path rules: this string is a Windows path even when
    # it is built on Linux, where posixpath calls C:\Windows relative.
    assert ntpath.isabs(P._ICACLS)
    assert ntpath.basename(P._ICACLS).lower() == "icacls.exe"
    assert "system32" in P._ICACLS.lower()


def test_no_call_site_looks_icacls_up_through_a_search_path():
    assert "shutil.which" not in SRC
    assert '"icacls"' not in SRC          # the bare name, as an argument
    for line in SRC.splitlines():         # every invocation names the absolute one
        if "icacls" in line.lower() and ("_run(" in line or "subprocess.run(" in line):
            assert "_ICACLS" in line, line


def test_the_presence_check_is_the_file_itself_not_the_path():
    """shutil.which finds a planted copy too, so it is not a check at all."""
    assert "os.path.isfile(_ICACLS)" in inspect.getsource(P._icacls_present)


# ------------------------------------------------------------- #7 the child

def test_the_elevated_image_is_absolute_and_comes_from_this_interpreter():
    exe, argv = P._elevation_target(["undo", "abc123"])
    assert exe and os.path.isabs(exe) and os.path.isfile(exe)
    assert exe == os.path.abspath(sys.executable)
    assert argv == ["-m", "demo_cli", "undo", "abc123"]


def test_a_console_script_shim_is_launched_directly(tmp_path, monkeypatch):
    """If we ARE demo_cli.exe there is no -m to add."""
    shim = tmp_path / "demo_cli.exe"
    shim.write_bytes(b"MZ")
    monkeypatch.setattr(P.sys, "executable", str(shim))
    exe, argv = P._elevation_target(["undo", "abc"])
    assert exe == str(shim)
    assert argv == ["undo", "abc"]


def test_an_interpreter_that_is_not_there_refuses_to_elevate(tmp_path, monkeypatch):
    """No image, no UAC prompt. Never fall back to a search."""
    monkeypatch.setattr(P.sys, "executable", str(tmp_path / "gone.exe"))
    assert P._elevation_target(["undo", "abc"]) == (None, [])


def test_nothing_in_the_elevation_path_is_a_shell_or_a_path_search():
    """`cmd /c "<which('demo_cli')> ... > log 2>&1"` was three defects.

    list2cmdline IS NOT cmd quoting - it quotes for space and tab and nothing
    else - so `&`, `|` and `%` in an argument reached an elevated shell live.
    _undo_argv forwards an agent-supplied id verbatim.
    """
    assert "cmd.exe" not in ELEVATE
    assert "/c" not in ELEVATE
    assert "shutil.which" not in SRC
    assert "info.lpFile = exe" in ELEVATE


def test_the_argument_that_used_to_be_an_injection_stays_one_token():
    """`demo_cli undo "x&whoami"` under the old code turned a UAC prompt the
    user is trained to approve into arbitrary elevated execution."""
    _, argv = P._elevation_target(["undo", "x&whoami"])
    line = subprocess.list2cmdline(argv + ["--elevated-log", "C:\\t\\a.log"])
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        ctypes.windll.shell32.CommandLineToArgvW.restype = ctypes.POINTER(
            ctypes.c_wchar_p)
        n = ctypes.c_int()
        p = ctypes.windll.shell32.CommandLineToArgvW(
            "x.exe " + line, ctypes.byref(n))
        got = [p[i] for i in range(n.value)][1:]
        ctypes.windll.kernel32.LocalFree(p)
        assert "x&whoami" in got          # one argv element, not two commands
    else:
        # No CRT parser here; assert instead that no shell will ever see it.
        assert "x&whoami" in line
        # and nothing between us and the child will reinterpret it
        assert "cmd.exe" not in ELEVATE
        assert "info.lpFile = exe" in ELEVATE


# ---------------------------------------------------------------- #8 the log

def test_the_elevated_log_is_created_fresh_and_never_at_a_fixed_path():
    """A predictable agent-writable path is a symlink-redirection target for
    arbitrary elevated file creation, and elevated_output prints it back as
    if it were ours."""
    assert "demo_cli-elevated.log" not in SRC
    assert "tempfile.mkstemp(" in ELEVATE
    assert "_LAST_ELEVATED_LOG = log" in ELEVATE


def test_no_elevated_run_means_no_output_rather_than_someone_elses_file(monkeypatch):
    monkeypatch.setattr(P, "_LAST_ELEVATED_LOG", None)
    assert P.elevated_output() == ""


def test_the_output_read_back_is_the_log_this_run_created(tmp_path, monkeypatch):
    log = tmp_path / "e.log"
    log.write_text("Access is denied.\n", encoding="utf-8")
    monkeypatch.setattr(P, "_LAST_ELEVATED_LOG", str(log))
    assert P.elevated_output() == "Access is denied."


def test_an_unreadable_log_is_empty_not_an_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_LAST_ELEVATED_LOG", str(tmp_path / "nope.log"))
    assert P.elevated_output() == ""


# --------------------------------------------------- #10 / #15 the handle

def test_a_failed_exit_code_query_is_not_reported_as_success():
    """GetExitCodeProcess failing leaves the DWORD zero-initialised, and 0 is
    success - so a call that told us nothing said the elevated step worked."""
    assert "ok = kernel32.GetExitCodeProcess" in ELEVATE
    assert "if ok else None" in ELEVATE


def test_the_process_handle_is_closed():
    """SEE_MASK_NOCLOSEPROCESS hands us a handle and makes it ours to close."""
    assert "CloseHandle(info.hProcess)" in ELEVATE


# ------------------------------------------------- #13 containment, for real

def test_a_backing_reached_through_a_symlink_is_still_inside(tmp_path):
    """commonpath normalises case and separators and NOTHING ELSE, so two
    spellings of one directory did not compare equal and `--backing` could
    put the backing inside the project it backs."""
    proj = tmp_path / "myproject"
    proj.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(proj, target_is_directory=True)

    plan = P.plan_protect(str(proj), backing=str(alias / "backing"))
    assert any("must be separate" in p for p in plan.problems), plan.problems


def test_a_backing_genuinely_elsewhere_is_still_allowed(tmp_path):
    """The guard must refuse the alias without refusing everything."""
    proj = tmp_path / "myproject"
    proj.mkdir()
    plan = P.plan_protect(str(proj), backing=str(tmp_path / "myproject.real"))
    assert not any("must be separate" in p for p in plan.problems), plan.problems


def test_standing_inside_through_a_symlink_is_still_standing_inside(tmp_path, monkeypatch):
    """Same trick against the cwd check brings back WinError 32 from an
    ELEVATED process, after the UAC prompt."""
    proj = tmp_path / "myproject"
    (proj / "sub").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(proj, target_is_directory=True)

    monkeypatch.setattr(P.os, "getcwd", lambda: str(alias / "sub"))
    plan = P.plan_protect(str(proj), backing=str(tmp_path / "b.real"))
    assert any("standing inside" in p for p in plan.problems), plan.problems


def test_a_path_that_cannot_be_resolved_is_compared_as_given(tmp_path):
    """_resolved never raises: unresolvable is no worse than before."""
    p = str(tmp_path / "does" / "not" / "exist")
    assert P._resolved(p) == os.path.normcase(os.path.abspath(p))


# ------------------------------------- the flag that carries the log across

def test_the_elevated_log_flag_is_accepted_but_not_advertised():
    from demo_cli import cli
    parser = cli.build_parser()
    args = parser.parse_args(["doctor", "--elevated-log", "/tmp/x.log"])
    assert args.elevated_log == "/tmp/x.log"
    assert "--elevated-log" not in parser.format_help()


def test_the_child_writes_its_output_to_the_log_and_not_to_the_console(tmp_path):
    """The whole point: without this a failure on the far side of a UAC
    prompt arrives as a bare exit code with the error already gone."""
    log = tmp_path / "child.log"
    env = dict(os.environ)
    env.pop("DEMO_CLI_DISABLE", None)
    env["PYTHONPATH"] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(P.__file__))))
    r = subprocess.run([sys.executable, "-m", "demo_cli", "doctor",
                        "--elevated-log", str(log)],
                       capture_output=True, text=True, cwd=str(tmp_path),
                       env=env, timeout=120)
    assert r.stdout == ""
    assert r.stderr == ""
    assert "doctor" in log.read_text(encoding="utf-8", errors="replace")


def test_an_unwritable_log_does_not_stop_the_command(tmp_path):
    """Losing the transcript must not lose the work."""
    env = dict(os.environ)
    env.pop("DEMO_CLI_DISABLE", None)
    env["PYTHONPATH"] = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(P.__file__))))
    bad = str(tmp_path / "no" / "such" / "dir" / "x.log")
    r = subprocess.run([sys.executable, "-m", "demo_cli", "doctor",
                        "--elevated-log", bad],
                       capture_output=True, text=True, cwd=str(tmp_path),
                       env=env, timeout=120)
    assert r.returncode in (0, 1)
    assert "doctor" in r.stdout
