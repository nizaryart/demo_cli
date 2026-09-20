"""`demo_cli guarded <agent>` - bring up what can be brought up, and say so.

Setup had become four things with four lifetimes: hooks (persistent, per
host), the mount (detached, needs admin), the egress proxy (a second
terminal), environment variables (per shell). Nothing told anyone how many
were actually on, and "installed but inert" has been the dangerous state five
times in this project.

Two properties are tested harder than the rest:

  * ONLY RUNNING LAYERS GET VARIABLES. Pointing HTTPS_PROXY at a dead port
    breaks every network call in every child, long after anyone remembers
    setting it - the footgun that makes a tool get uninstalled.
  * A LAYER THAT IS OFF IS VISIBLE. The report is the point; a coverage line
    nobody sees is worth nothing.
"""
import os
import socket

import pytest

from demo_cli import guarded as g
from demo_cli.config import Config


@pytest.fixture
def cfg(tmp_path):
    return Config(project_root=str(tmp_path))


@pytest.fixture
def listening():
    """A real socket, because 'is the proxy up' has exactly one honest test."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    yield s.getsockname()[1]
    s.close()


# --------------------------------------------------------------------------
# Is anything actually listening
# --------------------------------------------------------------------------

def test_an_open_port_is_detected(listening):
    assert g.port_open(listening) is True


def test_a_port_stops_being_open_once_the_listener_goes_away():
    """The property that matters: this reflects reality NOW, not at some
    earlier moment. mitmdump is started separately, may be run by hand in
    another terminal, and may have died - a recorded pid would answer the
    wrong question."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    assert g.port_open(port) is True
    s.close()
    assert g.port_open(port) is False


# --------------------------------------------------------------------------
# The child environment - only for layers that are RUNNING
# --------------------------------------------------------------------------

def test_no_proxy_variables_when_the_proxy_is_down():
    """THE footgun this avoids. HTTPS_PROXY pointing at a dead port makes
    every network call in every child fail, and the cause is invisible."""
    env = g.child_env({}, 8080, egress_up=False)
    assert "HTTPS_PROXY" not in env
    assert "REQUESTS_CA_BUNDLE" not in env


def test_proxy_variables_are_set_when_it_is_up():
    env = g.child_env({}, 8080, egress_up=True)
    assert env["HTTPS_PROXY"] == "http://localhost:8080"
    assert env["HTTP_PROXY"] == "http://localhost:8080"


def test_both_cases_of_the_variable_names_are_set():
    """curl and requests read the lowercase spelling; plenty of other tools
    read the uppercase one. Setting one and not the other guards half the
    traffic and looks like it guards all of it."""
    env = g.child_env({}, 8080, egress_up=True)
    assert env["https_proxy"] == env["HTTPS_PROXY"]
    assert env["http_proxy"] == env["HTTP_PROXY"]


def test_localhost_is_never_proxied():
    """The agent talking to a local dev server - or to the guard's own port -
    would otherwise loop back through the proxy."""
    env = g.child_env({}, 8080, egress_up=True)
    assert "127.0.0.1" in env["NO_PROXY"]
    assert "localhost" in env["NO_PROXY"]


def test_llm_endpoints_are_never_proxied():
    """AI model endpoints (Anthropic, OpenAI, Gemini) must never route through
    the proxy - the agent's control plane stream must not be buffered or broken."""
    env = g.child_env({}, 8080, egress_up=True)
    np = env["NO_PROXY"]
    assert "api.anthropic.com" in np
    assert "api.openai.com" in np
    assert "generativelanguage.googleapis.com" in np
    assert "*.anthropic.com" in np
    assert "*.openai.com" in np


def test_custom_and_existing_no_proxy_merged_cleanly():
    base = {"NO_PROXY": "corp.internal,example.com"}
    env = g.child_env(base, 8080, egress_up=True, extra_no_proxy=["custom.ai"])
    np = env["NO_PROXY"]
    assert "corp.internal" in np
    assert "example.com" in np
    assert "custom.ai" in np
    assert "localhost" in np
    assert "api.anthropic.com" in np


def test_the_existing_environment_is_preserved():
    env = g.child_env({"PATH": "/usr/bin", "HOME": "/home/x"}, 8080, egress_up=True)
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/home/x"


def test_the_caller_environment_is_not_mutated():
    base = {"PATH": "/usr/bin"}
    g.child_env(base, 8080, egress_up=True)
    assert base == {"PATH": "/usr/bin"}, "guarded must not edit the parent's env"


@pytest.mark.skipif(os.name == "nt", reason="BASH_ENV is POSIX")
def test_bash_env_is_set_only_when_the_shell_guard_exists(monkeypatch):
    monkeypatch.setattr(g, "shell_guard_script", lambda: None)
    assert "BASH_ENV" not in g.child_env({}, 8080, egress_up=False)
    monkeypatch.setattr(g, "shell_guard_script", lambda: "/home/x/.demo_cli_shellguard.sh")
    assert g.child_env({}, 8080, egress_up=False)["BASH_ENV"].endswith("shellguard.sh")


def test_the_ca_bundle_is_only_set_when_the_file_exists(monkeypatch):
    """Naming a CA file that is not there makes every TLS handshake fail,
    which reads as 'the guard broke the internet'."""
    monkeypatch.setattr(g, "ca_bundle", lambda: None)
    assert "REQUESTS_CA_BUNDLE" not in g.child_env({}, 8080, egress_up=True)
    monkeypatch.setattr(g, "ca_bundle", lambda: "/home/x/ca.pem")
    env = g.child_env({}, 8080, egress_up=True)
    assert env["REQUESTS_CA_BUNDLE"] == env["NODE_EXTRA_CA_CERTS"] == "/home/x/ca.pem"


# --------------------------------------------------------------------------
# The coverage report
# --------------------------------------------------------------------------

def test_an_installed_hook_is_reported_active(cfg):
    layers = g.assess(cfg, 8080, [("claude code", "/x/.claude/settings.json")],
                      egress_up=False)
    string = next(x for x in layers if x.name == "string layer")
    assert string.ok and "claude code" in string.detail


def test_no_hook_is_reported_with_the_command_that_fixes_it(cfg):
    layers = g.assess(cfg, 8080, [("claude code", None)], egress_up=False)
    string = next(x for x in layers if x.name == "string layer")
    assert not string.ok
    assert string.fixable and "install-hook" in string.fixable


def test_a_down_proxy_is_reported_with_its_port(cfg):
    layers = g.assess(cfg, 8123, [], egress_up=False)
    egress = next(x for x in layers if x.name == "egress")
    assert not egress.ok and "8123" in egress.detail


def test_a_live_proxy_is_reported_active(cfg):
    layers = g.assess(cfg, 8080, [], egress_up=True)
    assert next(x for x in layers if x.name == "egress").ok


def test_a_stale_mount_record_is_reported_as_not_running(cfg, tmp_path):
    """The state where somebody believes they are protected and is not - it
    has to be visible at launch, not only in doctor."""
    from demo_cli import mountstate
    mount = tmp_path / "guarded"
    mount.mkdir()
    mountstate.write(cfg, 999_999_998, str(mount))
    fs = next(x for x in g.assess(cfg, 8080, [], egress_up=False)
              if x.name == "filesystem")
    assert not fs.ok and "NOT RUNNING" in fs.detail


def test_a_live_mount_is_reported_active(cfg, tmp_path):
    from demo_cli import mountstate
    mount = tmp_path / "guarded"
    mount.mkdir()
    mountstate.write(cfg, os.getpid(), str(mount))
    fs = next(x for x in g.assess(cfg, 8080, [], egress_up=False)
              if x.name == "filesystem")
    assert fs.ok and str(mount) in fs.detail


def test_the_summary_counts_what_is_on(cfg):
    layers = [g.Layer("a", True, ""), g.Layer("b", False, ""), g.Layer("c", True, "")]
    assert g.summary(layers) == "2 of 3 layers active"


def test_every_layer_that_is_off_offers_a_way_to_turn_it_on(cfg):
    """Except the ones with no always-on form - Linux has no equivalent of the
    WinFsp mount, and saying 'turn it on' there would be a lie."""
    layers = g.assess(cfg, 8080, [("claude code", None)], egress_up=False)
    for layer in layers:
        if layer.ok or "no always-on layer" in layer.detail:
            continue
        assert layer.fixable, f"{layer.name} is off with no stated remedy"


# --------------------------------------------------------------------------
# The heartbeat
#
# The coverage report prints once, at launch. If the mount crashes an hour in,
# or someone runs `demo_cli unmount` in another window, nothing says so and the
# person keeps working while believing they are covered. Sixth appearance of
# "is this thing actually protecting me?", and the one place it had no answer.
# --------------------------------------------------------------------------

def test_a_layer_going_down_is_reported():
    before = [g.Layer("filesystem", True, "mounted"), g.Layer("egress", True, ":8080")]
    after = [g.Layer("filesystem", False, "gone"), g.Layer("egress", True, ":8080")]
    assert [x.name for x in g.dropped(before, after)] == ["filesystem"]


def test_a_layer_that_was_already_down_is_not_reported_again():
    """Only TRANSITIONS. A guard that prints its status every minute is noise,
    and noise is how a real warning gets missed."""
    before = [g.Layer("egress", False, "down")]
    after = [g.Layer("egress", False, "down")]
    assert g.dropped(before, after) == []


def test_nothing_is_reported_when_nothing_changed():
    layers = [g.Layer("filesystem", True, "mounted")]
    assert g.dropped(layers, layers) == []
    assert g.recovered(layers, layers) == []


def test_a_layer_coming_back_is_reported():
    """Otherwise the user acts on a stale warning for the rest of the session."""
    before = [g.Layer("egress", False, "down")]
    after = [g.Layer("egress", True, ":8080")]
    assert [x.name for x in g.recovered(before, after)] == ["egress"]


def test_a_layer_that_disappears_from_the_report_is_not_a_drop():
    """Platform differences change which layers are assessed at all; a missing
    row is not the same as a row that failed."""
    before = [g.Layer("shell guard", True, "installed"), g.Layer("egress", True, "up")]
    after = [g.Layer("egress", True, "up")]
    assert g.dropped(before, after) == []


# --------------------------------------------------------------------------
# Environment scrubbing & VFS Cloaking configuration
# --------------------------------------------------------------------------

def test_child_env_strips_sensitive_variables(cfg):
    base = {
        "AWS_SECRET_ACCESS_KEY": "AKIA...",
        "AWS_REGION": "us-east-1",
        "DATABASE_URL": "postgres://user:pass@localhost/db",
        "DB_PASSWORD": "secretpassword",
        "DEMO_CLI_APPROVER_KEY": "structural_key_123",
        "GITHUB_TOKEN": "ghp_xxxx",
        "MY_SECRET_KEY": "supersecret",
        "SAFE_VAR": "harmless",
    }
    env = g.child_env(base, 8080, egress_up=False, config=cfg)
    assert env["SAFE_VAR"] == "harmless"
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "DB_PASSWORD" not in env
    assert "DEMO_CLI_APPROVER_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "MY_SECRET_KEY" not in env


def test_child_env_preserves_agent_keys(cfg):
    base = {
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "OPENAI_API_KEY": "sk-proj-...",
        "GEMINI_API_KEY": "AIza...",
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/user",
    }
    env = g.child_env(base, 8080, egress_up=False, config=cfg)
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-..."
    assert env["OPENAI_API_KEY"] == "sk-proj-..."
    assert env["GEMINI_API_KEY"] == "AIza..."
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/user"


def test_custom_env_policy_strip_and_preserve():
    from demo_cli.config import Config
    custom_cfg = Config(
        env_policy={
            "strip": ["CUSTOM_SECRET_*"],
            "preserve": ["CUSTOM_SECRET_ALLOWED"],
        }
    )
    base = {
        "CUSTOM_SECRET_FOO": "123",
        "CUSTOM_SECRET_ALLOWED": "456",
        "OTHER_VAR": "789",
    }
    env = custom_cfg.sanitized_env(base)
    assert "CUSTOM_SECRET_FOO" not in env
    assert env["CUSTOM_SECRET_ALLOWED"] == "456"
    assert env["OTHER_VAR"] == "789"


def test_config_is_cloaked():
    from demo_cli.config import Config
    c = Config()
    assert c.is_cloaked(".env") is True
    assert c.is_cloaked(".env.production") is True
    assert c.is_cloaked("secrets.env") is True
    assert c.is_cloaked(".demo_cli.toml") is True
    assert c.is_cloaked("secret.key") is True
    assert c.is_cloaked(".env.example") is False
    assert c.is_cloaked(".env.template") is False
    assert c.is_cloaked("README.md") is False
    assert c.is_cloaked("main.py") is False

