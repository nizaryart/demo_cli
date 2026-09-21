"""Egress guard - the pure classifier core across all 5 protocols.
The mitmproxy addon (TLS, hold-and-ask prompt) is verified manually; here we
lock in classify_http + the operation extractors.
"""
from demo_cli.egress import classify_http, detect_protocol, _tokens, _verb_intent


def _level(**kw):
    return classify_http(**kw).level


# --- REST: method is the verb -------------------------------------------------

def test_rest_reads_are_safe():
    assert _level(method="GET", host="api.atlassian.com", path="/wiki/x") == "safe"
    assert _level(method="HEAD", host="api.stripe.com", path="/v1/x") == "safe"


def test_rest_delete_put_on_known_host_destructive():
    assert _level(method="DELETE", host="api.atlassian.com",
                  path="/wiki/rest/api/content/123") == "destructive"
    assert _level(method="PUT", host="shop.myshopify.com",
                  path="/admin/api/2024-01/themes/1/assets.json") == "destructive"


def test_rest_path_hint_boosts_post():
    # Stripe refund is a POST - caught by the path hint, not the method.
    assert _level(method="POST", host="api.stripe.com", path="/v1/refunds") == "destructive"


def test_rest_delete_unknown_host_reviews_by_default_blocks_when_strict():
    assert _level(method="DELETE", host="internal.example.com", path="/x") == "review"
    assert _level(method="DELETE", host="internal.example.com", path="/x",
                  strict_unknown_hosts=True) == "destructive"


def test_rest_ambiguous_post_unknown_host_is_safe():
    # a plain POST to an unknown host (telemetry, create) must not nag.
    assert _level(method="POST", host="telemetry.example.com", path="/collect") == "safe"


# --- GraphQL: query vs mutation grammar (body) --------------------------------

def test_graphql_mutation_delete_is_destructive():
    body = '{"query":"mutation { deleteRepository(id: 1) { ok } }"}'
    v = classify_http("POST", "api.github.com", "/graphql", {"content-type": "application/json"}, body)
    assert v.level == "destructive" and detect_protocol({}, "/graphql", body) == "graphql"


def test_graphql_query_is_safe():
    body = '{"query":"query { viewer { login } }"}'
    assert classify_http("POST", "api.github.com", "/graphql", {}, body).level == "safe"


def test_graphql_anonymous_query_is_safe():
    body = '{"query":"{ viewer { login } }"}'
    assert classify_http("POST", "api.github.com", "/graphql", {}, body).level == "safe"


def test_graphql_persisted_query_is_review_opaque():
    body = '{"extensions":{"persistedQuery":{"sha256Hash":"abc123"}}}'
    assert classify_http("POST", "api.github.com", "/graphql", {}, body).level == "review"


def test_graphql_mutation_unknown_verb_is_review():
    body = '{"query":"mutation { transmogrify(id: 1) { ok } }"}'
    assert classify_http("POST", "api.github.com", "/graphql", {}, body).level == "review"


# --- JSON-RPC: "method" field -------------------------------------------------

def test_jsonrpc_delete_destructive_get_safe():
    d = '{"jsonrpc":"2.0","method":"deleteBlock","params":{},"id":1}'
    g = '{"jsonrpc":"2.0","method":"getBlock","params":{},"id":1}'
    assert classify_http("POST", "api.notion.com", "/rpc", {}, d).level == "destructive"
    assert classify_http("POST", "api.notion.com", "/rpc", {}, g).level == "safe"


def test_jsonrpc_batch_any_destructive():
    body = '[{"jsonrpc":"2.0","method":"getX","id":1},{"jsonrpc":"2.0","method":"purgeCache","id":2}]'
    assert classify_http("POST", "api.notion.com", "/rpc", {}, body).level == "destructive"


# --- XML-RPC: <methodName> (WordPress) ----------------------------------------

def test_xmlrpc_wordpress_delete_destructive():
    body = ("<?xml version='1.0'?><methodCall>"
            "<methodName>wp.deletePost</methodName></methodCall>")
    hdr = {"content-type": "text/xml"}
    assert detect_protocol(hdr, "/xmlrpc.php", body) == "xmlrpc"
    assert classify_http("POST", "myblog.wordpress.com", "/xmlrpc.php", hdr, body).level == "destructive"


def test_xmlrpc_wordpress_get_safe():
    body = "<?xml version='1.0'?><methodCall><methodName>wp.getPosts</methodName></methodCall>"
    hdr = {"content-type": "text/xml"}
    assert classify_http("POST", "myblog.wordpress.com", "/xmlrpc.php", hdr, body).level == "safe"


# --- SOAP: SOAPAction header --------------------------------------------------

def test_soap_delete_action_destructive():
    hdr = {"content-type": "text/xml", "SOAPAction": '"http://tempuri.org/DeleteAccount"'}
    assert detect_protocol(hdr, "/svc", "<soap/>") == "soap"
    assert classify_http("POST", "api.contentful.com", "/svc", hdr, "<soap/>").level == "destructive"


def test_soap_read_action_safe():
    hdr = {"SOAPAction": '"http://tempuri.org/GetAccount"'}
    assert classify_http("POST", "api.contentful.com", "/svc", hdr, "<soap/>").level == "safe"


# --- helpers ------------------------------------------------------------------

def test_tokenizer_and_verb_intent():
    assert _tokens("wp.deletePost") == ["wp", "delete", "post"]
    assert _tokens("getBlock") == ["get", "block"]
    assert _verb_intent("deleteUser") == "destructive"
    assert _verb_intent("getUser") == "read"
    assert _verb_intent("createUser") == "write"


# --------------------------------------------------------------------------
# Launching the guard: the only part of this layer that is platform-coupled
#
# classify_http and the five protocol extractors are pure and already pass on
# both platforms. What did not port was the LAUNCHER:
#
#   * os.execve does not replace the process on Windows - it spawns a new one
#     and terminates this one, so the prompt returns, the proxy is orphaned,
#     and Ctrl-C never reaches it
#   * the setup steps were printed as bash `export VAR=value`, which does
#     nothing in PowerShell. Same class of mistake as telling somebody to
#     write a config with Out-File: it looks helpful and silently fails
# --------------------------------------------------------------------------
import os as _os
import pytest

from demo_cli import cli
from demo_cli import egress
from demo_cli.cli import egress_setup_lines


def test_egress_cli_reexports():
    exported = [
        "_MITM_DIR",
        "_CA_PEM_NAME",
        "_CA_CER_NAME",
        "_ca_path",
        "egress_setup_lines",
        "_trust_ca",
        "cmd_egress",
    ]
    for sym in exported:
        assert hasattr(egress, sym), f"egress missing {sym}"
        assert hasattr(cli, sym), f"cli missing re-export {sym}"
        assert getattr(cli, sym) is getattr(egress, sym), f"mismatch for {sym}"


def _text(port=8080, windows=False):
    return "\n".join(egress_setup_lines(port, windows=windows))


def test_posix_setup_uses_export():
    out = _text()
    assert "export HTTPS_PROXY=http://localhost:8080" in out
    assert "$env:" not in out


def test_windows_setup_uses_powershell_syntax():
    out = _text(windows=True)
    assert '$env:HTTPS_PROXY = "http://localhost:8080"' in out
    assert "export " not in out, "bash syntax silently does nothing in PowerShell"


def test_the_port_is_carried_into_both_dialects():
    assert "9999" in _text(port=9999)
    assert "9999" in _text(port=9999, windows=True)


def test_windows_setup_names_the_certificate_store_route():
    """REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS cover Python and Node, which
    is most agent traffic - but Invoke-WebRequest, .NET and curl.exe ignore
    them and read the Windows store. Saying only the first half would leave
    somebody debugging TLS errors with no clue."""
    out = _text(windows=True)
    assert "REQUESTS_CA_BUNDLE" in out
    assert "--trust-ca" in out
    assert "--untrust-ca" in out, "an install with no documented undo is not offered"


def test_both_dialects_point_at_the_pem_for_python_clients():
    for windows in (False, True):
        assert "mitmproxy-ca-cert.pem" in _text(windows=windows)


@pytest.mark.skipif(_os.name == "nt", reason="checks the non-Windows path")
def test_trust_ca_off_windows_explains_the_alternative(capsys):
    from demo_cli.cli import _trust_ca
    assert _trust_ca() == 1
    out = capsys.readouterr().out
    assert "Windows-only" in out
    assert "REQUESTS_CA_BUNDLE" in out, "point them at what DOES work here"


def test_cmd_egress_fails_cleanly_when_port_already_in_use(monkeypatch, capsys):
    from demo_cli.cli import cmd_egress
    import types
    monkeypatch.setattr("demo_cli.guarded.port_open", lambda p: True)
    args = types.SimpleNamespace(port=8080, enforce=False, trust_ca=False, untrust_ca=False)
    rc = cmd_egress(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "already in use" in out


def test_egress_non_interactive_stdin_falls_back_to_timeout_action(monkeypatch):
    import asyncio
    import types
    from demo_cli import egress
    monkeypatch.setattr("sys.stdin", None)
    addons = egress._build_addon()
    assert len(addons) == 1
    addon = addons[0]
    addon.timeout_action = "block"
    req = types.SimpleNamespace(method="POST", pretty_host="api.atlassian.com", path="/wiki/rest/api")
    v = egress.HttpVerdict(level="review", surface="test", operation="POST", reason="ambiguous write")

    res = asyncio.run(addon._ask(req, v))
    assert res is False

    addon.timeout_action = "allow"
    res2 = asyncio.run(addon._ask(req, v))
    assert res2 is True


# --------------------------------------------------------------------------
# Egress port precedence and validation
# --------------------------------------------------------------------------

def test_resolve_egress_port_precedence():
    from demo_cli.config import Config, resolve_egress_port

    # 1. Default when neither CLI nor config provides a port
    cfg = Config()
    port, err = resolve_egress_port(cfg, None)
    assert port == 8080 and err is None

    # 2. Config overrides default when CLI is None
    cfg_custom = Config(egress={"port": 8888})
    port, err = resolve_egress_port(cfg_custom, None)
    assert port == 8888 and err is None

    # 3. CLI flag overrides config
    port, err = resolve_egress_port(cfg_custom, 9090)
    assert port == 9090 and err is None


def test_resolve_egress_port_validation():
    from demo_cli.config import Config, resolve_egress_port

    # Invalid CLI ports
    for invalid in (0, -1, 65536, 100000):
        port, err = resolve_egress_port(Config(), invalid)
        assert port is None
        assert "between 1 and 65535" in err

    # Invalid config ports (out of range or non-integer)
    cfg_bad_range = Config(egress={"port": 70000})
    port, err = resolve_egress_port(cfg_bad_range, None)
    assert port is None
    assert "between 1 and 65535" in err

    cfg_bad_type = Config(egress={"port": "invalid_port"})
    port, err = resolve_egress_port(cfg_bad_type, None)
    assert port is None
    assert "integer" in err


def test_cmd_egress_fails_cleanly_on_invalid_port(capsys):
    from demo_cli.cli import cmd_egress
    import types

    args = types.SimpleNamespace(port=99999, enforce=False, trust_ca=False, untrust_ca=False)
    rc = cmd_egress(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "invalid port" in out.lower()
    assert "between 1 and 65535" in out


def test_cmd_guarded_fails_cleanly_on_invalid_port(capsys):
    from demo_cli.cli import cmd_guarded
    import types

    args = types.SimpleNamespace(argv=["claude"], root=None, port=0, no_egress=False, heartbeat=0)
    rc = cmd_guarded(args)
    assert rc == 1
    out = capsys.readouterr().out
    assert "invalid port" in out.lower()


def test_doctor_reports_fail_on_invalid_egress_port():
    from demo_cli.config import Config
    from demo_cli.doctor import _egress_checks

    cfg = Config(egress={"port": -10})
    rows = _egress_checks(cfg)
    assert len(rows) == 1
    status, label, detail = rows[0]
    assert status == "fail"
    assert label == "egress port"
    assert "between 1 and 65535" in detail

