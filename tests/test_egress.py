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
