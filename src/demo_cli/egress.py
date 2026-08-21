"""Egress guard: gate destructive EXTERNAL / SaaS API calls at the network wire.

The three other guards protect LOCAL blast radius (files on this machine) by
snapshot-then-recover. An external SaaS write (a Confluence page overwrite, a
Shopify theme push, a Stripe refund) executes on a server we do not control, so
a local snapshot can never make it reversible. This layer is the "behavior over
string" analog at the NETWORK boundary: it watches what actually goes out on the
wire (HTTP method + host + path + body), which an obfuscated command cannot hide.
It is PREVENTION, not recovery - the honest frontier for external destruction.

Design (see architectures.md):
  * method-first, host-refined, path-optional - anchor on the STABLE parts of
    HTTP (method semantics never change; hostnames last years); treat PATH as a
    low-trust hint that degrades gracefully. Avoids the brittle "enumerate every
    endpoint" trap.
  * one classifier, N per-protocol operation extractors:
      REST     -> operation = HTTP method
      GraphQL  -> operation = query/mutation keyword (body grammar)
      JSON-RPC -> operation = "method" field (JSON body)
      XML-RPC  -> operation = <methodName> (XML body)
      SOAP     -> operation = SOAPAction header
  * three levels: safe / review / destructive. REVIEW absorbs everything
    uncertain (ambiguous writes, opaque/persisted payloads).

`classify_http` and the extractors are pure and dependency-free (mitmproxy is
imported lazily only for the addon), so they are unit-tested in isolation.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

READ_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# The shared destructive-verb set (used by the RPC protocols; REST uses its
# method directly). A write whose operation name carries one of these is treated
# as destroying data.
DESTRUCTIVE_VERBS = {
    "delete", "remove", "destroy", "purge", "drop", "truncate", "wipe",
    "reset", "clear", "erase", "unpublish", "revoke", "cancel", "terminate",
}
# Read verbs: a write op named with one of these is really a read (get/list/...).
READ_VERBS = {
    "get", "list", "read", "fetch", "find", "search", "query", "describe",
    "count", "exists", "view", "show", "lookup", "retrieve",
}

# Known SaaS hosts we scrutinise (substring match on the host). Everything else
# falls back to method posture. Extend via config `[egress] saas_hosts`.
_SAAS_HOSTS = [
    "atlassian.net", "atlassian.com",           # Confluence / Jira
    "myshopify.com", "shopify.com",             # Shopify
    "stripe.com",                                # Stripe
    "slack.com",                                 # Slack
    "notion.so", "notion.com",                   # Notion
    "api.github.com",                            # GitHub
    "contentful.com",                            # Contentful
    "netlify.com", "vercel.com",                 # deploy platforms
    "wordpress.com",                             # WordPress.com
    "googleapis.com",                            # Google APIs
]

# Optional high-confidence PATH hints: (host_substr, method, path_substr, surface).
# A booster only - if a path changes we fall back to host+method, never break.
_PATH_HINTS = [
    ("atlassian", "PUT", "/wiki", "confluence_content"),
    ("atlassian", "DELETE", "/wiki", "confluence_content"),
    ("myshopify", "PUT", "/themes", "shopify_theme"),
    ("myshopify", "DELETE", "/themes", "shopify_theme"),
    ("shopify", "PUT", "/themes", "shopify_theme"),
    ("stripe", "POST", "/v1/refunds", "payment_refund"),
    ("slack", "POST", "/api/chat.delete", "slack_delete"),
    ("github", "DELETE", "/repos", "github_repo"),
]


@dataclass
class HttpVerdict:
    level: str                       # "safe" | "review" | "destructive"
    surface: Optional[str]           # short label of what/why (or None)
    operation: str                   # the extracted operation (for the receipt)
    reason: str                      # human-readable one-liner


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _as_text(body) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8", "replace")
        except Exception:
            return ""
    return str(body)


def _header(headers: Optional[Dict[str, str]], name: str) -> Optional[str]:
    """Case-insensitive header lookup."""
    if not headers:
        return None
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return None


def _try_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _tokens(op: str) -> List[str]:
    """Split an operation name into lowercased word tokens, handling camelCase,
    dots, underscores and dashes: `wp.deletePost` -> [wp, delete, post]."""
    out: List[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", op or ""):
        out += re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", part)
    return [t.lower() for t in out if t]


def _is_known_host(host: str, hosts: List[str]) -> bool:
    return any(h in host for h in hosts)


def _path_hint(host: str, method: str, path: str) -> Optional[str]:
    for host_sub, m, path_sub, surface in _PATH_HINTS:
        if host_sub in host and method == m and path_sub in path:
            return surface
    return None


# --------------------------------------------------------------------------
# Per-protocol operation extraction  (the only protocol-specific part)
# --------------------------------------------------------------------------

def detect_protocol(headers: Optional[Dict[str, str]], path: str, body: str) -> str:
    """Cheap protocol detection - headers/path/shape first, no full parse unless
    the body is small JSON/XML we already hold."""
    if _header(headers, "soapaction") is not None:
        return "soap"
    ct = (_header(headers, "content-type") or "").lower()
    low = body.lower()
    if ("xml" in ct or low.lstrip().startswith("<?xml")) and "<methodcall" in low:
        return "xmlrpc"
    if "/graphql" in (path or "").lower():
        return "graphql"
    j = _try_json(body) if body else None
    if isinstance(j, dict):
        if "jsonrpc" in j:
            return "jsonrpc"
        if "query" in j:
            return "graphql"
    if isinstance(j, list) and j and isinstance(j[0], dict):
        if any(isinstance(x, dict) and "jsonrpc" in x for x in j):
            return "jsonrpc"
        if any(isinstance(x, dict) and "query" in x for x in j):
            return "graphql"
    return "rest"


def _verb_intent(name: str) -> str:
    """read | destructive | write, from an operation name's tokens."""
    toks = set(_tokens(name))
    if toks & DESTRUCTIVE_VERBS:
        return "destructive"
    if toks & READ_VERBS:
        return "read"
    return "write"


def _rpc_intent(names: List[str]) -> Tuple[str, str]:
    """Overall (intent, op_name) for a batch of RPC operation names. Worst wins:
    destructive > write > read. Empty -> opaque."""
    names = [n for n in names if n]
    if not names:
        return "opaque", ""
    intents = [(_verb_intent(n), n) for n in names]
    for want in ("destructive", "write", "read"):
        for intent, n in intents:
            if intent == want:
                return intent, n
    return "write", names[0]


def _op_graphql(body: str) -> Tuple[str, str]:
    """Return (intent, op_name). intent in read|destructive|write|opaque, using
    GraphQL's own grammar (query vs mutation) - stable, not per-API."""
    j = _try_json(body)
    docs = j if isinstance(j, list) else [j]
    saw_mutation = saw_query = opaque = False
    op_field = ""
    for d in docs:
        if not isinstance(d, dict):
            opaque = True
            continue
        # persisted / hashed query with no text -> opaque
        ext = d.get("extensions") or {}
        if isinstance(ext, dict) and "persistedQuery" in ext and not d.get("query"):
            opaque = True
            continue
        q = d.get("query")
        if not isinstance(q, str):
            opaque = True
            continue
        if re.search(r"\bmutation\b", q):
            saw_mutation = True
            fm = re.search(r"mutation\b[^{]*\{\s*([A-Za-z_][A-Za-z0-9_]*)", q)
            if fm:
                op_field = fm.group(1)
        else:
            saw_query = True                       # incl. anonymous `{ ... }`
    if saw_mutation:
        intent = _verb_intent(op_field) if op_field else "write"
        if intent == "read":                       # a mutation is never a read
            intent = "write"
        return intent, (op_field or "mutation")
    if saw_query:
        return "read", "query"
    return "opaque", ""


def _op_jsonrpc(body: str) -> Tuple[str, str]:
    j = _try_json(body)
    names: List[str] = []
    if isinstance(j, dict):
        m = j.get("method")
        if isinstance(m, str):
            names.append(m)
    elif isinstance(j, list):
        for x in j:
            if isinstance(x, dict) and isinstance(x.get("method"), str):
                names.append(x["method"])
    return _rpc_intent(names)


def _op_xmlrpc(body: str) -> Tuple[str, str]:
    names = re.findall(r"<methodName>\s*([^<\s]+)\s*</methodName>", body or "", re.I)
    return _rpc_intent(names)


def _op_soap(headers: Optional[Dict[str, str]]) -> Tuple[str, str]:
    action = (_header(headers, "soapaction") or "").strip().strip('"').strip("'")
    if not action:
        return "opaque", ""
    tail = re.split(r"[/#]", action)[-1]           # SOAPAction is often a URL/URN
    return _rpc_intent([tail or action])


# --------------------------------------------------------------------------
# The classifier
# --------------------------------------------------------------------------

def classify_http(method: str, host: str, path: str = "",
                  headers: Optional[Dict[str, str]] = None, body=None,
                  saas_hosts: Optional[List[str]] = None,
                  strict_unknown_hosts: bool = False) -> HttpVerdict:
    """Decide safe / review / destructive for one outbound request. Pure."""
    method = (method or "").upper()
    host = (host or "").lower()
    path = path or ""
    body = _as_text(body)
    hosts = saas_hosts if saas_hosts is not None else _SAAS_HOSTS
    known = _is_known_host(host, hosts)

    # 1. read methods are safe by HTTP spec (RPCs are always POST, never here).
    if method in READ_METHODS:
        return HttpVerdict("safe", None, method, "read method")

    proto = detect_protocol(headers, path, body)
    hint = _path_hint(host, method, path)

    # 2. figure out the operation's intrinsic intent (protocol-specific).
    if proto == "rest":
        if hint:
            intent, op = "destructive", method          # known destructive endpoint
        elif method in ("DELETE", "PUT"):
            intent, op = "destructive", method
        elif method in ("POST", "PATCH"):
            intent, op = "write", method
        else:
            intent, op = "write", method
    elif proto == "graphql":
        intent, op = _op_graphql(body)
    elif proto == "jsonrpc":
        intent, op = _op_jsonrpc(body)
    elif proto == "xmlrpc":
        intent, op = _op_xmlrpc(body)
    elif proto == "soap":
        intent, op = _op_soap(headers)
    else:
        intent, op = "write", method

    label = op or method

    # 3. map intent -> final level, refined by host + strict policy.
    if intent == "read":
        return HttpVerdict("safe", None, label, f"{proto} read operation")
    if intent == "opaque":
        return HttpVerdict("review", hint or f"{proto}_opaque", label,
                           f"{proto} payload opaque; cannot confirm intent")
    if intent == "destructive":
        if hint or known or strict_unknown_hosts:
            surface = hint or f"{proto}_destructive"
            where = "known SaaS host" if known else ("strict policy" if strict_unknown_hosts else "known endpoint")
            return HttpVerdict("destructive", surface, label,
                               f"{proto} destructive op ({where})")
        # destructive verb but unknown host, not strict -> surface, don't block.
        return HttpVerdict("review", f"{proto}_destructive_unknown", label,
                           f"{proto} destructive op on an unknown host")
    # intent == "write" (ambiguous): known host -> review; unknown -> safe (noise).
    if known:
        return HttpVerdict("review", f"{proto}_write", label,
                           f"{proto} write to a known SaaS host")
    return HttpVerdict("safe", None, label, f"{proto} write to an unknown host")


# --------------------------------------------------------------------------
# mitmproxy addon  (loaded by `mitmdump -s egress.py`; import guarded so the
# pure functions above can be imported/tested without mitmproxy installed)
# --------------------------------------------------------------------------

def _build_addon():
    import asyncio
    import os
    import sys
    from mitmproxy import http

    from .config import load_config
    from .context import redact
    from .receipts import Receipt, append_receipt

    class DemoCliEgress:
        def __init__(self):
            self.cfg = load_config()
            self.mode = os.environ.get("DEMO_CLI_EGRESS_MODE") or self.cfg.mode
            eg = getattr(self.cfg, "egress", {}) or {}
            self.strict = bool(eg.get("strict_unknown_hosts", False))
            self.timeout = int(eg.get("review_timeout_seconds", 30))
            self.timeout_action = str(eg.get("review_timeout_action", "block")).lower()
            self.saas_hosts = eg.get("saas_hosts") or None
            self._lock = asyncio.Lock()

        def running(self):
            # mitmproxy calls this when the proxy actually starts - keep the
            # banner out of __init__ so merely importing the module (tests,
            # `demo_cli` CLI) is silent.
            sys.stderr.write(f"demo_cli egress guard active (mode={self.mode}, "
                             f"strict_unknown_hosts={self.strict})\n")

        def _receipt(self, req, v: HttpVerdict, decision: str, reason: str):
            try:
                append_receipt(self.cfg.receipts_path, Receipt(
                    action_raw=redact(f"{req.method} {req.pretty_host}{req.path}"),
                    action_type="http",
                    target_environment="external",
                    decision=decision,
                    reason=reason,
                    mode=self.mode,
                    matched_rule=v.surface,
                    classification=("destructive" if v.level == "destructive"
                                    else "mutating" if v.level == "review" else "safe"),
                    recovery_point=None,          # external = not locally recoverable
                    agent_id="egress",
                    session_id="egress",
                ))
            except Exception as exc:
                sys.stderr.write(f"demo_cli egress: receipt error ({exc})\n")

        async def _ask(self, req, v: HttpVerdict) -> bool:
            loop = asyncio.get_event_loop()
            prompt = (f"\ndemo_cli egress ⚠ REVIEW  {req.method} {req.pretty_host}{req.path}\n"
                      f"   operation={v.operation}  surface={v.surface}  ({v.reason})\n"
                      f"   allow this request? [y/N]  "
                      f"(auto-{self.timeout_action} in {self.timeout}s): ")
            async with self._lock:                # serialise prompts across flows
                sys.stderr.write(prompt)
                sys.stderr.flush()
                try:
                    line = await asyncio.wait_for(
                        loop.run_in_executor(None, sys.stdin.readline), self.timeout)
                except asyncio.TimeoutError:
                    sys.stderr.write(f"\ndemo_cli egress: no answer -> {self.timeout_action}\n")
                    return self.timeout_action == "allow"
                return line.strip().lower() in ("y", "yes")

        async def request(self, flow):
            req = flow.request
            body = ""
            try:
                if req.content:
                    body = req.get_text(strict=False) or ""
            except Exception:
                body = ""
            v = classify_http(req.method, req.pretty_host, req.path,
                              dict(req.headers), body,
                              saas_hosts=self.saas_hosts,
                              strict_unknown_hosts=self.strict)

            # shadow: observe only.
            if self.mode != "enforce":
                if v.level != "safe":
                    sys.stderr.write(f"demo_cli egress [shadow] {v.level.upper()}: "
                                     f"{req.method} {req.pretty_host}{req.path} ({v.reason})\n")
                self._receipt(req, v, "ALLOW", f"[shadow] {v.reason}")
                return

            # enforce.
            if v.level == "safe":
                self._receipt(req, v, "ALLOW", v.reason)
                return
            if v.level == "destructive":
                flow.response = http.Response.make(
                    403, b"blocked by demo_cli egress guard\n",
                    {"Content-Type": "text/plain"})
                sys.stderr.write(f"demo_cli egress ⛔ BLOCKED {req.method} "
                                 f"{req.pretty_host}{req.path} ({v.reason})\n")
                self._receipt(req, v, "ESCALATE", f"blocked: {v.reason}")
                return
            # review -> sync hold-and-ask.
            approved = await self._ask(req, v)
            if approved:
                sys.stderr.write("demo_cli egress ✅ approved\n")
                self._receipt(req, v, "ALLOW", f"review approved: {v.reason}")
            else:
                flow.response = http.Response.make(
                    403, b"denied at demo_cli egress review\n",
                    {"Content-Type": "text/plain"})
                sys.stderr.write("demo_cli egress ⛔ denied at review\n")
                self._receipt(req, v, "ESCALATE", f"review denied: {v.reason}")

    return [DemoCliEgress()]


try:                                               # only when loaded by mitmdump
    import mitmproxy  # noqa: F401
    addons = _build_addon()
except Exception:                                  # imported for the pure core / tests
    addons = []
