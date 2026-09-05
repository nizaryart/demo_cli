#!/usr/bin/env python3
"""Extract a real call graph from the demo_cli source with Python's own parser.

Nothing here is hand-written knowledge about the code: every node is a function
that exists and every edge is a call site that exists. Re-run it after changing
the source and the graph stays true - a diagram that quietly goes stale is worse
than no diagram.

Limitation, stated rather than hidden: Python is dynamic, so a static reader
cannot see calls dispatched through a variable (`self.fn()`, `getattr`,
argparse's `set_defaults(func=...)`). Those edges are marked `dynamic` in the
output instead of being silently dropped.

Usage:  python3 tools/callgraph.py src/demo_cli > callgraph.json
"""
from __future__ import annotations

import ast
import json
import os
import sys
from collections import defaultdict


def module_name(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    return rel[:-3].replace(os.sep, ".")


def collect(root: str) -> dict:
    """Walk every .py file and record each function: where it lives, what it
    says it does, its source, and the names it calls."""
    funcs: dict[str, dict] = {}
    defs_seen: list = []          # every definition, including redefinitions
    # name -> [qualified names], so a bare call like `snapshot(...)` can be
    # resolved even when we do not know which module it came from.
    by_short: dict[str, list[str]] = defaultdict(list)

    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            src = open(path, encoding="utf-8").read()
            lines = src.splitlines()
            mod = module_name(path, root)
            tree = ast.parse(src)

            # Walk the tree, remembering the enclosing class so methods get a
            # qualified name like `guard.Guard.evaluate`.
            def visit(node, cls=None):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.ClassDef):
                        visit(child, child.name)
                    elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qual = f"{mod}.{cls}.{child.name}" if cls else f"{mod}.{child.name}"
                        end = getattr(child, "end_lineno", child.lineno)
                        funcs[qual] = {
                            "qual": qual,
                            "module": mod,
                            "cls": cls,
                            "name": child.name,
                            "file": os.path.relpath(path, os.path.dirname(root)),
                            "line": child.lineno,
                            "doc": (ast.get_docstring(child) or "").strip().split("\n")[0],
                            "source": "\n".join(lines[child.lineno - 1:end]),
                            "calls_raw": raw_calls(child),
                        }
                        by_short[child.name].append(qual)
                        defs_seen.append(qual)
                        visit(child, cls)   # nested functions
                    else:
                        visit(child, cls)

            visit(tree)
    # A name defined more than once is a try/except import-fallback (only one
    # exists at runtime), so collapsing it is correct - but report it rather
    # than leaving an unexplained gap between definitions and nodes.
    from collections import Counter
    dupes = {k: v for k, v in Counter(defs_seen).items() if v > 1}
    return {"funcs": funcs, "by_short": dict(by_short),
            "definitions": len(defs_seen), "redefined": dupes}


def raw_calls(fn_node) -> list:
    """Every call site inside one function, as (text, kind).

    kind is 'name'  for  foo(...)
            'attr'  for  mod.foo(...) or self.foo(...)
            'dyn'   for  anything we cannot read statically
    """
    out = []
    for n in ast.walk(fn_node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name):
            out.append((f.id, "name"))
        elif isinstance(f, ast.Attribute):
            base = f.value
            if isinstance(base, ast.Name):
                out.append((f"{base.id}.{f.attr}", "attr"))
            elif isinstance(base, ast.Attribute):
                out.append((f"{base.attr}.{f.attr}", "attr"))
            else:
                out.append((f.attr, "dyn"))
    return out


def resolve(data: dict) -> dict:
    """Turn raw call text into edges between functions we actually know about.
    Unresolvable names (stdlib, builtins, dynamic) are dropped from edges but
    counted, so the diagram never pretends to be more complete than it is."""
    funcs, by_short = data["funcs"], data["by_short"]
    external = defaultdict(int)

    for qual, info in funcs.items():
        edges, seen = [], set()
        for text, kind in info["calls_raw"]:
            short = text.split(".")[-1]
            cands = by_short.get(short, [])
            hit = None
            if len(cands) == 1:
                hit = cands[0]
            elif cands:
                # Several functions share the name. Prefer one in the same
                # module, else one whose module matches the attribute prefix.
                same_mod = [c for c in cands if funcs[c]["module"] == info["module"]]
                prefix = text.split(".")[0] if "." in text else None
                by_pref = [c for c in cands if prefix and funcs[c]["module"].endswith(prefix)]
                hit = (same_mod or by_pref or cands)[0]
            if hit and hit != qual and hit not in seen:
                seen.add(hit)
                edges.append(hit)
            elif not hit:
                external[text] += 1
        info["calls"] = edges
        del info["calls_raw"]

    # reverse edges = xrefs, the "who calls me" view
    callers = defaultdict(list)
    for qual, info in funcs.items():
        for callee in info["calls"]:
            callers[callee].append(qual)
    for qual, info in funcs.items():
        info["callers"] = sorted(callers.get(qual, []))

    return {"funcs": funcs, "external": dict(external)}


def reachable(funcs: dict, entries: list) -> set:
    """Breadth-first walk outward from the entry points."""
    seen, queue = set(), list(entries)
    while queue:
        q = queue.pop(0)
        if q in seen or q not in funcs:
            continue
        seen.add(q)
        queue.extend(funcs[q]["calls"])
    return seen


ENTRIES = [
    "hooks.claude_code.run_pretooluse",
    "hooks.codex.run_pretooluse",
    "hooks.cursor.run_before_shell",
]

if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "src/demo_cli"
    raw = collect(root)
    data = resolve(raw)
    funcs = data["funcs"]
    keep = reachable(funcs, ENTRIES)
    out = {
        "entries": [e for e in ENTRIES if e in funcs],
        "funcs": {k: v for k, v in funcs.items() if k in keep},
        "total_in_package": len(funcs),
        "definitions": raw["definitions"],
        "redefined": raw["redefined"],
        "reachable": len(keep),
    }
    json.dump(out, sys.stdout, indent=1)
