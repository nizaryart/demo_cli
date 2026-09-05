#!/usr/bin/env python3
"""Render callgraph.json into one self-contained, clickable HTML page.

The graph data is extracted by tools/callgraph.py from the real source; this
script only lays it out. Re-run both after changing code and the page stays true.

Usage: python3 tools/callgraph.py src/demo_cli > cg.json
       python3 tools/build_callgraph_page.py cg.json "Linux" > page.html
"""
import json, sys

data = json.load(open(sys.argv[1]))
variant = sys.argv[2] if len(sys.argv) > 2 else "Linux"

# The order Guard.evaluate actually runs these in (read from guard.py). The
# EDGES all come from the extractor; only the left-to-right ORDER is curated,
# because source order is not something an AST walk preserves meaningfully.
SPINE = [
    ("classify.classify_pipeline",   "1. classify",  "what kind of action is this?"),
    ("recovery.extract_path_operand","2. find target","which file will die?"),
    ("context.build_context",        "3. context",   "where are we? which env?"),
    ("recovery.snapshot",            "4. SNAPSHOT",  "copy it - before deciding"),
    ("decide.decide",                "5. decide",    "allow / reversible / escalate"),
    ("receipts.append_receipt",      "6. receipt",   "hash-chained record"),
]

payload = {"funcs": data["funcs"], "entries": data["entries"], "spine": SPINE,
           "total": data["total_in_package"], "reachable": data["reachable"],
           "definitions": data.get("definitions"), "redefined": data.get("redefined", {}),
           "variant": variant}

TEMPLATE = open(sys.argv[3] if len(sys.argv) > 3 else "tools/callgraph_template.html").read()

# Embedding JSON inside <script> has one classic hazard: if any string in the
# data contains "</script>", the HTML parser ends the script block there and the
# page dies mid-JSON. Escaping "</" as "<\/" is identical to JavaScript and
# invisible to the HTML parser. (Real case: hooks/codex.py's docstring mentions
# `bash -lc "<script>"`.)
blob = json.dumps(payload).replace("</", "<\\/")

sys.stdout.write(TEMPLATE.replace("__DATA__", blob).replace("__VARIANT__", variant))
