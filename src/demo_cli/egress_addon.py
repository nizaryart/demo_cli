"""Thin mitmproxy entry point: `mitmdump -s egress_addon.py`.

mitmproxy loads a `-s` script as a standalone module, which breaks a package
module that uses relative imports and `from __future__ import annotations`
dataclasses (its `__module__` is not registered under its real name). So this
tiny loader imports the real addon as the proper package module
`demo_cli.egress` (registered correctly in sys.modules) and re-exports its
`addons`. `demo_cli` must be importable in mitmdump's Python — `demo_cli egress`
sets PYTHONPATH accordingly when it launches mitmdump.
"""
from demo_cli.egress import addons  # noqa: F401
