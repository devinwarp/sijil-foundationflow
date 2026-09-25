"""Product claims enforced as tests."""

import ast
import re

from conftest import ROOT


def test_verifier_does_not_import_sijill():
    tree = ast.parse((ROOT / "verifier" / "sijill_verify.py").read_text())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in names if m == "sijill" or m.startswith("sijill.")]


def test_application_never_updates_or_deletes():
    pattern = re.compile(r"\b(UPDATE|DELETE|DROP|REPLACE|TRUNCATE|ALTER)\b", re.IGNORECASE)
    for path in (ROOT / "sijill").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "records" in node.value:
                assert not pattern.search(node.value), f"{path.name}: {node.value!r}"
