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


def test_guard_never_imports_sijill():
    """The guard is Apache-2.0 and talks to the ledger over HTTP only (spec §10)."""
    for path in (ROOT / "guard").glob("*.py"):
        tree = ast.parse(path.read_text())
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        assert not [m for m in names if m == "sijill" or m.startswith("sijill.")], path.name


def test_guard_sources_carry_no_invisible_unicode():
    """The guard's own code, rule packs and tests pass the scan they apply to others (spec §7.3)."""
    from guard import unicode
    files = [*(ROOT / "guard").glob("*.py"), *(ROOT / "rulepacks").glob("*.yaml"), *(ROOT / "tests").glob("*guard*.py"),
             *(ROOT / "tests").glob("mcp_*.py")]
    for path in files:
        assert unicode.scan(path.read_text())["count"] == 0, path.name
