"""verifier/sijill_trace.py (spec §4.5): who caused seq N, from the database alone."""

import json
import subprocess
import sys

import v2chain
from conftest import ROOT, tamper

TRACE = ROOT / "verifier" / "sijill_trace.py"

SEQ_9 = """\
SIJIL TRACE seq=9  node=dev-mbp-01  chain=PASS records=15
record    tool_call  2026-10-01T08:00:08.000Z  decision=block mode=enforce
          rule_hits=no-net-exec-from-untrusted
          rulepack=3e9dbbbb…bbbb (seq 1, sijil-starter 0.1.0)  policy=7c1faaaa…aaaa (APR-0203)

task      seq=4  started 2026-10-01T08:00:03.000Z  outcome=completed (task_end seq=14)
          intent_hash=6fa7c1a0fa8f0e31…  repo=github.com/acme/app  commit=3f1c9e2a
          harness=claude-code  session=9b1e2c7a…  lockfile=0b1c8888…
          delegated_from=-  agent_auth=key  principal_auth=none
agent     spiffe://acme.example/agent/ci-fixer
          registered seq=2 (2026-10-01T08:00:01.000Z) by email:03f5e1f3…  key=29acbae1…6dd7
          logical=did:web:acme.example:agents:ci-fixer responsible=did:web:acme.example lifecycle=persistent
          rotations=0  revoked=no (at seq 9)
principal email:03f5e1f3412d1c41…  (hashed; display name available only from the ledger's principal_index)

causal chain (parent_seq, oldest first)
  5   inference    allow  api:anthropic:claude-sonnet-4-5-20250929  tool_uses=[mcp__sentry__get_issue]
  6   tool_call    allow  mcp:sentry get_issue  correlation=tool_use_id
  7   tool_result  flag   source=mcp:sentry  bytes=36  rules=[result-from-telemetry]
  8   inference    allow  api:anthropic:claude-sonnet-4-5-20250929  tool_uses=[Bash,Bash]
> 9   tool_call    BLOCK  Bash  argv0=npx packages=[@acme-tools/fix-sentry-4821] env_refs=[SENTRY_AUTH_TOKEN]
                          context_labels=[mcp:sentry] context_seqs=[7]
children of 9: none
"""


def trace(db, pub, *args):
    r = subprocess.run([sys.executable, str(TRACE), "--db", str(db), "--pubkey", str(pub), *map(str, args)],
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def test_blocked_call_traces_back_through_its_context(tmp_path):
    code, out, _ = trace(*v2chain.demo().write(tmp_path), 9)
    assert (code, out) == (0, SEQ_9)


def test_children_are_listed_breadth_first(tmp_path):
    code, out, _ = trace(*v2chain.demo().write(tmp_path), 10)
    assert code == 0
    tail = out.split("children of 10:\n", 1)[1].splitlines()
    assert tail[0].startswith("    11  egress       allow  registry.npmjs.org:443  https  allowed_by=repo_pin")
    assert tail[1].startswith("    12  tool_result  allow  source=repo")


def test_json_carries_the_same_walk(tmp_path):
    code, out, _ = trace(*v2chain.demo().write(tmp_path), 9, "--json")
    res = json.loads(out)
    assert code == 0 and res["chain"] == "PASS records=15" and res["verified"] is True
    assert (res["task"], res["task_end"], res["registered"], res["rulepack_change"]) == (4, 14, 2, 1)
    assert res["causal_chain"] == [5, 6, 7, 8, 9] and res["children"] == []
    assert set(res["records"]) == {"1", "2", "4", "5", "6", "7", "8", "9", "14"}
    assert res["records"]["9"]["decision"] == "block"


def test_delegation_and_rotation(tmp_path):
    c = v2chain.demo()
    t2 = v2chain.task_start(c, delegated_from="4")
    c.add("task_end", agent_id=v2chain.AGENT, principal=v2chain.PRINCIPAL, task_seq=t2,
          ext={"outcome": "completed", "inference": 0, "tool_calls": 0, "blocked": 0, "confirmed": 0,
               "denied": 0, "flagged": 0, "egress": 0, "last_seq": int(t2)})
    code, out, _ = trace(*c.write(tmp_path), t2)
    assert code == 0, out
    assert "  delegated_from=4  agent_auth=key" in out
    assert "rotations=1  revoked=no (at seq 16)" in out


def test_refuses_a_failing_chain_unless_no_verify(tmp_path):
    db, pub = v2chain.demo().write(tmp_path)
    tamper(db, "forge", "7")
    code, out, err = trace(db, pub, 9)
    assert (code, out) == (1, "") and "FAIL seq=7 signature invalid" in err
    code, out, _ = trace(db, pub, 9, "--no-verify")
    assert code == 0
    assert all(line.startswith("UNVERIFIED ") for line in out.splitlines())
    assert "UNVERIFIED SIJIL TRACE seq=9  node=dev-mbp-01  chain=UNVERIFIED" in out


def test_exit_codes_for_missing_seq_and_io(tmp_path):
    db, pub = v2chain.demo().write(tmp_path)
    assert trace(db, pub, 99)[0] == 2
    assert trace(tmp_path / "nope.db", pub, 1)[0] == 3
    assert trace(db, tmp_path / "nope.pub", 1)[0] == 3


def test_trace_imports_nothing_from_sijill():
    import ast
    tree = ast.parse(TRACE.read_text())
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in names if m == "sijill" or m.startswith("sijill.")]
