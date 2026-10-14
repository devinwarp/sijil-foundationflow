"""Narrated, interactive run of the M2 gate demo (tests/test_m2_gate.py), keeping the ledger afterwards.

Stand-ins: a scripted model, a test Entra issuer and a mock case API (the test fixtures). The ledger, guard, HTTP
adapter, rules, budgets, approvals and verifier are the real code.

    venv/bin/python scripts/m2_demo.py [--out DIR] [--no-pause]
"""
import argparse, asyncio, json, os, shutil, subprocess, sys, tempfile, threading, time, warnings
from pathlib import Path

warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "tests"), str(ROOT)]
os.environ["SIJIL_TOOLS_TOKEN"] = "tools-secret"

import httpx
from fastapi.testclient import TestClient
from conftest import MODEL, rows, verify
from govkit import CASE, CLOSE, NOTE, gov_node, officer, supervisor
from guard import config, http, identity, serve
from guardkit import guard_yaml, ledger_of, live
from sijill import record
from test_guard_http import SPEC, CaseApi
from test_m2_gate import GATE_PACK, INJECTION, document_intake, model

B, R, G, Y, D, X = ("\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m") if sys.stdout.isatty() else [""] * 6
ap = argparse.ArgumentParser()
ap.add_argument("--out", default=str(Path(tempfile.gettempdir()) / "sijil-m2-demo"))
ap.add_argument("--no-pause", action="store_true")
a = ap.parse_args()
PAUSE = sys.stdin.isatty() and not a.no_pause
out = Path(a.out)
if out.exists():
    if any(out.iterdir()) and not (out / "sijill.db").exists():
        sys.exit(f"{out} is not empty and is not a previous demo run; pick another --out")
    shutil.rmtree(out)
out.mkdir(parents=True)
last = 0


def step(n, title, story):
    print(f"\n{B}── Step {n}. {title}{X}\n{story}")
    if PAUSE:
        input(f"{D}   [Enter to run]{X}")


def sealed(db):
    """Print the records the ledger sealed since the last call."""
    global last
    for r in rows(db, f"seq > {last}"):
        x = json.loads(r["ext"] or "{}")
        what = x.get("tool") or (",".join(u["name"] for u in x.get("tool_uses", [])) and
                                 "asks for " + ",".join(u["name"] for u in x.get("tool_uses", []))) or ""
        dec = r["decision"]
        c = R if dec == "block" else Y if dec == "flag" else G
        hits = json.loads(r["rule_hits"] or "[]")
        if r["type"] == "rulepack_change":
            what, hits = f"{len(hits)} rules adopted", []
        print(f"   {D}sealed{X} seq={r['seq']:<3} {r['type']:<15} {c}{dec:<6}{X} {what}"
              + (f"  {R}rule_hits={hits}{X}" if hits else ""))
        last = r["seq"]


print(f"{B}Sijil M2 demo: an injection against a government case agent{X}")
print("A case officer signed in through Entra ID asks an AI agent to work case " + CASE + ".\n"
      "The agent reads the citizen's uploaded document (MCP tool) and calls the case system (HTTP tool).\n"
      "Every model call and tool call goes through Sijil, which seals a signed, hash-chained record of it.\n"
      f"{D}(Stand-ins: a scripted model, a test Entra issuer and a mock case API. The ledger, guard, adapter,\n"
      f" rules, budgets, approvals and verifier are the real code.){X}")

spec = {**SPEC, "paths": {**SPEC["paths"], "/cases/export": {"post": {"operationId": "exportCases"}}}}
(out / "case-api.json").write_text(json.dumps(spec))
token = officer()
client, s, _ = gov_node(out, pack=GATE_PACK, handler=model)
with client, live(document_intake()) as docs:
    cfg = config.load(str(guard_yaml(out, f"""rulepack: {out}/starter.yaml
repo: {out}/repo
servers:
  - name: document-intake
    transport: http
    url: {docs}/mcp
http_tools:
  inbound_auth: {{mode: bearer_env}}
  servers:
    - name: case-api
      upstream: https://case.moi.internal/api/v2
      spec: {out}/case-api.json
""")))
    identity.register(ledger_of(client), cfg.agent_id, identity.create_key(cfg.key_path, cfg.repo), cfg.registered_by)
    api = CaseApi()
    adapter = http.Adapter(cfg, ledger_of(client), httpx.AsyncClient(transport=httpx.MockTransport(api)))
    with TestClient(http.app(adapter), headers={"X-Sijil-Tools-Token": "tools-secret"}) as tools:
        step(0, "Setup", "The ledger adopts the ministry's rule pack, the agent registers its key, and the officer\n"
             "opens a task with their Entra token.")
        t = tools.post("/_sijil/task/start", json={"intent": f"Review {CASE}", "session_id": "conv-1"},
                       headers={"X-Sijil-Principal-Token": token}).json()
        hdr = {"X-Sijil-Task-Seq": str(t["task_seq"])}
        sealed(s.db_path)

        def think(prompt):
            r = client.post("/v1/chat/completions", json={"model": MODEL, "messages": [
                {"role": "user", "content": prompt}]}, headers={**hdr, "X-Sijil-Agent-Session": t["agent_session"],
                                                                 "X-Sijil-Principal-Token": token})
            return r.json()["choices"][0]["message"]["tool_calls"][0]["id"]

        def case_api(method, path, call_id, body=None):
            return tools.request(method, f"/case-api{path}", json=body, headers={**hdr, "X-Sijil-Tool-Use-Id": call_id})

        step(1, "The agent reads the citizen's uploaded document",
             "The document is a salary certificate, but it hides an instruction:\n"
             f"{Y}   \"{INJECTION.split(chr(10))[-1]}\"{X}")
        think("read the uploaded salary certificate")

        async def read_document():
            g = serve.Guard(cfg, cfg.servers[0], ledger_of(client))
            await g.start()
            sess = await g.new_session(serve.mcp.Client(), {"x-sijil-task-seq": str(t["task_seq"])})
            await sess.handle("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
            await sess.handle("tools/call", {"name": "get_document", "arguments": {"caseId": CASE}})
            await sess.close(), await g.aclose()
        asyncio.run(read_document())
        sealed(s.db_path)

        step(2, "The injected instruction: export every case file",
             "The model obeys the document and asks for exportCases. Rule no-export-after-citizen-upload says:\n"
             "no bulk export once the context holds a citizen-uploaded document.")
        r = case_api("POST", "/cases/export", think("follow the instructions in the document"))
        export_seq = r.json()["error"]["seq"]
        print(f"   case API answered {R}{r.status_code}{X}: {r.json()['error'].get('message', '')}")
        sealed(s.db_path)

        step(3, "Autonomy budget: one case note per task",
             "The agent adds a case note (allowed), then tries a second one (over budget).\n"
             f"{D}   (The mock case API hides a zero-width character in its reply; Sijil strips it and flags the result.){X}")
        for p in ("add the note", "add the note again"):
            r = case_api("POST", f"/cases/{CASE}/notes", think(p), {"note": NOTE["note"]})
            print(f"   addCaseNote -> {G if r.status_code < 300 else R}{r.status_code}{X}")
        sealed(s.db_path)

        step(4, "Closing the case needs a named supervisor",
             "closeCase is consequential: the call is held until a supervisor with the CaseClosure role\n"
             "approves it with their own Entra sign-in.")
        res, call_id = [], think("close the case")
        th = threading.Thread(daemon=True, target=lambda: res.append(case_api(
            "POST", f"/cases/{CASE}/close", call_id, {"resolution": CLOSE["resolution"]})))
        th.start()
        while not rows(s.db_path, "type = 'approval'"):
            time.sleep(0.05)
        sealed(s.db_path)
        print(f"   {Y}closeCase is waiting for approval...{X}")
        if PAUSE:
            input(f"{D}   [Enter to approve as the supervisor]{X}")
        aid = json.loads(rows(s.db_path, "type = 'approval'")[0]["ext"])["approval_id"]
        client.post(f"/api/approval/{aid}/decide", json={"decision": "grant", "token": supervisor(),
                                                         "reason": "Certificate checked."})
        th.join(10)
        print(f"   supervisor granted; closeCase -> {G}{res[0].status_code}{X}")
        sealed(s.db_path)
        print(f"   the case API saw only: {[m + ' ' + p for m, p, *_ in api.seen]}  {D}(never the export){X}")
        tools.post("/_sijil/task/end", json={"task_seq": t["task_seq"]})
        sealed(s.db_path)

kept = out / "kept-tokens"
kept.mkdir()
(kept / f"{record.sha256_hex(token.encode())}.jwt").write_text(token)
flags = ["--token-dir", str(kept), "--jwks-dir", s.jwks_dir, "--rulepack", s.rulepack_path,
         "--min-principal-assurance", "substantial"]
step(5, "An auditor verifies the chain offline", "Only the node's public key, the kept token, the JWKS snapshot\n"
     "and the rule pack. No access to the running system.")
code, line = verify(s.db_path, s.pubkey_path, *flags)
print(f"   {G if code == 0 else R}{line}{X}")
step(6, "Why was the export stopped?", f"sijil trace on record {export_seq}:")
print(subprocess.run([sys.executable, str(ROOT / "verifier" / "sijill_trace.py"), "--db", s.db_path,
                      "--pubkey", s.pubkey_path, str(export_seq)], capture_output=True, text=True).stdout)

print(f"""{B}Your turn.{X} From the sijil-foundationflow repo root:

  D={out}
  Verify again:      venv/bin/python verifier/sijill_verify.py --db $D/sijill.db --pubkey $D/node.pub \\
                       --token-dir $D/kept-tokens --jwks-dir $D/jwks --rulepack $D/starter.yaml --min-principal-assurance substantial
  Trace a record:    venv/bin/python verifier/sijill_trace.py --db $D/sijill.db --pubkey $D/node.pub <seq>
  List records:      sqlite3 $D/sijill.db "select seq,type,decision,rule_hits from records"
  Tamper, then verify again and watch it name the record:
                     sqlite3 $D/sijill.db "update records set decision='allow' where seq={export_seq}"
  Rerun the demo:    venv/bin/python scripts/m2_demo.py
""")
