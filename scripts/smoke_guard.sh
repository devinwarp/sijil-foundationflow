#!/usr/bin/env bash
# Smoke test for the sijil-guard image against a ledger container. Run from repo root:
#   scripts/smoke_guard.sh [guard-image] [ledger-image]
# The adapter runs as a sidecar: it shares the agent container's network namespace (--network container:),
# as it shares the agent's pod on Kubernetes, because agent sessions are bound to the address that opened them.
set -euo pipefail

GUARD=${1:-sijil-guard:$(git rev-parse --short HEAD)}
LEDGER=${2:-sijil:$(git rev-parse --short HEAD)}
P="sijil-gsmoke-$$"
TMP=$(mktemp -d)
cleanup() {
  docker rm -f "$P-adapter" "$P-agent" "$P-api" "$P-ledger" >/dev/null 2>&1 || true
  docker volume rm "$P-data" "$P-state" >/dev/null 2>&1 || true
  docker network rm "$P-net" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; docker logs "$P-ledger" >&2 2>&1 || true; docker logs "$P-adapter" >&2 2>&1 || true; exit 1; }

cp rulepacks/starter.yaml deploy/rehearsal/standins.py "$TMP/"
{ cat policy.yaml; printf 'agents:\n  register_policy: open\n'; } > "$TMP/policy.yaml"
python3 deploy/rehearsal/standins.py spec 0 > "$TMP/case-api.json" 2>/dev/null \
  || docker run --rm -v "$TMP:/w:ro" --entrypoint python "$GUARD" /w/standins.py spec 0 > "$TMP/case-api.json"
cat > "$TMP/guard.yaml" <<YAML
version: 1
sijil: {url: "http://$P-ledger:8000"}
identity:
  agent_id: spiffe://smoke.test/agent/case-agent
  key_path: /state/agent.key
  registered_by: local:$(printf 'smoke' | shasum -a 256 | cut -c1-64)
state_path: /state/session.json
rulepack: /config/starter.yaml
correlation: {require_parent: false}      # no model in this smoke: tool calls are sealed as orphans
http_tools:
  listen: 127.0.0.1:8090
  inbound_auth: {mode: bearer_env}
  servers:
    - name: case-api
      upstream: http://$P-api:9000/api/v2
      spec: /config/case-api.json
YAML
chmod -R a+rX "$TMP"

docker network create "$P-net" >/dev/null
docker run -d --name "$P-ledger" --network "$P-net" --user 12345:0 -v "$P-data:/data" -v "$TMP:/config:ro" \
  -e SIJILL_TOKEN=agent-secret -e SIJILL_RULEPACK_PATH=/config/starter.yaml "$LEDGER" >/dev/null
docker run -d --name "$P-api" --network "$P-net" -v "$TMP:/w:ro" --entrypoint python "$GUARD" \
  /w/standins.py case-api 9000 >/dev/null
docker run -d --name "$P-agent" --network "$P-net" --entrypoint sleep "$GUARD" infinity >/dev/null
G=(--network "container:$P-agent" --user 12345:0 -v "$P-state:/state" -v "$TMP:/config:ro"
   -e SIJIL_TOKEN=agent-secret -e SIJIL_TOOLS_TOKEN=tools-secret)

for _ in $(seq 1 40); do
  docker exec "$P-agent" python -c "import httpx; httpx.get('http://$P-ledger:8000/api/policy').raise_for_status()" \
    2>/dev/null && break
  sleep 0.5
done

docker run --rm "${G[@]}" "$GUARD" identity init || fail "identity init"
docker run -d --name "$P-adapter" "${G[@]}" "$GUARD" >/dev/null

docker exec -i "$P-agent" python - "$P" <<'PY' || fail "request through the adapter"
import sys, time, httpx
p = sys.argv[1]
a = httpx.Client(base_url="http://127.0.0.1:8090", headers={"X-Sijil-Tools-Token": "tools-secret"})
for _ in range(40):
    try:
        a.get("/"); break
    except httpx.TransportError:
        time.sleep(0.5)
assert httpx.post("http://127.0.0.1:8090/_sijil/task/start", json={}).status_code == 401
t = a.post("/_sijil/task/start", json={"intent": "smoke", "session_id": "s1"})
assert t.status_code == 200, t.text
t = t.json()
r = a.get("/case-api/cases/MOI-1", headers={"X-Sijil-Task-Seq": str(t["task_seq"])})
assert r.status_code == 200 and r.json() == {"ok": True}, (r.status_code, r.text)
print(f"tool call through adapter: {r.status_code} X-Sijil-Seq={r.headers['x-sijil-seq']}")
assert httpx.get(f"http://{p}-api:9000/_seen").json() == ["GET /cases/MOI-1"]
e = a.post("/_sijil/task/end", json={"task_seq": t["task_seq"]})
assert e.status_code == 200, e.text
recs = httpx.get(f"http://{p}-ledger:8000/api/records").json()["records"]
print("sealed:", " ".join(r["type"] for r in recs))
for want in ("agent_register", "task_start", "tool_call", "egress", "tool_result", "task_end"):
    assert want in [r["type"] for r in recs], want
PY

# The tool call has no parent inference (no model here), so the verifier is told orphans are expected.
docker exec "$P-ledger" python verifier/sijill_verify.py --db /data/sijill.db --pubkey /data/node.pub \
  --allow-orphan-tool-calls --plain || fail "verifier"

docker run --rm --entrypoint sh "$GUARD" -c 'test ! -e /app/sijill && test ! -e /app/verifier' \
  || fail "the guard image holds ledger code"
echo "no ledger code in the guard image"
echo PASS
