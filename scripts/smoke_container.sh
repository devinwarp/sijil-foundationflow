#!/usr/bin/env bash
# Container smoke test for the Sijil image. Run from repo root: scripts/smoke_container.sh [image-tag]
# Default tag is sijil:<HEAD short sha>, as built by scripts/bundle_offline.sh.
set -euo pipefail

IMAGE=${1:-sijil:$(git rev-parse --short HEAD)}
NAME="sijil-smoke-$$"
TOKEN=smoke
CID=""
NET="sijil-smoke-net-$$"
STUB="sijil-smoke-stub-$$"
CHAT="sijil-smoke-chat-$$"
TMP=""

cleanup() {
  if [ -n "$CID" ]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi
  docker rm -f "$CHAT" "$STUB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [ -n "$TMP" ]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
BASE="http://127.0.0.1:$PORT"

# Arbitrary UID in group 0, as OpenShift runs the image. The image's own user (1001) is not in group 0.
CID=$(docker run -d --name "$NAME" --user 12345:0 -p "127.0.0.1:$PORT:8000" \
  -v "$PWD/policy.yaml:/config/policy.yaml:ro" \
  -e SIJILL_ADMIN_TOKEN="$TOKEN" "$IMAGE")

# Poll until the proxy answers (up to ~20s).
up=0
for _ in $(seq 1 40); do
  if curl -fsS "$BASE/api/policy" >/dev/null 2>&1; then up=1; break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null)" != "true" ]; then break; fi
  sleep 0.5
done
[ "$up" = 1 ] || { docker logs "$CID" >&2 || true; fail "proxy did not answer /api/policy"; }

policy=$(curl -fsS "$BASE/api/policy")
echo "$policy" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["admin_auth"] == "token" else 1)' \
  || fail "admin_auth is not \"token\": $policy"
echo "admin_auth=token"

verify=$(curl -fsS "$BASE/api/verify")
echo "$verify" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["ok"] is True else 1)' \
  || fail "/api/verify ok is not true: $verify"
echo "verify ok=true"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/policy/reload")
[ "$code" = 401 ] || fail "unauthenticated POST /api/admin/policy/reload returned $code, expected 401"
echo "unauthenticated reload=401"

# No key file in the image (checked on the image itself, not the running container).
docker run --rm --entrypoint sh "$IMAGE" -c 'test ! -e /app/node.key' \
  || fail "/app/node.key exists in the image"
echo "no-key"

# The migration script ships in the image (M1 installs are told to run it).
docker run --rm --entrypoint sh "$IMAGE" -c 'test -f /app/scripts/migrate_v2.py' \
  || fail "scripts/migrate_v2.py missing from the image"
echo "migrate-script-ok"

# An arbitrary UID in group 0 can write /data.
docker run --rm --user 12345:0 --entrypoint sh "$IMAGE" -c 'touch /data/uid-probe && rm /data/uid-probe' \
  || fail "arbitrary UID in group 0 cannot write /data"
echo "arbitrary-uid-ok"

# One real chat call end to end as the image's own user (1001): weights read-only at /models, digest
# cache under /data, a stub OpenAI-compatible upstream. Catches an unwritable digest cache.
TMP=$(mktemp -d)
printf 'smoke weights' > "$TMP/smoke-model.gguf"
DIGEST="sha256:$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/smoke-model.gguf")"
python3 - "$DIGEST" "$TMP/policy.yaml" <<'PY'
import re, sys
text = open("policy.yaml").read()
text, n = re.subn(r"allow_digests:.*", f'allow_digests: ["{sys.argv[1]}"]', text)
assert n == 1 and "AE-AZ" in text
open(sys.argv[2], "w").write(text)
PY
chmod 755 "$TMP"; chmod 644 "$TMP"/*

docker network create "$NET" >/dev/null
docker run -d --name "$STUB" --network "$NET" --entrypoint python "$IMAGE" -c '
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
BODY = json.dumps({"id": "chatcmpl-smoke", "object": "chat.completion", "created": 0, "model": "smoke-model",
  "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
  "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY))); self.end_headers(); self.wfile.write(BODY)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 9000), H).serve_forever()' >/dev/null

ready=0
for _ in $(seq 1 40); do
  if docker exec "$STUB" python -c 'import socket; socket.create_connection(("127.0.0.1", 9000), 1)' >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { docker logs "$STUB" >&2 || true; fail "stub upstream did not start"; }

CPORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
CBASE="http://127.0.0.1:$CPORT"
docker run -d --name "$CHAT" --network "$NET" -p "127.0.0.1:$CPORT:8000" \
  -v "$TMP/policy.yaml:/config/policy.yaml:ro" -v "$TMP:/models:ro" \
  -e SIJILL_ADMIN_TOKEN="$TOKEN" -e "LMSTUDIO_BASE_URL=http://$STUB:9000/v1" -e SIJILL_MODEL=smoke-model \
  "$IMAGE" >/dev/null

up=0
for _ in $(seq 1 40); do
  if curl -fsS "$CBASE/api/policy" >/dev/null 2>&1; then up=1; break; fi
  sleep 0.5
done
[ "$up" = 1 ] || { docker logs "$CHAT" >&2 || true; fail "chat proxy did not answer /api/policy"; }

chat_hdr="$TMP/chat.hdr"
code=$(curl -s -D "$chat_hdr" -o "$TMP/chat.out" -w '%{http_code}' -X POST "$CBASE/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"smoke-model","messages":[{"role":"user","content":"hello"}]}')
if [ "$code" != 200 ] || ! tr -d '\r' < "$chat_hdr" | grep -qi '^x-sijill-decision: allow$'; then
  cat "$chat_hdr" "$TMP/chat.out" >&2 || true; docker logs "$CHAT" >&2 || true
  fail "chat call returned $code or was not allowed"
fi
echo "chat call=200 decision=allow"

# The cache write is non-fatal, so check it actually landed on the /data volume.
docker exec "$CHAT" test -s /data/sijill_digests.json || fail "digest cache not written to /data"
if docker logs "$CHAT" 2>&1 | grep -q "digest cache not written"; then fail "proxy logged a digest cache write failure"; fi
echo "digest cache on /data"

verify=$(curl -fsS "$CBASE/api/verify")
echo "$verify" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["ok"] is True else 1)' \
  || fail "/api/verify ok is not true after chat call: $verify"
echo "verify after chat ok=true"

echo "PASS: $IMAGE"
