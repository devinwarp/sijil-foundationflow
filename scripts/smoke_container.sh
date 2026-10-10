#!/usr/bin/env bash
# Container smoke test for the Sijil image. Run from repo root: scripts/smoke_container.sh [image-tag]
# Default tag is sijil:<HEAD short sha>, as built by scripts/bundle_offline.sh.
set -euo pipefail

IMAGE=${1:-sijil:$(git rev-parse --short HEAD)}
NAME="sijil-smoke-$$"
TOKEN=smoke
CID=""

cleanup() {
  if [ -n "$CID" ]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi
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

# An arbitrary UID in group 0 can write /data.
docker run --rm --user 12345:0 --entrypoint sh "$IMAGE" -c 'touch /data/uid-probe && rm /data/uid-probe' \
  || fail "arbitrary UID in group 0 cannot write /data"
echo "arbitrary-uid-ok"

echo "PASS: $IMAGE"
