#!/usr/bin/env bash
# Build an offline install bundle for an air-gapped site. Run from repo root.
set -euo pipefail
SHA=$(git rev-parse --short HEAD)
OUT=dist/sijil-$SHA
rm -rf "$OUT" && mkdir -p "$OUT"
docker build -t "sijil:$SHA" .
docker save "sijil:$SHA" | gzip > "$OUT/sijil-image-$SHA.tar.gz"
cp -r policy.yaml verifier "$OUT/"
mkdir -p "$OUT/scripts" && cp scripts/siem_forward.py "$OUT/scripts/"
cat > "$OUT/INSTALL.txt" <<EOT
1. docker load < sijil-image-$SHA.tar.gz   (or: podman load -i ...)
2. Edit policy.yaml (node id, region, approved model digests).
3. docker run -d -p 8000:8000 -v \$PWD/policy.yaml:/config/policy.yaml:ro -v sijil-data:/data \\
     -e SIJILL_ADMIN_TOKEN=<random 32+ chars> -e LMSTUDIO_BASE_URL=<model endpoint>/v1 sijil:$SHA
   HSM: add -e SIJILL_PKCS11_MODULE=... -e SIJILL_PKCS11_TOKEN=... -e SIJILL_PKCS11_KEY=... -e SIJILL_PKCS11_PIN=...
   and mount the vendor PKCS#11 library.
4. Point agents' OpenAI base URL at http://<host>:8000/v1.
5. SIEM: python3 scripts/siem_forward.py --url http://<host>:8000 --sink <siem>:514
6. Verify offline at any time: python3 verifier/sijill_verify.py --db <copy of sijill.db> --pubkey node.pub
EOT
(cd dist && tar czf "sijil-$SHA.tar.gz" "sijil-$SHA")
echo "dist/sijil-$SHA.tar.gz"
