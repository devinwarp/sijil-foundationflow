# Render image for the hosted demo node: the repo's Dockerfile plus the demo policy and rule pack, run as root so it can write the mounted disk
# (Render mounts persistent disks root-owned). SIJILL_SESSION_ADDR_BIND=0: behind Render's proxy, and for calls from Vercel functions, the caller's address is not stable. One instance only: the ledger is a single SQLite file on the disk at /data.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 sqlite3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY LICENSE LICENSE
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sijill sijill
COPY guard guard
COPY verifier verifier
COPY report report
COPY dashboard dashboard
COPY scripts/siem_forward.py scripts/siem_forward.py
COPY scripts/migrate_v2.py scripts/migrate_v2.py
RUN mkdir -p /data /config
COPY deploy/render/policy.yaml /config/policy.yaml
COPY rulepacks/starter.yaml /config/rulepack.yaml
ENV DATABASE_PATH=/data/sijill.db POLICY_PATH=/config/policy.yaml SIJILL_RULEPACK_PATH=/config/rulepack.yaml \
    NODE_KEY_PATH=/data/node.key NODE_PUBKEY_PATH=/data/node.pub SIJILL_HALT_PATH=/data/sijill.halt \
    SIJILL_JWKS_DIR=/data/jwks SIJILL_DIGEST_CACHE=/data/sijill_digests.json SIJILL_MODELS_DIR=/models \
    SIJILL_SESSION_ADDR_BIND=0 SIJILL_UPSTREAM_PROVIDER=openrouter LMSTUDIO_BASE_URL=https://openrouter.ai/api/v1 SIJILL_MODEL=deepseek/deepseek-v4.1-flash
EXPOSE 8000
CMD ["sh", "-c", "uvicorn sijill.proxy:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
