FROM python:3.11-slim
# weasyprint needs pango for the PDF report; sqlite3 CLI takes consistent DB exports (INSTALL.txt step 6)
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 sqlite3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sijill sijill
COPY verifier verifier
COPY report report
COPY dashboard dashboard
COPY scripts/siem_forward.py scripts/siem_forward.py
# OpenShift runs an arbitrary UID in group 0: make /data group-writable
RUN mkdir /data /config && chgrp 0 /data && chmod g=u /data
ENV DATABASE_PATH=/data/sijill.db POLICY_PATH=/config/policy.yaml \
    NODE_KEY_PATH=/data/node.key NODE_PUBKEY_PATH=/data/node.pub SIJILL_HALT_PATH=/data/sijill.halt \
    SIJILL_DIGEST_CACHE=/data/sijill_digests.json SIJILL_MODELS_DIR=/models
# Operators mount model weights read-only at /models (-v <dir>:/models:ro)
USER 1001
EXPOSE 8000
CMD ["uvicorn", "sijill.proxy:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
