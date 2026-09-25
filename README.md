# Sijill

Inference attestation for AI running on infrastructure you own.

Sijill is a proxy in front of an OpenAI-compatible model endpoint. It evaluates every call against a policy, forwards or blocks it, and seals a signed, hash-chained record of it. An independent verifier proves the chain is intact or names the exact record that broke. A report generator produces an A4 audit PDF for a date range. Everything runs locally on one machine.

The build spec is [`docs/README.md`](docs/README.md). The session log for the judges is [`DEVIN_LOG.md`](DEVIN_LOG.md).

## Setup

Requirements: macOS, Python 3.11, Homebrew `pango` (for WeasyPrint), `sqlite3`, and LM Studio serving `llama-3.2-3b-instruct` on `localhost:1234`.

```bash
brew install pango
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Put the LM Studio token in `.env.local` (git-ignored):

```bash
LM_API_TOKEN=<token from LM Studio → Developer → API tokens>
```

Update `approved_models.allow_digests` in `policy.yaml` if you serve a different weights file. The digest is the SHA-256 of the GGUF file (`shasum -a 256 <file>.gguf`), because LM Studio's API doesn't report one.

## Run

```bash
uvicorn sijill.proxy:app --port 8000 --env-file .env.local   # one worker only
open http://localhost:8000                                  # demo console
```

The first run creates `node.key` (Ed25519 private key, mode 0600), `node.pub` and `sijill.db`. The first call to a model hashes its weights file, which takes about 4 s. After that the digest is cached in `.sijill_digests.json`.

| Env var | Default |
| --- | --- |
| `LMSTUDIO_BASE_URL` | `http://localhost:1234/v1` |
| `LM_API_TOKEN` | *(none)* |
| `DATABASE_PATH` | `sijill.db` |
| `POLICY_PATH` | `policy.yaml` |
| `NODE_KEY_PATH` / `NODE_PUBKEY_PATH` | `node.key` / `node.pub` |
| `SIJILL_MODEL` | `llama-3.2-3b-instruct` |
| `SIJILL_MODELS_DIR` | LM Studio `downloadsFolder` |
| `SIJILL_ENTITY` | `Demonstration Government Entity` (report) |

## Commands

```bash
python verifier/sijill_verify.py --db sijill.db --pubkey node.pub   # PASS/FAIL, exit 0/1
python scripts/seed.py --n 50                                       # 50 calls through the proxy
python scripts/bench.py --n 100                                     # overhead p50/p95 (test 7)
python report/generate.py --from 2026-09-25 --to 2026-09-25 --out report.pdf
scripts/tamper.sh backup | alter <seq> | forge <seq> | restore
python -m pytest                                                    # acceptance tests 1-7 and more
```

## Endpoints

| Method and path | Purpose |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible, non-streaming. Blocked calls get HTTP 403 with the record's `seq` |
| `GET /api/records?since=N` | Records with seq > N, plus the total count |
| `GET /api/policy` | Rules and modes, node id, current region |
| `GET /api/verify` | Runs the verifier CLI as a subprocess and returns its output |
| `POST /api/admin/policy/reload` | Re-reads `policy.yaml`. A mode change writes a `policy_change` record |
| `POST /api/admin/node/region` | `{"region": "US-VA"}`. Writes a `policy_change` record |
| `GET /api/report?from=&to=` | The audit PDF |

**The admin endpoints have no authentication.** This is a local demo build.

Every response carries `X-Sijill-Seq`, `X-Sijill-Decision`, `X-Sijill-Record-Hash` and `X-Sijill-Overhead-Ms`. The last is handler time minus the time spent waiting on the model.

## Demo run-sheet

Before going on stage, reset and prepare:

```bash
rm -f sijill.db sijill.db.bak                       # keep node.key
uvicorn sijill.proxy:app --port 8000 --env-file .env.local
python scripts/seed.py --n 30
scripts/tamper.sh backup
```

On stage, with the console on one side and the terminal on the other:

1. **Policy.** `cat policy.yaml`: three rules, residency and approved models on `enforce`, sensitive terms on `record`.
2. **Traffic.** Click *Ask a plain question* (allow), then *Ask with Emirates ID* (amber flag, still answered).
3. **Residency.** Set the region selector to `US-VA`. The header turns red and a policy change row appears. Ask again: blocked, and the block is sealed too. Set it back to `AE-AZ`.
4. **Tamper, the key moment.** In the terminal:
   ```bash
   scripts/tamper.sh alter 17      # verifier bar: FAIL seq=17 content altered
   scripts/tamper.sh restore       # PASS
   scripts/tamper.sh forge 17      # recomputes the hash like an attacker would: FAIL seq=17 signature invalid
   scripts/tamper.sh restore       # PASS
   ```
   Then run the verifier full-screen: `python verifier/sijill_verify.py --db sijill.db --pubkey node.pub`.
5. **Enforce switch.** Edit `sensitive_terms` to `mode: enforce`, then `curl -XPOST localhost:8000/api/admin/policy/reload`. A policy change row appears, and *Ask with Emirates ID* is now blocked.
6. **Report.** Click *Generate report*: the PDF shows calls by decision, policy hashes in force, the verifier result, and every flag and block.

Fallback: a pre-generated `report.pdf` and the screen recording.

## Measured (MacBook, LM Studio, Llama-3.2-3B-Instruct Q4_K_S)

| | |
| --- | --- |
| Proxy overhead, 100 calls | p50 0.74 ms, p95 0.91 ms (target < 50 ms) |
| End-to-end with model, max_tokens 8 | p50 92 ms, p95 142 ms |
| Storage | ~770 bytes per record (~0.75 MB per 1,000 records) |
| Report generation | ~0.8 s for 118 records |

## Design notes

- **The verifier doesn't import `sijill/`.** It reimplements canonicalisation from the spec, and a test enforces this. The record module's known-answer test was computed with the verifier's code, not the writer's.
- **Append-only.** Application code only SELECTs and INSERTs, and a test scans `sijill/` for anything else. Tampering happens outside the application, with `sqlite3`.
- **`tamper.sh forge` uses only `sqlite3` and `shasum`.** An attacker who knows the algorithm can recompute a valid `record_hash`, but can't sign it.
- **The writer trusts its own head.** The proxy keeps the chain head in memory. Deleting the newest record while it runs shows up as a gap at the next record.
- **Model digest** is the SHA-256 of the weights file, re-checked by file size and mtime on every call. A model whose weights can't be located gets an empty digest and is blocked by `approved_models`.
- **Upstream failures are recorded** with an empty `output_hash`, and the proxy returns 502.

## Honest boundaries

Sijill proves records haven't been altered since they were sealed. It doesn't prove the sealing process was honest: node identity and region are asserted by the node and signed with its key, not bound to hardware. Hardware root of trust (TEE / GPU attestation) is roadmap. The chain also can't detect truncation of its newest records while the node is offline. Anchoring the chain head externally would fix that.

## Layout

```
sijill/      record.py (frozen) keys.py store.py policy.py digest.py proxy.py
verifier/    sijill_verify.py (standalone)
report/      generate.py template.html
dashboard/   index.html
scripts/     seed.py bench.py tamper.sh
tests/       pytest: acceptance 1-7, known-answer vector, product-claim checks
```
