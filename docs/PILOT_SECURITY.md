# Pilot security checklist

Each line is checked by a command or a test. Run before every pilot install.

| Control | Evidence |
| --- | --- |
| Admin endpoints need a token; disabled when unset | `pytest tests/test_admin_auth.py` |
| No key file in the image | `scripts/smoke_container.sh` (prints `no-key`) |
| Signing key in the HSM, no file fallback | `pytest tests/test_hsm.py` (not skipped) |
| Runs as non-root, arbitrary UID | `scripts/smoke_container.sh` (prints `arbitrary-uid-ok`) |
| Prompts and answers never stored, only hashed | `sijill/record.py` input_hash/output_hash; `tests/test_record.py` |
| Records append-only in application code | `pytest tests/test_claims.py` |
| Every streamed call sealed, including hang-ups (after delivery: a signer outage mid-stream leaves a delivered, unsealed answer) | `pytest tests/test_streaming.py` |
| SOC receives blocks as CEF severity 8 | `pytest tests/test_siem.py`; manual SIEM check below |
| Chain verifies offline with the Apache-2.0 verifier | `python3 verifier/sijill_verify.py --db export.db --pubkey node.pub`; see below |
| Operator can halt every call, halt survives restart; a stream in flight stops and seals `block` with `halted` | `pytest tests/test_halt.py tests/test_streaming.py` |

`scripts/smoke_container.sh [image]` starts the image with the policy mounted read-only and a token set,
then checks the admin auth mode, `/api/verify`, the 401 on an unauthenticated admin call, the absence of
`/app/node.key`, and a write to `/data` as an arbitrary UID in group 0. It exits non-zero on any failure.

## Manual checks

**SIEM.** With the proxy running and a blocked call in the ledger:

```bash
nc -lk 5514                                                     # terminal 1: stand-in SIEM receiver
python3 scripts/siem_forward.py --url http://127.0.0.1:8000 --sink 127.0.0.1:5514 --state /tmp/siem_state   # terminal 2
```

Expect CEF lines (`CEF:0|FoundationFlow|Sijil|...`). The blocked call's line carries severity `|8|`.

**Verifier.** For a container deployment, copy the public key and a consistent DB snapshot out of the
data volume (INSTALL.txt, step 6). The proxy may be writing, so take an SQLite online backup first; a plain
file copy can be torn and fail verification:

```bash
docker run --rm -v sijil-data:/data --entrypoint cat sijil:<sha> /data/node.pub > node.pub
docker run --rm -v sijil-data:/data --entrypoint sqlite3 sijil:<sha> /data/sijill.db ".backup /data/export.db"
docker run --rm -v sijil-data:/data --entrypoint cat sijil:<sha> /data/export.db > export.db
python3 verifier/sijill_verify.py --db export.db --pubkey node.pub   # PASS, exit 0
```

Known limits to state to the entity: read endpoints (`/api/records`, `/api/policy`, `/api/verify`,
`/api/report`, and the dashboard at `/`) are not authenticated in the pilot build; put them behind the
entity's reverse proxy with SSO. The proxy host can still seal false records (README "Honest boundaries");
HSM custody limits key theft, not a compromised host. A non-streamed call already forwarded to the model
when the halt lands completes, and is sealed `allow` after the `halted` record. A streamed answer is
sealed after it reaches the client, so a signer outage mid-stream leaves a delivered, unsealed answer.
A stream halted mid-answer is sealed `block` with rule hits `halted` and `upstream_error` and an empty
`output_hash`, even if part of the answer already reached the client. The record's decision enum is
frozen, so auditors should read `block` with `halted` on a streamed call as "stopped mid-stream; partial
output may have been delivered", not as "nothing was delivered".
