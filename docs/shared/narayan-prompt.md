# Narayan: the engine

**Owns:** `sijill/*`, `verifier/*`, `tests/*`, `policy.yaml`, `scripts/tamper.sh`, `scripts/bench.py`
**Branch:** `narayan/core`, from `devin/build`

## Before handing anything to Devin

1. **Review `sijill/record.py` yourself, not with Devin.** We tell the judges a human checked the cryptographic core. If Devin reviews Devin's code, that claim is false. When you're satisfied, it's frozen: `tests/test_record.py` locks the hash and signature.
2. Decide two open questions:
   - Failed model calls are currently recorded with an empty `output_hash`, and the proxy returns 502. Keep this or drop it?
   - A `policy.yaml` changed while the proxy was down writes no record at startup. Should the proxy write a `policy_change` record when the policy hash differs from the last record's?

## Setup

```bash
git clone https://github.com/devinwarp/sijil-foundationflow.git
cd sijil-foundationflow
git checkout devin/build && git checkout -b narayan/core
brew install pango
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
echo "LM_API_TOKEN=<your LM Studio token>" > .env.local
```

- `node.key` and `node.pub` aren't in the repo. The proxy generates them on first run. The demo laptop's key is the one that gets created there.
- If your GGUF file differs from Shameer's, update `approved_models.allow_digests` in `policy.yaml` (`shasum -a 256 <file>.gguf`, prefixed with `sha256:`). Otherwise every call is blocked by `approved_models`.

## Prompt for Devin

> Check out `devin/build` from devinwarp/sijil-foundationflow and create `narayan/core`. `docs/README.md` is the spec and wins over everything else. Only edit `sijill/`, `verifier/`, `tests/`, `policy.yaml`, `scripts/tamper.sh` and `scripts/bench.py`. Other files belong to Shameer's lane: if something there needs changing, tell me instead of editing it.
>
> Don't change `sijill/record.py` unless I ask; `tests/test_record.py` freezes it. The verifier must never import from `sijill/`. Application code in `sijill/` must never UPDATE or DELETE. Both are enforced by `tests/test_claims.py`.
>
> Implement these decisions:
> 1. Upstream model failures: <keep recording them with an empty output_hash and a 502 | stop recording them>.
> 2. Startup policy drift: <write a policy_change record at startup when the policy file hash differs from the last record's policy_hash | leave as is>.
> 3. <any fixes from my review of store.py, policy.py and proxy.py>
>
> Keep `python -m pytest` green and add tests for each change. Then run `scripts/bench.py --n 100` against the real proxy and report p50/p95 overhead. Add a short entry at the end of `DEVIN_LOG.md`: what was delegated, what came back, what I changed and why. Commit in small commits with clear messages. Don't push until I say so.

## After Devin

- Run `python -m pytest` and `scripts/bench.py` on the demo laptop.
- Rehearse the terminal half of the demo until it's automatic:
  ```bash
  scripts/tamper.sh backup
  scripts/tamper.sh alter 17     # FAIL seq=17 content altered
  scripts/tamper.sh restore      # PASS
  scripts/tamper.sh forge 17     # FAIL seq=17 signature invalid
  scripts/tamper.sh restore      # PASS
  python verifier/sijill_verify.py --db sijill.db --pubkey node.pub
  ```
- Fill in your rows of the "What a human changed, and why" table at the end of `DEVIN_LOG.md`.
- Merge order: `narayan/core` into `devin/build` first, then `shameer/demo`, then everything into `main`.

## `record.py` review checklist (do this yourself, about 20 minutes)

Deck slide 7/8 says you reviewed and froze the sealing logic, and `DEVIN_LOG.md` still marks it _pending_. Check each item against "Record schema" and "Canonicalisation and hashing" in `docs/README.md`:

1. `FIELDS` lists exactly the 18 spec fields, spelled as in the spec.
2. `canonical_json` is `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`, and nothing else.
3. `compute_record_hash` excludes `record_hash` and `signature` only.
4. `_validate` makes `seq` the only integer. Every other field must be a string, and type, mode and decision are limited to the spec values.
5. The signature is Ed25519 over `bytes.fromhex(record_hash)`, the 32 raw bytes, not the hex text, and is stored hex-encoded.
6. `now_ts()` gives UTC with milliseconds and a `Z` suffix. `GENESIS_HASH` is 64 zeros.
7. The caller supplies the chain link: `Node.seal` in `proxy.py` takes `seq` and `prev_hash` from the in-memory head, under the lock.
8. Cross-check with a third implementation, independent of both `record.py` and the verifier:
   ```bash
   python - <<'PY'
   import hashlib, json, sqlite3
   db = sqlite3.connect("sijill.db")
   db.row_factory = sqlite3.Row
   r = dict(db.execute("SELECT * FROM records WHERE seq = 1").fetchone())
   body = {k: v for k, v in r.items() if k not in ("record_hash", "signature")}
   print(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == r["record_hash"])
   PY
   ```
   It should print `True`.
9. `python -m pytest tests/test_record.py tests/test_verifier.py` passes. The known-answer vector in `test_record.py` was computed with the verifier's code, not `record.py`'s.

Then replace the _pending_ row in the Session 2 table of `DEVIN_LOG.md`, for example: `| Narayan | sijill/record.py | Reviewed against the spec, items 1-9; no changes (or: changed X) | Correctness-critical; frozen from here |`.
