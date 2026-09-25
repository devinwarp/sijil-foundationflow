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
