# Shameer: the show

**Owns:** `dashboard/*`, `report/*`, `scripts/seed.py`, `README.md`, `docs/*`, the deck
**Branch:** `shameer/demo`, from `devin/build`

## Before handing anything to Devin

1. Fix `.env`: it still has `LM_API_TOKEN=your-token-here`, which overrides the real token in `.env.local`. Delete the line or put the real token in.
2. Decide the demo content:
   - Entity name on the report (currently `Demonstration Government Entity`).
   - The two console preset questions: a plain one, and one containing "Emirates ID".
   - The disallowed region to show (currently `US-VA`; the allowed ones are `AE-AZ` and `AE-DU`).

## Setup

```bash
cd /Users/shameerthaha/GitHub/hackathons/sijil-foundationflow
git fetch && git checkout devin/build && git checkout -b shameer/demo
source venv/bin/activate
```

## Prompt for Devin

> On `shameer/demo` (created from `devin/build`) in devinwarp/sijil-foundationflow. `docs/README.md` is the spec and wins over everything else. Only edit `dashboard/`, `report/`, `scripts/seed.py`, `README.md` and `docs/`. `sijill/`, `verifier/`, `tests/`, `policy.yaml`, `scripts/tamper.sh` and `scripts/bench.py` belong to Narayan's lane: if something there needs changing, tell me instead of editing it.
>
> The console must never offer any way to alter records. Tampering happens only in the terminal. The policy strip stays display-only. It must work fully offline: no CDNs or web fonts.
>
> Apply these:
> 1. Report entity name: <name>. Set it as the default for `SIJILL_ENTITY` in `report/generate.py`.
> 2. Console preset questions: plain = "<question>", sensitive = "<question containing Emirates ID>".
> 3. Disallowed demo region in the region selector: <code>.
> 4. <any polish from rehearsal: console readability on a projector, report wording, etc.>
>
> Check the console with headless Chrome screenshots, intact and after `scripts/tamper.sh alter 17`, and the report by rendering its pages to PNG. Keep `python -m pytest` green. Add a short entry at the end of `DEVIN_LOG.md`: what was delegated, what came back, what I changed and why. Commit in small commits with clear messages. Don't push until I say so.

## After Devin

- Put the measured numbers in the deck:
  - Proxy overhead p95: **0.91 ms** (p50 0.74 ms, 100 calls, target < 50 ms)
  - End to end with the model: **p50 92 ms**
  - Storage: **~0.75 MB per 1,000 records**
  - Report generation: **~0.8 s**
  - Replace these with Narayan's numbers from the demo laptop if they differ.
- Record the fallback video as soon as one full run works, before any polish. Keep a pre-generated `report.pdf` as backup.
- Rehearse the stage flow from the run-sheet in `README.md`, especially the tamper moment.
- Fill in your rows of the "What a human changed, and why" table at the end of `DEVIN_LOG.md`.
- Merge order: `narayan/core` into `devin/build` first, then `shameer/demo`, then everything into `main`.
