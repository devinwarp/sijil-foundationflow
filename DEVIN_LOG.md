# Devin Session Log - Sijill Verifier Implementation

## Task Delegation
From Build Spec: "Read the Build Spec in README.md. Build the verifier CLI in `verifier/sijill_verify.py` exactly as specified under 'Canonicalisation and hashing' and 'Verifier CLI'. Do not import anything from the `sijill/` package. Write a fixture generator that creates a valid 50-record chain with a test keypair, then implement acceptance tests 1 through 4 against that fixture. Log your work in `DEVIN_LOG.md`. Stop and report when tests 1–4 pass."

## Implementation Summary

### Phase 1: Verifier CLI Implementation
**File**: `verifier/sijill_verify.py`

Implemented standalone verifier CLI with the following components:

1. **Canonicalisation and Hashing** (`canonicalise_and_hash` function)
   - Takes record dict excluding `record_hash` and `signature`
   - Serialises with `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`
   - Computes SHA-256 hash and returns lowercase hex string
   - Correctly handles `seq` as integer, all other fields as strings

2. **Signature Verification** (`verify_signature` function)
   - Loads Ed25519 public key from PEM or hex format
   - Decodes hex `record_hash` and `signature` to bytes
   - Verifies signature using cryptography library

3. **Record Chain Verification** (`verify_records` function)
   - Walks records in sequence order
   - Check 1: seq is exactly previous + 1 → FAIL on gap
   - Check 2: recomputed hash equals stored `record_hash` → FAIL on content alteration
   - Check 3: `prev_hash` equals previous record's `record_hash` → FAIL on chain broken
   - Check 4: signature verifies against public key → FAIL on invalid signature
   - Stops at first failure
   - On success: prints `PASS records=N first=<ts> last=<ts>`, exit code 0
   - On failure: prints specific failure message with seq, exit code 1

4. **CLI Interface**
   - Accepts `--db` and `--pubkey` arguments
   - Large, readable output suitable for projector display

**Key Design Decision**: Implemented as completely standalone script with no imports from `sijill/` package, as required by spec.

### Phase 2: Fixture Generator
**File**: `tests/test_fixture.py`

Created fixture generator to support acceptance testing:

1. **Keypair Generation**
   - Generates Ed25519 keypair using cryptography library
   - Saves private key in PEM format (`test_private.pem`)
   - Saves public key in PEM format (`test_public.pem`)
   - Saves public key in hex format (`test_public.hex`)

2. **Database Creation**
   - Creates SQLite database with exact schema from Build Spec
   - Drops existing table to ensure clean state

3. **Record Generation**
   - Generates valid records with all required fields
   - Implements same canonicalisation and hashing as verifier
   - Signs each record with private key
   - Maintains hash chain (prev_hash → record_hash)
   - Creates 50 records by default

**Testing Issue**: Initial implementation used `CREATE TABLE IF NOT EXISTS` which caused UNIQUE constraint failures when regenerating fixtures. Fixed by explicitly dropping table before creation.

### Phase 3: Acceptance Tests
**File**: `tests/test_acceptance.py`

Implemented acceptance tests 1-4 as specified:

#### Test 1: Valid Chain
- Generates 50-record fixture
- Runs verifier
- **Expected**: PASS with record count and timestamps
- **Result**: ✓ PASSED

#### Test 2: Content Altered
- Generates 50-record fixture
- Modifies `output_hash` of record 17 using sqlite3
- Runs verifier
- **Expected**: FAIL at seq 17 with "content altered"
- **Result**: ✓ PASSED

#### Test 3: Signature Invalid
- Generates 50-record fixture
- Changes record 17's `model_id` (content alteration)
- Recomputes hash using canonicalisation algorithm
- Updates record with new hash but keeps old signature
- **Expected**: FAIL at seq 17 with "signature invalid"
- **Result**: ✓ PASSED

**Testing Issue**: Initial implementation had column query issue. Fixed by querying columns before fetching row.

#### Test 4: Gap Detection
- Generates 50-record fixture
- Deletes record 17 using sqlite3
- Runs verifier
- **Expected**: FAIL at seq 18 with "gap"
- **Result**: ✓ PASSED

## Test Results

All acceptance tests (1-4) passed successfully:

```
Test 1: Valid chain: ✓ PASSED
Test 2: Content altered: ✓ PASSED
Test 3: Signature invalid: ✓ PASSED
Test 4: Gap detection: ✓ PASSED
```

## Key Implementation Details

### Canonicalisation Implementation
The canonicalisation follows the exact specification:
```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

This ensures:
- Keys are sorted alphabetically
- No whitespace in output
- Non-ASCII characters preserved
- UTF-8 encoding before hashing

### Hash Chain Integrity
- First record: `prev_hash = '0' * 64`
- Subsequent records: `prev_hash = previous_record['record_hash']`
- Each record's hash includes the previous hash, creating an immutable chain

### Signature Scheme
- Ed25519 signing of the 32 raw bytes of `record_hash`
- Hex-encoded signature stored in database
- Verification uses public key only (no private key needed for verification)

### Independence Requirement
The verifier deliberately reimplements canonicalisation and verification logic from the Build Spec rather than importing from the `sijill/` package. This independence is a core product claim - the thing that checks the records is not the thing that wrote them.

## Files Created
1. `verifier/sijill_verify.py` - Standalone verifier CLI (162 lines)
2. `tests/test_fixture.py` - Fixture generator (176 lines)
3. `tests/test_acceptance.py` - Acceptance tests 1-4 (209 lines)

## Dependencies
- Python 3.11+ (tested with 3.14.7)
- cryptography library (for Ed25519 operations)
- sqlite3 (standard library)

## Environment Notes
- LM Studio authentication configured with API token
- Project structure created according to Build Spec
- All tests run locally without external dependencies

## Status
**COMPLETED**: Acceptance tests 1-4 all passing. Verifier CLI ready for integration with the main sijill package.

## Next Steps (Per Build Spec)
The Build Spec indicates these remaining tasks are assigned to the Engineer:
- `record.py`, `store.py`, `keys.py`, `proxy.py`, `policy.py` implementation
- These are correctness-critical components

The Build Spec also indicates remaining Devin tasks:
- Report generator
- Dashboard, `seed.py`, `bench.py`, `tamper.sh`
- README with setup and demo steps

However, the immediate task from the first prompt is complete: "Stop and report when tests 1–4 pass."

---

# Session 2 — 25 Sep 2026: full build

## Delegated (by Shameer)
Initialise git and create `devinwarp/sijil-foundationflow` (public). Build to `docs/README.md` (the newer spec). Fix the gaps found in session 1's work. Devin also builds the correctness-critical core (`record.py`, `store.py`, `keys.py`, `policy.py`, `proxy.py`), which the spec assigned to the engineer, with a human review of `record.py` before freeze. Model digest = SHA-256 of the GGUF file. Report via WeasyPrint.

## Clarifying questions Devin asked, and the answers
| Question | Answer |
| --- | --- |
| Repo visibility | Public |
| Which docs to commit | Specs and partner brief. PRD and pitch deck stay local (internal commercial notes) |
| Which spec wins | `docs/README.md`. The older Build Spec is now marked superseded |
| Layout | Flat: repo root is the project, package at `./sijill/` |
| Who writes the core | Devin, with Narayan reviewing and owning it |
| Model digest source | SHA-256 of the weights file on disk (LM Studio's API reports none) |

## Gaps found in session 1's work, and fixed
- Test 2 ran `SET output_hash = 'd' * 64`. In SQLite that stores the integer `0`, so the test passed for the wrong reason. It now writes a real 64-char value and asserts it landed.
- Fixture timestamps weren't millisecond UTC (`+00:00`, no ms). All records now use `2026-09-25T10:00:00.123Z`.
- The verifier crashed on a missing DB or table, read `SELECT *` (so extra columns changed the hash), and added text to the seq-1 failure line. It now reads only the spec's columns, opens the DB read-only, prints one spec-format line, and shows a large PASS/FAIL banner on a TTY for the projector.
- The tests were standalone scripts using cwd-relative paths and `python`. They are now pytest with temp dirs.
- Session 1 was tested on Python 3.14. Everything now runs in a Python 3.11 venv.

## What Devin built
| Commit | Content |
| --- | --- |
| `4498177` | `record.py` alone, first, so it can be reviewed before anything depends on it |
| `1f31c68` | `keys.py`, `store.py` (SELECT/INSERT only), `policy.py`, `digest.py`, `proxy.py`, `policy.yaml` with the real model digest |
| `6be9ed2` | Verifier hardening, `tamper.sh`, pytest acceptance tests 1-7, known-answer vector, product-claim tests |
| `96fd4b9` | `seed.py`, `bench.py`, demo console, WeasyPrint report |

Design decisions worth a human look:
1. **Known-answer vector for `record.py`**, computed with the verifier's independent code, not with `record.py` itself. Two implementations agree.
2. **`tamper.sh forge` uses only `sqlite3` and `shasum`.** Test 3 gets `signature invalid` (not `content altered`), which proves the shell recompute matches the canonical hash byte for byte.
3. **The writer trusts its in-memory head**, not the DB. Deleting the newest record while running shows up as a gap. Found while thinking through `tamper.sh restore`; covered by a test.
4. **`tamper.sh restore` only replaces rows that differ from the backup**, so records sealed after the backup survive. A whole-file restore would have silently dropped them during the demo.
5. **A region change writes a `policy_change` record with `rule_hits=[]`.** The spec only defines `rule_hits` for mode changes. The console shows it as `region → US-VA`.
6. **Upstream (model) failures are recorded** with an empty `output_hash`, and the proxy returns 502. Open for Narayan to confirm.
7. **Found while running for real:** WeasyPrint can't find Homebrew's pango on macOS without `DYLD_FALLBACK_LIBRARY_PATH`. `generate.py` re-execs itself with it set.

## Results
- `pytest`: 33 passed. Covers acceptance 1-7, tamper alter/forge/restore on a proxy-written chain, the tail-deletion gap, and the verifier-independence and append-only checks.
- Real run against LM Studio (Llama-3.2-3B Q4_K_S): seed, region block (403), policy reload, forge (`FAIL seq=17 signature invalid`), restore (PASS), report PDF.
- `bench.py`, 100 calls on the real model: overhead p50 0.74 ms, p95 0.91 ms. End to end p50 92 ms.

## What a human changed, and why
*(Narayan and Shameer fill this in as they review. Judges read this section.)*

| Who | File | Change | Why |
| --- | --- | --- | --- |
| Shameer | `docs/` | Chose `docs/README.md` over the older Build Spec as the source of truth | The newer spec adds the demo console, `/api/verify` and the tamper subcommands |
| Shameer | `sijill/*` | Assigned the core to Devin instead of the engineer, with Narayan reviewing | Capacity on the day. Review of the cryptographic core stays with a human |
| Shameer | `sijill/digest.py`, `policy.yaml` | Chose SHA-256 of the GGUF weights file as the model digest | LM Studio's API reports no content digest |
| Shameer | `report/` | Chose WeasyPrint over reportlab | The spec calls for an HTML template rendered to PDF |
| Shameer | repo, `.gitignore` | Public repo, with the PRD and pitch deck kept out of git | The PRD contains internal commercial notes |
| Narayan | `sijill/record.py` | Review and freeze: _pending_ | |

---

# Session 3 — 25 Sep 2026: demo content (Shameer's lane, `shameer/demo`)

## Delegated (by Shameer)
Branch `shameer/demo` from `devin/build`. Only edit `dashboard/`, `report/`, `scripts/seed.py`, `README.md` and `docs/`. Apply Shameer's entity name, preset questions and demo region. The console must never offer a way to alter records.

## Choices (Devin offered options, Shameer picked)
| Item | Choice |
| --- | --- |
| Report entity | Ministry of Citizen Services (fictional, fits the pitch's citizen-assistant opening) |
| Plain preset | "What documents do I need to renew a trade licence?" |
| Sensitive preset | "My Emirates ID number is 784-1990-1234567-1. Can you check my application status?" (a fictional number) |
| Disallowed region | SG. A neutral non-UAE region, rather than US-VA, following the PRD's advice not to frame sovereignty as anti-US with a US lab on the panel |

## What came back
- `dashboard/index.html`: new sensitive preset. The region selector is now `AE-AZ`, `AE-DU`, `SG`. Still no controls that alter records, and the policy strip is still display-only.
- `report/generate.py`: `SIJILL_ENTITY` now defaults to Ministry of Citizen Services.
- `scripts/seed.py`: seeded sensitive calls use the same ID-number question.
- `README.md` and `docs/shared/shameer-prompt.md` updated to match. The run-sheet now points out that the ID number is stored only as a SHA-256 hash.
- Not touched, because they're Narayan's lane: `tests/test_proxy.py` still uses `US-VA` as its disallowed region. The API accepts any region code, so the tests are unaffected.

## Verification
- `pytest`: 33 passed.
- Live run on a scratch DB with the real model: the ID-number question was flagged (`sensitive_terms`) and answered. Switching to SG wrote a `policy_change` record and the next call got a 403. The verifier passed with 8 records. The report masthead reads "Ministry of Citizen Services". A headless screenshot shows SG in red with "outside residency".
- Checked that no record contains the raw text: `input_hash` holds only the digest.

## What a human changed, and why
| Who | File | Change | Why |
| --- | --- | --- | --- |
| Shameer | `dashboard/`, `README.md` | Chose SG instead of US-VA as the disallowed demo region | Frames residency as a gap, not a grievance. Avoids an anti-US reading with a US lab on the panel |
| Shameer | `dashboard/`, `scripts/seed.py` | Chose a sensitive preset that includes an ID number | Makes the point that the record holds only a hash of what was sent |
| Shameer | `report/generate.py` | Set the report entity to Ministry of Citizen Services (fictional) | Matches the pitch's opening question about a citizen-facing assistant |

---

# Session 4 — 25 Sep 2026: pitch deck v2 (Shameer's lane)

## Delegated (by Shameer)
Take the 13-slide Fish Tank pitch and the brand logo, and produce a new, livelier version optimised for a 5-minute slot with a clear commercialization next step. Use GSAP for animation. New file, not an edit of the original.

## What came back
- `docs/presentation/Sijil — Fish Tank pitch v2.html` (git-ignored with the rest of `docs/presentation/`). Single self-contained file: GSAP 3.12 from jsDelivr, Google Fonts (Inter, IBM Plex Mono), logo embedded as base64. `sijil-logo.png` saved alongside.
- 13 slides cut to 10: cover → hook → four questions → the gap → how it works → live demo → numbers → who pays → commercialization roadmap → the ask. "Where we stop", "Assurance unblocks adoption" and "Not solved yet" were folded into the market and roadmap slides rather than dropped.
- New commercialization slide: today (working product + partner brief) → 30 days (write the compliance section for one integrator bid, free) → 90 days (paid pilot on a FlowServe-operated stack) → 12 months (annual per-model licences + TEE/GPU attestation). The honest boundaries sit under it as a strip.
- Live-demo slide doubles as the fallback: → steps through `alter 17` / `restore` / `forge 17` / `restore` with a chain visualisation and the verifier bar reading exactly what the CLI prints.
- Presenter aids: 5-minute timer (amber at 4:00, red at 4:45; starts on leaving slide 1), speaker notes with target timestamps (N), fullscreen (F), URL hash per slide.
- Brand: `#FF4F00` from the logo, dark base, orange full-bleed for the ask.

## Verification
- Headless Chrome via Playwright at 1920×1080: every slide rendered after its animation, all four demo steps exercised, zero page or console errors. Layout fixes made from the screenshots (headline wrapping, chain overflow, market slide overflow).
- Numbers on the slides match `README.md` ("Measured"): p95 0.91 ms, ~770 bytes/record.

## What a human changed, and why
| Who | File | Change | Why |
| --- | --- | --- | --- |
| Shameer | | _pending review_ | |
