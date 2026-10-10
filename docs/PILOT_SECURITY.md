# Pilot security checklist

Each line is checked by a command or a test. Run before every pilot install.

| Control | Evidence |
| --- | --- |
| Admin endpoints need a token; disabled when unset | `pytest tests/test_admin_auth.py` |
| No key file in the image | Task 5 smoke: `no-key` |
| Signing key in the HSM, no file fallback | `pytest tests/test_hsm.py` (not skipped) |
| Runs as non-root, arbitrary UID | Task 5 smoke: `arbitrary-uid-ok` |
| Prompts and answers never stored, only hashed | `sijill/record.py` input_hash/output_hash; `tests/test_record.py` |
| Records append-only in application code | `pytest tests/test_claims.py` |
| Every streamed call sealed, including hang-ups | `pytest tests/test_streaming.py` |
| SOC receives blocks as CEF severity 8 | `pytest tests/test_siem.py`; manual `nc` check |
| Chain verifies offline with the Apache-2.0 verifier | `python verifier/sijill_verify.py --db ... --pubkey ...` |
| Operator can halt every call, halt survives restart | `pytest tests/test_halt.py` |

Known limits to state to the entity: read endpoints (`/api/records`, `/api/report`, dashboard) are not
authenticated in the pilot build; put them behind the entity's reverse proxy with SSO. The proxy host can
still seal false records (README "Honest boundaries"); HSM custody limits key theft, not a compromised host.
