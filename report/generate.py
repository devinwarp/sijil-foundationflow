#!/usr/bin/env python3
"""Generate the Sijill audit report (A4 PDF) for a date range.

    python report/generate.py --db sijill.db --pubkey node.pub --from 2026-09-25 --to 2026-09-25 --out report.pdf

Reads the record store read-only and runs the independent verifier as a
subprocess at generation time.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent / "verifier" / "sijill_verify.py"

# WeasyPrint dlopens pango/gobject by bare name; on macOS the Homebrew libraries
# are only found if the fallback path is set before the process starts.
if sys.platform == "darwin" and "DYLD_FALLBACK_LIBRARY_PATH" not in os.environ and Path("/opt/homebrew/lib").is_dir():
    os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = "/opt/homebrew/lib:/usr/local/lib:/usr/lib"
    os.execv(sys.executable, [sys.executable, *sys.argv])

from cryptography.hazmat.primitives import serialization  # noqa: E402
from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: E402


def bound(value: str | None, end: bool) -> str | None:
    """Accept YYYY-MM-DD (whole day) or a full ISO timestamp."""
    if not value:
        return None
    if len(value) == 10:
        return f"{value}T23:59:59.999Z" if end else f"{value}T00:00:00.000Z"
    return value


def pubkey_fingerprint(path: str) -> str:
    data = Path(path).read_bytes()
    if b"BEGIN PUBLIC KEY" in data:
        raw = serialization.load_pem_public_key(data).public_bytes(serialization.Encoding.Raw,
                                                                   serialization.PublicFormat.Raw)
    else:
        raw = bytes.fromhex(data.decode().strip())
    return hashlib.sha256(raw).hexdigest()


def collect(db: str, pubkey: str, ts_from: str | None, ts_to: str | None, entity: str) -> dict:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    first, last = conn.execute("SELECT MIN(ts), MAX(ts) FROM records").fetchone()
    ts_from = ts_from or first or "1970-01-01T00:00:00.000Z"
    ts_to = ts_to or last or ts_from
    recs = [dict(r) for r in conn.execute("SELECT * FROM records WHERE ts >= ? AND ts <= ? ORDER BY seq",
                                          (ts_from, ts_to))]
    head = conn.execute("SELECT seq, record_hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
    conn.close()

    v = subprocess.run([sys.executable, str(VERIFIER), "--db", db, "--pubkey", pubkey, "--plain"],
                       capture_output=True, text=True)
    calls = [r for r in recs if r["type"] == "inference"]
    decisions = Counter(r["decision"] for r in calls)

    policies: dict[tuple, dict] = {}
    for r in recs:
        key = (r["policy_id"], r["policy_hash"], r["approval_ref"])
        p = policies.setdefault(key, {"policy_id": key[0], "policy_hash": key[1], "approval_ref": key[2],
                                      "first": r["ts"], "last": r["ts"], "first_seq": r["seq"], "count": 0})
        p["last"], p["count"] = r["ts"], p["count"] + 1

    models = Counter((r["model_id"], r["model_digest"]) for r in calls)
    exceptions = [dict(r, rules=", ".join(json.loads(r["rule_hits"])) or "—") for r in calls
                  if r["decision"] in ("flag", "block")]
    changes = [r for r in recs if r["type"] == "policy_change"]
    generated = datetime.now(timezone.utc)
    report_id = hashlib.sha256(f"{ts_from}|{ts_to}|{head and head['record_hash']}|{generated.isoformat()}"
                               .encode()).hexdigest()[:10].upper()
    return {
        "entity": entity,
        "report_id": f"SJL-{report_id}",
        "generated": generated.strftime("%d %B %Y, %H:%M UTC"),
        "period_from": ts_from, "period_to": ts_to,
        "nodes": sorted({r["node_id"] for r in recs}),
        "regions": sorted({r["node_region"] for r in recs}),
        "totals": {"allow": decisions["allow"], "flag": decisions["flag"], "block": decisions["block"],
                   "calls": len(calls), "policy_changes": len(changes), "records": len(recs)},
        "policies": sorted(policies.values(), key=lambda p: p["first_seq"]),
        "models": [{"model_id": m or "—", "digest": d or "not located", "count": c} for (m, d), c in models.items()],
        "exceptions": exceptions,
        "verify_ok": v.returncode == 0,
        "verify_line": v.stdout.strip() or v.stderr.strip(),
        "pubkey_fingerprint": pubkey_fingerprint(pubkey),
        "head_seq": head["seq"] if head else 0,
        "head_hash": head["record_hash"] if head else "",
    }


def render(ctx: dict, out: str) -> None:
    from weasyprint import HTML

    env = Environment(loader=FileSystemLoader(HERE), autoescape=select_autoescape(["html"]))
    env.filters["day"] = lambda ts: datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%d %b %Y")
    env.filters["clock"] = lambda ts: ts[11:19]
    html = env.get_template("template.html").render(**ctx)
    HTML(string=html, base_url=str(HERE)).write_pdf(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the Sijill audit report PDF.")
    ap.add_argument("--db", default=os.environ.get("DATABASE_PATH", "sijill.db"))
    ap.add_argument("--pubkey", default=os.environ.get("NODE_PUBKEY_PATH", "node.pub"))
    ap.add_argument("--from", dest="ts_from", help="YYYY-MM-DD or ISO timestamp (default: first record)")
    ap.add_argument("--to", dest="ts_to", help="YYYY-MM-DD or ISO timestamp (default: last record)")
    ap.add_argument("--entity", default=os.environ.get("SIJILL_ENTITY", "Demonstration Government Entity"))
    ap.add_argument("--out", default="sijill-report.pdf")
    args = ap.parse_args()
    ctx = collect(args.db, args.pubkey, bound(args.ts_from, False), bound(args.ts_to, True), args.entity)
    render(ctx, args.out)
    print(f"report {ctx['report_id']}  records={ctx['totals']['records']}  {ctx['verify_line']}  -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
