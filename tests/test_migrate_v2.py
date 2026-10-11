"""scripts/migrate_v2.py and scripts/tamper.sh forge under schema v2 (spec §2.1 Migration, §2.2)."""

import json
import sqlite3
import subprocess
import sys

import vectors_v2
from conftest import ROOT, rows, sqlite, tamper
from sijill import record
from sijill.store import Store

MIGRATE = ROOT / "scripts" / "migrate_v2.py"
V1_COLUMNS = [f for f in record.FIELDS if f not in record.EXT_FIELDS]


def migrate(db) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(MIGRATE), str(db)], capture_output=True, text=True)


def make_v1_db(db, n=5) -> list[dict]:
    """An 18-column store holding n v1-shaped records sealed by record.py (as an M1 node wrote them)."""
    conn = sqlite3.connect(db)
    conn.execute(f"CREATE TABLE records (seq INTEGER PRIMARY KEY, {', '.join(c + ' TEXT NOT NULL' for c in V1_COLUMNS[1:])})")
    prev, out = record.GENESIS_HASH, []
    for seq in range(1, n + 1):
        body = {f: "" for f in record.BODY_FIELDS} | dict(
            type="inference", ts=f"2026-09-25T10:00:0{seq}.000Z", node_id="auh-node-01", node_region="AE-AZ",
            policy_id="gov-assistant", policy_hash="a" * 64, approval_ref="APR-0147", mode="record",
            decision="allow", rule_hits="[]", input_hash="b" * 64, output_hash="c" * 64)
        rec = record.seal(body, seq, prev, vectors_v2.NODE_KEY)
        conn.execute(f"INSERT INTO records ({', '.join(V1_COLUMNS)}) VALUES ({', '.join('?' * len(V1_COLUMNS))})",
                     [rec[c] for c in V1_COLUMNS])
        prev = rec["record_hash"]
        out.append(rec)
    conn.commit()
    conn.close()
    return out


def test_migrate_adds_seven_columns_and_keeps_hashes(tmp_path):
    db = tmp_path / "v1.db"
    sealed = make_v1_db(db)
    r = migrate(db)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ("migrate_v2: added 7 column(s): parent_seq, source_label, rulepack_hash, ext, "
                                "agent_id, principal, task_seq")
    after = rows(db)
    assert [a["record_hash"] for a in after] == [s["record_hash"] for s in sealed]
    assert all(record.compute_record_hash(a) == a["record_hash"] for a in after)
    assert all(a[f] == "" for a in after for f in record.EXT_FIELDS)
    Store(str(db)).close()                                   # no longer refused


def test_migrate_is_idempotent(tmp_path):
    db = tmp_path / "v1.db"
    make_v1_db(db)
    migrate(db)
    r = migrate(db)
    assert (r.returncode, r.stdout.strip()) == (0, "migrate_v2: added 0 column(s) (already v2)")


def test_migrate_refuses_missing_database(tmp_path):
    r = migrate(tmp_path / "nope.db")
    assert r.returncode != 0 and "no database" in r.stderr


def test_forge_recomputes_the_v2_canonical_hash(tmp_path):
    """tamper.sh forge must build the §2.2 canonical bytes with only sqlite3 and shasum."""
    db = tmp_path / "v2.db"
    store = Store(str(db))
    for k in (42, 74, 76):                                  # ext, parent_seq, source_label, principal set
        store.append(vectors_v2.out[k])
    store.close()
    tamper(db, "forge", "74")
    row = rows(db, "seq = 74")[0]
    assert row["record_hash"] != vectors_v2.out[74]["record_hash"]
    assert row["record_hash"] == record.compute_record_hash(row)


def test_restore_after_forge_on_v2_rows(tmp_path):
    db = tmp_path / "v2.db"
    store = Store(str(db))
    store.append(vectors_v2.out[42])
    store.close()
    tamper(db, "backup")
    tamper(db, "forge", "42")
    assert tamper(db, "restore") == "restore  1 record(s) returned to their sealed state"
    assert sqlite(db, "SELECT record_hash FROM records WHERE seq = 42;") == vectors_v2.out[42]["record_hash"]


def test_forge_matches_the_writer_on_non_ascii_ext(tmp_path):
    """Arabic text and escapes in ext: sqlite3's JSON and record.canonical_json must give the same bytes."""
    src = vectors_v2.out[42]
    ext = record.canonical_json({**json.loads(src["ext"]),
                                 "summary": {"arg_keys": ["رقم_القضية", 'quote"and\\slash', "tab\there"]}}).decode()
    body = {f: src[f] for f in record.BODY_FIELDS} | {"ext": ext}
    rec = record.seal(body, 42, src["prev_hash"], vectors_v2.NODE_KEY)
    db = tmp_path / "v2.db"
    store = Store(str(db))
    store.append(rec)
    store.close()
    tamper(db, "forge", "42")
    row = rows(db, "seq = 42")[0]
    assert row["record_hash"] == record.compute_record_hash(row) != rec["record_hash"]


def test_migrate_non_sqlite_file_exits_one_line(tmp_path):
    db = tmp_path / "junk.db"
    db.write_bytes(b"this is not a database" * 50)
    r = migrate(db)
    assert r.returncode != 0
    assert "Traceback" not in r.stderr and r.stderr.strip().count("\n") == 0
    assert "not a readable SQLite database" in r.stderr
