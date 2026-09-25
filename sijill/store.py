"""Append-only SQLite access. This module only ever SELECTs and INSERTs."""

import sqlite3

from .record import FIELDS, GENESIS_HASH

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    ts TEXT NOT NULL,
    model_id TEXT NOT NULL,
    model_digest TEXT NOT NULL,
    node_id TEXT NOT NULL,
    node_region TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    approval_ref TEXT NOT NULL,
    mode TEXT NOT NULL,
    decision TEXT NOT NULL,
    rule_hits TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    output_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    signature TEXT NOT NULL
)
"""
COLUMNS = ", ".join(FIELDS)


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def head(self) -> tuple[int, str]:
        """(seq, record_hash) of the newest record, or (0, genesis) for an empty chain."""
        row = self.conn.execute("SELECT seq, record_hash FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return (row["seq"], row["record_hash"]) if row else (0, GENESIS_HASH)

    def last(self) -> dict | None:
        row = self.conn.execute(f"SELECT {COLUMNS} FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def append(self, record: dict) -> None:
        placeholders = ", ".join(f":{f}" for f in FIELDS)
        self.conn.execute(f"INSERT INTO records ({COLUMNS}) VALUES ({placeholders})", record)

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

    def since(self, seq: int, limit: int = 200) -> list[dict]:
        """Records with seq > `seq`, ascending; at most the newest `limit` of them."""
        rows = self.conn.execute(
            f"SELECT {COLUMNS} FROM records WHERE seq > ? ORDER BY seq DESC LIMIT ?", (seq, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def between(self, ts_from: str, ts_to: str) -> list[dict]:
        rows = self.conn.execute(
            f"SELECT {COLUMNS} FROM records WHERE ts >= ? AND ts <= ? ORDER BY seq", (ts_from, ts_to)).fetchall()
        return [dict(r) for r in rows]
