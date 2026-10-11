"""Append-only SQLite access. This module only ever SELECTs and INSERTs (plus CREATE ... IF NOT EXISTS for the schema)."""

import sqlite3

from .record import EXT_FIELDS, FIELDS, GENESIS_HASH

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
    parent_seq TEXT NOT NULL DEFAULT '',
    source_label TEXT NOT NULL DEFAULT '',
    rulepack_hash TEXT NOT NULL DEFAULT '',
    ext TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    principal TEXT NOT NULL DEFAULT '',
    task_seq TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    signature TEXT NOT NULL
)
"""
# Side tables are rebuildable lookups, not evidence (spec §2.1, §5.4, §5.8.2). scripts/migrate_v2.py runs this too.
SIDE_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_use_index (tool_use_id TEXT PRIMARY KEY, seq INTEGER NOT NULL,
    name TEXT NOT NULL, args_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS principal_index (principal TEXT PRIMARY KEY, display TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_sessions (agent_session TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
    principal TEXT NOT NULL, agent_auth TEXT NOT NULL, principal_auth TEXT NOT NULL,
    remote_addr TEXT NOT NULL, expires_at TEXT NOT NULL, jti TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_records_task ON records(task_seq);
CREATE INDEX IF NOT EXISTS idx_records_agent ON records(agent_id);
"""
COLUMNS = ", ".join(FIELDS)


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA)
        have = {r["name"] for r in self.conn.execute("PRAGMA table_info(records)")}
        missing = [f for f in EXT_FIELDS if f not in have]
        if missing:
            self.conn.close()
            raise RuntimeError(f"{path}: record store predates schema v2 (missing {', '.join(missing)}); "
                               f"run: python scripts/migrate_v2.py {path}")
        self.conn.executescript(SIDE_SCHEMA)

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

    def after(self, seq: int, limit: int = 200) -> list[dict]:
        """Records with seq > `seq`, ascending; the OLDEST `limit` of them (lossless paging)."""
        rows = self.conn.execute(
            f"SELECT {COLUMNS} FROM records WHERE seq > ? ORDER BY seq LIMIT ?", (seq, limit)).fetchall()
        return [dict(r) for r in rows]

    def between(self, ts_from: str, ts_to: str) -> list[dict]:
        rows = self.conn.execute(
            f"SELECT {COLUMNS} FROM records WHERE ts >= ? AND ts <= ? ORDER BY seq", (ts_from, ts_to)).fetchall()
        return [dict(r) for r in rows]
