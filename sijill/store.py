"""Append-only SQLite access. This module only ever SELECTs and INSERTs
(plus CREATE ... IF NOT EXISTS for the schema).
"""

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

    def index_tool_uses(self, seq: int, uses: list[dict]) -> None:
        """tool_use_index rows for one sealed inference (spec §5.4: a lookup cache, rebuildable from ext)."""
        self.conn.executemany(
            "INSERT OR IGNORE INTO tool_use_index (tool_use_id, seq, name, args_hash) VALUES (?, ?, ?, ?)",
            [(u["id"], seq, u["name"], u["args_hash"]) for u in uses if u["id"]])

    def get(self, seq: int) -> dict | None:
        row = self.conn.execute(f"SELECT {COLUMNS} FROM records WHERE seq = ?", (seq,)).fetchone()
        return dict(row) if row else None

    def of_types(self, *types: str) -> list[dict]:
        rows = self.conn.execute(f"SELECT {COLUMNS} FROM records WHERE type IN ({', '.join('?' * len(types))}) "
                                 f"ORDER BY seq", types).fetchall()
        return [dict(r) for r in rows]

    def add_session(self, row: dict) -> None:
        """agent_sessions: side table, not evidence (spec §5.8.2)."""
        self.conn.execute("INSERT INTO agent_sessions (agent_session, agent_id, principal, agent_auth, "
                          "principal_auth, remote_addr, expires_at, jti) VALUES (:agent_session, :agent_id, "
                          ":principal, :agent_auth, :principal_auth, :remote_addr, :expires_at, :jti)", row)

    def jti_used(self, jti: str) -> bool:
        return self.conn.execute("SELECT 1 FROM agent_sessions WHERE jti = ?", (jti,)).fetchone() is not None

    def session(self, agent_session: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM agent_sessions WHERE agent_session = ?", (agent_session,)).fetchone()
        return dict(row) if row else None

    def open_tasks(self, agent_session: str | None = None) -> list[dict]:
        """task_start records with no task_end, optionally only those of one agent session."""
        sql = (f"SELECT {COLUMNS} FROM records r WHERE type = 'task_start' AND NOT EXISTS (SELECT 1 FROM records e "
               f"WHERE e.type = 'task_end' AND e.task_seq = CAST(r.seq AS TEXT))")
        if agent_session is None:
            return [dict(x) for x in self.conn.execute(sql + " ORDER BY seq")]
        return [dict(x) for x in self.conn.execute(
            sql + " AND json_extract(r.ext, '$.agent_session') = ? ORDER BY seq", (agent_session,))]

    def task_ended(self, task_seq: int) -> bool:
        return self.conn.execute("SELECT 1 FROM records WHERE type = 'task_end' AND task_seq = ?",
                                 (str(task_seq),)).fetchone() is not None

    def in_task(self, task_seq: int) -> list[dict]:
        rows = self.conn.execute("SELECT seq, type, decision, source_label, ext FROM records WHERE task_seq = ? "
                                 "ORDER BY seq",
                                 (str(task_seq),)).fetchall()
        return [dict(r) for r in rows]

    def has_child(self, type_: str, parent_seq: str) -> bool:
        return self.conn.execute("SELECT 1 FROM records WHERE type = ? AND parent_seq = ?",
                                 (type_, parent_seq)).fetchone() is not None

    def children(self, type_: str, parent_seq: str) -> list[dict]:
        rows = self.conn.execute("SELECT input_hash, ext FROM records WHERE type = ? AND parent_seq = ? ORDER BY seq",
                                 (type_, parent_seq)).fetchall()
        return [dict(r) for r in rows]

    def tool_use(self, task_seq: str, tool_use_id: str = "", name: str = "", args_hash: str = "") -> dict | None:
        """Newest tool_use_index entry of an inference in this task: by id, or by (name, args_hash) among
        entries no tool_call has consumed yet (spec §5.4 mechanisms 1 and 2)."""
        if tool_use_id:
            where, args = "i.tool_use_id = ?", (task_seq, tool_use_id)
        else:
            where = ("i.name = ? AND i.args_hash = ? AND NOT EXISTS (SELECT 1 FROM records c WHERE c.type = "
                     "'tool_call' AND c.parent_seq = CAST(i.seq AS TEXT) AND c.input_hash = i.args_hash)")
            args = (task_seq, name, args_hash)
        row = self.conn.execute("SELECT i.tool_use_id, i.seq, i.name, i.args_hash FROM tool_use_index i JOIN records r "
                                f"ON r.seq = i.seq WHERE r.task_seq = ? AND {where} ORDER BY i.seq DESC LIMIT 1",
                                args).fetchone()
        return dict(row) if row else None

    def token_in_force(self, task_seq: int) -> str | None:
        """token_hash of the principal_claims in force in a task: the newest record of it that carried them."""
        row = self.conn.execute(
            "SELECT json_extract(CASE ext WHEN '' THEN '{}' ELSE ext END, '$.principal_claims.token_hash') AS h "
            "FROM records WHERE (seq = ? OR task_seq = ?) AND h IS NOT NULL ORDER BY seq DESC LIMIT 1",
            (task_seq, str(task_seq))).fetchone()
        return row["h"] if row else None

    def index_principal(self, principal: str, display: str) -> None:
        """principal_index: display names for the report; side table, not evidence (spec §2.1)."""
        self.conn.execute("INSERT OR IGNORE INTO principal_index (principal, display) VALUES (?, ?)",
                          (principal, display))

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
