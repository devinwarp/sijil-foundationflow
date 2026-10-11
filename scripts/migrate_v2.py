#!/usr/bin/env python3
"""Upgrade a Sijil record store to schema v2 in place (spec §2.1 "Migration"). Idempotent.

    python scripts/migrate_v2.py sijill.db

Adds the seven v2 columns as TEXT NOT NULL DEFAULT ''. Existing rows get '' in each, which keeps
their hashes valid under the §2.2 omit-if-empty rule. Then creates the side tables and indexes.
Lives outside sijill/ because tests/test_claims.py forbids ALTER next to `records` there.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sijill.record import EXT_FIELDS  # noqa: E402
from sijill.store import SIDE_SCHEMA  # noqa: E402


def migrate(path: str) -> list[str]:
    """Add whichever v2 columns are missing; return their names (empty when already v2)."""
    if not Path(path).is_file():
        raise SystemExit(f"migrate_v2: no database at {path}")
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        have = {row[1] for row in conn.execute("PRAGMA table_info(records)")}
        if not have:
            raise SystemExit(f"migrate_v2: {path} has no records table")
        added = [f for f in EXT_FIELDS if f not in have]
        conn.execute("BEGIN IMMEDIATE")
        for f in added:
            conn.execute(f"ALTER TABLE records ADD COLUMN {f} TEXT NOT NULL DEFAULT ''")
        conn.execute("COMMIT")
        conn.executescript(SIDE_SCHEMA)
    finally:
        conn.close()
    return added


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: migrate_v2.py <database>", file=sys.stderr)
        return 2
    added = migrate(args[0])
    print(f"migrate_v2: added {len(added)} column(s)" + (f": {', '.join(added)}" if added else " (already v2)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
