#!/usr/bin/env python3
"""
Sijill verifier — standalone CLI.

Reimplements canonicalisation and verification from the Build Spec
(docs/README.md). Deliberately imports nothing from the `sijill/` package:
the thing that checks the records is not the thing that wrote them.

    python verifier/sijill_verify.py --db sijill.db --pubkey node.pub

Prints exactly one result line, `PASS records=N first=<ts> last=<ts>` or
`FAIL seq=N <reason>`. When stdout is a terminal it is preceded by a large
banner for projector display (disable with --plain). Exit 0 on pass, 1 on fail.
"""

import argparse
import json
import os
import sqlite3
import sys
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

FIELDS = (
    "seq", "type", "ts", "model_id", "model_digest", "node_id", "node_region",
    "policy_id", "policy_hash", "approval_ref", "mode", "decision", "rule_hits",
    "input_hash", "output_hash", "prev_hash", "record_hash", "signature",
)
GENESIS = "0" * 64

BANNER_FONT = {
    "P": ["█████ ", "██  ██", "█████ ", "██    ", "██    "],
    "A": [" ████ ", "██  ██", "██████", "██  ██", "██  ██"],
    "S": [" █████", "██    ", " ████ ", "    ██", "█████ "],
    "F": ["██████", "██    ", "█████ ", "██    ", "██    "],
    "I": ["██████", "  ██  ", "  ██  ", "  ██  ", "██████"],
    "L": ["██    ", "██    ", "██    ", "██    ", "██████"],
}


def canonical_bytes(record):
    """Every field except record_hash and signature, sorted keys, no whitespace, UTF-8."""
    obj = {k: v for k, v in record.items() if k not in ("record_hash", "signature")}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(record):
    return sha256(canonical_bytes(record)).hexdigest()


def signature_valid(public_key, record_hash_hex, signature_hex):
    try:
        public_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(record_hash_hex))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_public_key(path):
    """Accepts a PEM (SubjectPublicKeyInfo) file or a file holding the 32-byte key as hex."""
    with open(path, "rb") as f:
        data = f.read()
    if b"BEGIN PUBLIC KEY" in data:
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return key
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(data.decode().strip()))


def verify(db_path, pubkey_path):
    """Returns (ok, result_line). Walks records in seq order, stops at first failure."""
    if not os.path.exists(db_path):
        return False, f"FAIL database not found: {db_path}"
    try:
        public_key = load_public_key(pubkey_path)
    except (OSError, ValueError) as e:
        return False, f"FAIL public key unreadable: {e}"

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(f"SELECT {', '.join(FIELDS)} FROM records ORDER BY seq ASC")
        prev_seq, prev_hash, count, first_ts, last_ts = 0, GENESIS, 0, None, None
        for row in rows:
            record = dict(row)
            seq = record["seq"]
            if seq != prev_seq + 1:
                return False, f"FAIL seq={seq} gap"
            if record_hash(record) != record["record_hash"]:
                return False, f"FAIL seq={seq} content altered"
            if record["prev_hash"] != prev_hash:
                return False, f"FAIL seq={seq} chain broken"
            if not signature_valid(public_key, record["record_hash"], record["signature"]):
                return False, f"FAIL seq={seq} signature invalid"
            prev_seq, prev_hash = seq, record["record_hash"]
            count += 1
            first_ts = first_ts or record["ts"]
            last_ts = record["ts"]
    except sqlite3.Error as e:
        return False, f"FAIL database unreadable: {e}"
    finally:
        conn.close()
    return True, f"PASS records={count} first={first_ts or '-'} last={last_ts or '-'}"


def banner(word, ok):
    colour = "\033[1;32m" if ok else "\033[1;31m"
    rows = ["  ".join(BANNER_FONT[c][i] for c in word) for i in range(5)]
    return colour + "\n".join("  " + r for r in rows) + "\033[0m\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a Sijill record chain.")
    parser.add_argument("--db", required=True, help="path to the SQLite record store")
    parser.add_argument("--pubkey", required=True, help="Ed25519 public key (PEM or hex)")
    parser.add_argument("--plain", action="store_true", help="no banner, result line only")
    args = parser.parse_args(argv)

    ok, line = verify(args.db, args.pubkey)
    if sys.stdout.isatty() and not args.plain:
        colour = "\033[1;32m" if ok else "\033[1;31m"
        print("\n" + banner("PASS" if ok else "FAIL", ok))
        print(f"  {colour}{line}\033[0m\n")
    else:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
