#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shameer Thaha
"""
Sijill verifier: standalone CLI. Record schema v2.

Reimplements canonicalisation and verification from the Build Spec (docs/README.md) and the
agent integration spec (§2.2 hashing, §4 checks). Deliberately imports nothing from the `sijill/`
package: the thing that checks the records is not the thing that wrote them.

    python verifier/sijill_verify.py --db sijill.db --pubkey node.pub [--json]
        [--allow-orphan-tool-calls] [--allow-unauthenticated-agents]

Prints exactly one result line, `PASS records=N first=<ts> last=<ts> attestation=... agent_auth=...`
or `FAIL seq=N <reason>`; with --json, one JSON object instead. When stdout is a terminal the line
is preceded by a large banner for projector display (disable with --plain). Exit 0 on pass, 1 on fail.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

FIELDS = (
    "seq", "type", "ts", "model_id", "model_digest", "node_id", "node_region",
    "policy_id", "policy_hash", "approval_ref", "mode", "decision", "rule_hits",
    "input_hash", "output_hash",
    "parent_seq", "source_label", "rulepack_hash", "ext",
    "agent_id", "principal", "task_seq",
    "prev_hash", "record_hash", "signature",
)
EXT_FIELDS = ("parent_seq", "source_label", "rulepack_hash", "ext", "agent_id", "principal", "task_seq")
TYPES = ("inference", "policy_change", "tool_call", "tool_result", "egress", "integrity_baseline",
         "integrity_drift", "rulepack_change", "agent_register", "agent_rotate", "agent_revoke", "task_start",
         "task_end", "scitt_receipt", "agent_identity_update", "approval")
GENESIS = "0" * 64
PARENT_TYPE = {"tool_call": "inference", "tool_result": "tool_call", "egress": "tool_call",
               "integrity_drift": "integrity_baseline"}
ATTESTATION = ("weights", "api", "api+tee", "none")
AGENT_AUTH = ("key", "mtls", "oidc", "relay", "none")
DECIMAL = re.compile(r"[1-9][0-9]*")
SOURCE_LABEL = re.compile(r"user|repo|telemetry|web|memory|mcp:[a-z0-9_-]{1,32}|http:[a-z0-9_-]{1,32}")
MODEL_DIGEST = re.compile(r"sha256:[0-9a-f]{64}|api:[a-z0-9-]+:\S+|")

BANNER_FONT = {
    "P": ["█████ ", "██  ██", "█████ ", "██    ", "██    "],
    "A": [" ████ ", "██  ██", "██████", "██  ██", "██  ██"],
    "S": [" █████", "██    ", " ████ ", "    ██", "█████ "],
    "F": ["██████", "██    ", "█████ ", "██    ", "██    "],
    "I": ["██████", "  ██  ", "  ██  ", "  ██  ", "██████"],
    "L": ["██    ", "██    ", "██    ", "██    ", "██████"],
}


class Fail(Exception):
    """A failed check: `code` is the stable --json token, `reason` the text after `FAIL seq=N`."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_bytes(record):
    """Every field except record_hash and signature, sorted keys, no whitespace, UTF-8; an empty
    v2 column (EXT_FIELDS) is left out, so a v1 record hashes exactly as before (spec §2.2)."""
    obj = {k: v for k, v in record.items() if k not in ("record_hash", "signature")}
    for f in EXT_FIELDS:
        if obj.get(f, "") == "":
            obj.pop(f, None)
    return canonical_json(obj)


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


def parse_ext(ext):
    """Check 6: "" or a JSON object whose canonical re-serialisation is the stored string."""
    if ext == "":
        return {}
    try:
        obj = json.loads(ext)
    except ValueError:
        obj = None
    if not isinstance(obj, dict) or canonical_json(obj).decode("utf-8") != ext:
        raise Fail("ext_not_canonical", "ext not canonical")
    return obj


class Seen:
    """What later checks need from a record that passed (spec §4.2 `seen`)."""
    __slots__ = ("type", "ext", "input_hash", "task_seq")

    def __init__(self, type_, ext, input_hash, task_seq):
        self.type, self.ext, self.input_hash, self.task_seq = type_, ext, input_hash, task_seq


class State:
    def __init__(self, allow_orphans=False, allow_unauthenticated=False):
        self.allow_orphans, self.allow_unauthenticated = allow_orphans, allow_unauthenticated
        self.seen = {}                  # seq -> Seen
        self.result_parents = set()     # B3: tool_call seqs that already have a tool_result
        self.rulepack, self.rulepack_seen = "", False
        self.attestation = dict.fromkeys(ATTESTATION, 0)
        self.agent_auth = dict.fromkeys(AGENT_AUTH, 0)
        self.orphans = self.unauthenticated = 0


def check_record(st, rec):
    """Checks 5-7 and A-G (spec §4.2) on one record that already passed the four chain checks."""
    seq, t = rec["seq"], rec["type"]
    if t not in TYPES:
        raise Fail("unknown_type", f"unknown type {t}")
    x = parse_ext(rec["ext"])
    p = rec["parent_seq"]
    if p and not DECIMAL.fullmatch(p):
        raise Fail("parent_seq_malformed", "parent_seq malformed")
    parent = None
    if p:
        if int(p) >= seq:
            raise Fail("parent_not_earlier", "parent not earlier")
        if int(p) not in st.seen:
            raise Fail("parent_missing", "parent missing")
        parent = st.seen[int(p)]
        want = PARENT_TYPE.get(t)
        if want and parent.type != want:
            raise Fail("parent_type", f"parent type {parent.type} expected {want}")
    elif t == "integrity_drift":
        raise Fail("parent_missing", "parent missing")
    if t == "tool_call" and parent is None:
        if x.get("correlation") != "none" or not st.allow_orphans:
            raise Fail("orphan_tool_call", "tool_call without parent inference")
        st.orphans += 1
    if t == "tool_call" and parent is not None:
        uses = parent.ext.get("tool_uses")
        if not any(isinstance(u, dict) and u.get("args_hash") == rec["input_hash"]
                   and ("tool_use_id" not in x or u.get("id") == x["tool_use_id"])
                   for u in (uses if isinstance(uses, list) else [])):
            raise Fail("args_not_requested", "tool_call args not requested by parent")
    if t == "tool_result" and parent is not None:
        if p in st.result_parents:
            raise Fail("duplicate_tool_result", f"duplicate tool_result for parent {p}")
        st.result_parents.add(p)
    if t == "integrity_drift" and rec["input_hash"] != parent.input_hash:
        raise Fail("drift_baseline_mismatch", "drift baseline mismatch")
    rp = rec["rulepack_hash"]
    if rp == "" and st.rulepack_seen:
        raise Fail("schema_downgrade", "schema downgrade")
    if t == "rulepack_change":
        if x.get("before") != st.rulepack or x.get("after") != rp:
            raise Fail("rulepack_change_mismatch", "rulepack_change before/after mismatch")
    elif rp != st.rulepack:
        raise Fail("rulepack_unsealed", "rulepack changed without rulepack_change")
    st.rulepack, st.rulepack_seen = rp, st.rulepack_seen or rp != ""
    label = rec["source_label"]
    if (label or t == "tool_result") and (t != "tool_result" or not SOURCE_LABEL.fullmatch(label)):
        raise Fail("source_label_invalid", "source_label invalid")
    if t == "inference":
        st.attestation[attestation(rec["model_digest"], x)] += 1
    st.seen[seq] = Seen(t, x, rec["input_hash"], rec["task_seq"])


def attestation(digest, x):
    """Check G and the §3.3 classification: weights | api | api+tee | none."""
    if not MODEL_DIGEST.fullmatch(digest):
        raise Fail("attestation_mismatch", "attestation mismatch")
    kind = "weights" if digest.startswith("sha256:") else "api" if digest else "none"
    claimed = x.get("attestation")
    allowed = {"weights": ("weights",), "api": ("api", "api+tee"), "none": ("none",)}[kind]
    if claimed is not None and claimed not in allowed:
        raise Fail("attestation_mismatch", "attestation mismatch")
    return "api+tee" if claimed == "api+tee" else kind


def counts(d):
    return ",".join(f"{k}:{v}" for k, v in d.items())


def verify_full(db_path, pubkey_path, allow_orphans=False, allow_unauthenticated=False):
    """Walk the chain in seq order, stop at the first failure. Returns the --json object."""
    st = State(allow_orphans, allow_unauthenticated)
    res = {"ok": False, "line": "", "seq": None, "code": None, "records": 0, "attestation": st.attestation,
           "agent_auth": st.agent_auth, "orphans": 0, "unauthenticated": 0, "agents": {}}

    def fail(seq, code, reason):
        res.update(seq=seq, code=code, line=f"FAIL seq={seq} {reason}" if seq is not None else f"FAIL {reason}",
                   orphans=st.orphans, unauthenticated=st.unauthenticated)
        return res

    if not os.path.exists(db_path):
        return fail(None, "database_not_found", f"database not found: {db_path}")
    try:
        public_key = load_public_key(pubkey_path)
    except (OSError, ValueError) as e:
        return fail(None, "public_key_unreadable", f"public key unreadable: {e}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        have = {r["name"] for r in conn.execute("PRAGMA table_info(records)")}
        if not have:
            return fail(None, "database_unreadable", "database unreadable: no records table")
        cols = [f for f in FIELDS if f in have]          # v1 (18) and v2.0 (22) stores: missing columns are ""
        rows = conn.execute(f"SELECT {', '.join(cols)} FROM records ORDER BY seq ASC")
        prev_seq, prev_hash, first_ts, last_ts = 0, GENESIS, None, None
        for row in rows:
            record = {**dict.fromkeys(FIELDS, ""), **dict(row)}
            seq = record["seq"]
            try:
                if seq != prev_seq + 1:
                    raise Fail("gap", "gap")
                if record_hash(record) != record["record_hash"]:
                    raise Fail("content_altered", "content altered")
                if record["prev_hash"] != prev_hash:
                    raise Fail("chain_broken", "chain broken")
                if not signature_valid(public_key, record["record_hash"], record["signature"]):
                    raise Fail("signature_invalid", "signature invalid")
                check_record(st, record)
            except Fail as f:
                return fail(seq, f.code, f.reason)
            prev_seq, prev_hash = seq, record["record_hash"]
            res["records"] += 1
            first_ts = first_ts or record["ts"]
            last_ts = record["ts"]
    except sqlite3.Error as e:
        return fail(None, "database_unreadable", f"database unreadable: {e}")
    finally:
        conn.close()
    line = (f"PASS records={res['records']} first={first_ts or '-'} last={last_ts or '-'} "
            f"attestation={counts(st.attestation)} agent_auth={counts(st.agent_auth)}")
    if allow_orphans and st.orphans:
        line += f" orphans={st.orphans}"
    if allow_unauthenticated and st.unauthenticated:
        line += f" unauthenticated={st.unauthenticated}"
    res.update(ok=True, line=line, orphans=st.orphans, unauthenticated=st.unauthenticated)
    return res


def verify(db_path, pubkey_path, **opts):
    """Returns (ok, result_line). Kept for backward-compatible callers; returns the result line only (no --json fields)."""
    res = verify_full(db_path, pubkey_path, **opts)
    return res["ok"], res["line"]


def banner(word, ok):
    colour = "\033[1;32m" if ok else "\033[1;31m"
    rows = ["  ".join(BANNER_FONT[c][i] for c in word) for i in range(5)]
    return colour + "\n".join("  " + r for r in rows) + "\033[0m\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify a Sijill record chain.")
    parser.add_argument("--db", required=True, help="path to the SQLite record store")
    parser.add_argument("--pubkey", required=True, help="Ed25519 public key (PEM or hex)")
    parser.add_argument("--plain", action="store_true", help="no banner, result line only")
    parser.add_argument("--json", action="store_true", help="print the result as one JSON object")
    parser.add_argument("--allow-orphan-tool-calls", action="store_true",
                        help="accept tool_call records with correlation=none and no parent (counted)")
    parser.add_argument("--allow-unauthenticated-agents", action="store_true",
                        help="accept tasks with agent_auth=none (counted)")
    args = parser.parse_args(argv)

    res = verify_full(args.db, args.pubkey, allow_orphans=args.allow_orphan_tool_calls,
                      allow_unauthenticated=args.allow_unauthenticated_agents)
    ok, line = res["ok"], res["line"]
    if args.json:
        print(json.dumps(res, sort_keys=True))
    elif sys.stdout.isatty() and not args.plain:
        colour = "\033[1;32m" if ok else "\033[1;31m"
        print("\n" + banner("PASS" if ok else "FAIL", ok))
        print(f"  {colour}{line}\033[0m\n")
    else:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
