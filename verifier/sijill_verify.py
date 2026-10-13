#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shameer Thaha
"""
Sijill verifier: standalone CLI. Record schema v2.

Reimplements canonicalisation and verification from the Build Spec (docs/README.md) and the
agent integration spec (§2.2 hashing, §4 checks, §17.7 government checks). Deliberately imports nothing
from the `sijill/` package: the thing that checks the records is not the thing that wrote them.

    python verifier/sijill_verify.py --db sijill.db --pubkey node.pub [--json]
        [--allow-orphan-tool-calls] [--allow-unauthenticated-agents]
        [--token-dir DIR] [--jwks-dir DIR] [--min-principal-assurance low|substantial|high] [--rulepack FILE]

Prints exactly one result line, `PASS records=N first=<ts> last=<ts> attestation=... agent_auth=...`
or `FAIL seq=N <reason>`; with --json, one JSON object instead. When stdout is a terminal the line
is preceded by a large banner for projector display (disable with --plain). Exit 0 on pass, 1 on fail.
"""

import argparse
import base64
import fnmatch
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

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
AGENT_ID = re.compile(r"spiffe://[a-z0-9.-]+/agent/[a-z0-9._-]+")
PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:[^\s]+|email:[0-9a-f]{64}|local:[0-9a-f]{64}"
                       r"|human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
ID_SYNTAX = {"spiffe": r"spiffe://[a-z0-9.-]+/\S+", "wimse": r"wimse://[a-z0-9.-]+/\S+", "did": r"did:[a-z0-9]+:\S+",
             "entra": r"[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}", "cloud-native": r"\S{1,512}", "other": r"\S{1,512}"}
CONTINUITY = ("logical_agent_id", "responsible_entity", "lifecycle_class", "runtime_identities", "derived_from")
REGISTER_AUTH = {"key": ("key", "mtls"), "oidc": ("oidc",), "relay": ("relay",)}   # N: register auth -> agent_auth
TASK_COUNTS = ("inference", "tool_calls", "blocked", "confirmed", "denied", "flagged", "egress")
ASSURANCE = ("low", "substantial", "high")                         # §17.1 PRINCIPAL_ASSURANCE, in order
HUMAN = re.compile(r"human:([a-z0-9-]{1,32}):([0-9a-f]{64})")
CLAIMS_REQ = ("issuer_id", "profile", "validation", "iss", "aud", "tenant", "assurance", "assurance_rule",
              "delegated", "token_hash")
CLAIMS_JWT = ("kid", "alg", "jwks_hash", "nbf", "exp")
HEX64 = re.compile(r"[0-9a-f]{64}")
SEALED_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")           # the form record.now_ts() / oidc.ts_at() write
SKEW_MS = 60_000                      # the ledger's oidc.SKEW_S (60 s): it accepts a token whose nbf is that far ahead
REFUSAL_CODES = re.compile(r"missing|malformed|alg|issuer|kid|signature|audience|tenant|not_delegated|expired"
                           r"|not_yet_valid|jwks_stale|userinfo_unreachable|userinfo_[0-9]+|assurance|task_principal")
PRINCIPAL_KINDS = {"human": "human", "oidc": "workload", "local": "local", "email": "local"}   # Ruling: email is local
APPROVAL_REQUEST = ("tool", "server", "qualified", "correlation", "route_id", "approver_set", "min_assurance",
                    "timeout_ms", "on_timeout", "sod")
METRIC_TYPE = {"tool_calls": "tool_call", "tool_calls_by": "tool_call", "egress_hosts": "egress",
               "model_spend_micro": "inference"}
# FAIL codes M2d adds to the spec 17.7 list (spec-delta): approval_request_malformed, approval_decision_invalid,
# approval_after_deadline, approver_is_principal, approval_mismatch, approval_reused, approval_undecided,
# budget_counter_mismatch, budget_unenforced, budget_spurious_hit, budget_limit_not_in_pack, cost_mismatch,
# http_tool_call_malformed, after_the_fact_enforced, rulepack_unreadable, rule_hits_malformed, task_already_ended
APPROVAL_ID = re.compile(r"ap_[0-9A-Z]{26}")
HTTP_QUALIFIED = re.compile(r"http:[a-z0-9_-]{1,32}:\S(.*\S)?")   # Ruling: section 17.3.3 names carry a space

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
        if not isinstance(obj, dict) or canonical_json(obj).decode("utf-8") != ext:
            obj = None
    except (ValueError, RecursionError):                 # deeply nested JSON is not canonical either
        obj = None
    if obj is None:
        raise Fail("ext_not_canonical", "ext not canonical")
    return obj


class Seen:
    """What later checks need from a record that passed (spec §4.2 `seen`)."""
    __slots__ = ("type", "ext", "input_hash", "task_seq")

    def __init__(self, type_, ext, input_hash, task_seq):
        self.type, self.ext, self.input_hash, self.task_seq = type_, ext, input_hash, task_seq


class State:
    def __init__(self, allow_orphans=False, allow_unauthenticated=False, token_dir=None, jwks_dir=None,
                 min_assurance=None):
        self.allow_orphans, self.allow_unauthenticated = allow_orphans, allow_unauthenticated
        self.token_dir, self.jwks_dir, self.min_assurance = token_dir, jwks_dir, min_assurance
        self.principals = dict.fromkeys(("human", "workload", "local", "none"), 0)
        self.principal_tokens = dict.fromkeys(("verified", "unverified", "unverifiable"), 0)
        self.approvals = {}             # approval_id -> the request (V-V4)
        self.decisions = {}             # decision seq -> {request, outcome, used}
        self.approval_counts = dict.fromkeys(("granted", "refused", "timeout"), 0)
        self.budget_hits = self.after_the_fact = self.rulepack_matched = 0
        self.pack = None                # --rulepack: {hash, budgets, pricing} (W2)
        self.seen = {}                  # seq -> Seen
        self.result_parents = set()     # B3: tool_call seqs that already have a tool_result
        self.rulepack, self.rulepack_seen = "", False
        self.attestation = dict.fromkeys(ATTESTATION, 0)
        self.agent_auth = dict.fromkeys(AGENT_AUTH, 0)
        self.orphans = self.unauthenticated = 0
        self.agents = {}                # agent_id -> {registered_seq, current_pubkey, auth, revoked}
        self.tasks = {}                 # task_start seq -> {agent_id, principal, ended, counts, last_seq}
        self.declared = set()           # runtime identities declared by agent_register / agent_identity_update


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
    rule_hits(rec)
    pack_checks(st, rec, x)
    identity_checks(st, rec, x, parent)
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


def proof_valid(pubkey_hex, signature_hex, digest_hex):
    """Agent proofs (K, K2): Ed25519 over the 32 raw bytes of sha256(canonical_json(message))."""
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    except (ValueError, TypeError):
        return False
    return signature_valid(key, digest_hex, signature_hex)


def declare(st, identity):
    """Record a runtime identity whose identifier matches its scheme's syntax (I2, spec §2.4.12)."""
    if isinstance(identity, dict) and isinstance(identity.get("identifier"), str):
        syntax = ID_SYNTAX.get(identity.get("scheme"))
        if syntax and re.fullmatch(syntax, identity["identifier"]):
            st.declared.add(identity["identifier"])


def registered(st, agent_id):
    a = st.agents.get(agent_id)
    if a is None:
        raise Fail("agent_not_registered", "agent not registered")
    if a["revoked"]:
        raise Fail("agent_revoked", "agent revoked")
    return a


def identity_checks(st, rec, x, parent):
    """Checks H-N (spec §4.2): tasks, identity columns, the agent registry and its offline proofs."""
    seq, t, task_seq = rec["seq"], rec["type"], rec["task_seq"]
    aid, principal = rec["agent_id"], rec["principal"]
    task = None
    if task_seq:                                                                       # H
        if not DECIMAL.fullmatch(task_seq):
            raise Fail("task_missing", "task missing")
        n = int(task_seq)
        if n >= seq:
            raise Fail("task_not_earlier", "task not earlier")
        if n not in st.seen:
            raise Fail("task_missing", "task missing")
        if st.seen[n].type != "task_start":
            raise Fail("task_type", f"task type {st.seen[n].type} expected task_start")
        task = st.tasks[n]
    if not task_seq and t in ("tool_call", "tool_result", "egress"):                 # H2
        raise Fail("record_outside_task", "record outside task")
    if not task_seq and t == "task_end":                                              # L, its own wording
        raise Fail("task_end_without_task_start", "task_end without task_start")
    if task_seq and (t in ("task_start", "policy_change", "rulepack_change") or t.startswith("agent_")):
        raise Fail("task_seq_not_allowed", f"task_seq not allowed on {t}")
    if task is not None and task["ended"] and t != "task_end":
        raise Fail("task_already_ended", "record in an ended task")
    if parent is not None and t != "integrity_drift" and parent.task_seq != task_seq:  # H3
        raise Fail("parent_in_different_task", "parent in different task")
    if task is not None:                                                              # I
        if aid != task["agent_id"]:
            raise Fail("agent_id_differs", "agent_id differs from task")
        if principal != task["principal"]:
            raise Fail("principal_differs", "principal differs from task")
    own = x.get("runtime_identities") if t == "agent_register" else None
    if own and isinstance(own, list):
        for identity in own:
            declare(st, identity)
    if aid and not (AGENT_ID.fullmatch(aid) or aid in st.declared):                   # I2
        raise Fail("agent_id_malformed", "agent_id malformed")
    if principal and not PRINCIPAL.fullmatch(principal):
        raise Fail("principal_malformed", "principal malformed")
    if t in ("task_start", "inference"):
        principal_checks(st, rec, x, task)
    approval_checks(st, rec, x, parent, task)
    if task is not None:
        budget_checks(st, rec, x, task)
    if t == "task_start":
        start_task(st, rec, x)
    elif t == "agent_register":
        register_agent(st, rec, x)
    elif t == "agent_rotate":                                                         # K2
        a = registered(st, aid)
        if a["auth"] != "key" or x.get("old_pubkey") != a["current_pubkey"]:
            raise Fail("rotation_key_mismatch", "rotation key mismatch")
        msg = {"agent_id": aid, "new_pubkey": x.get("new_pubkey"), "nonce": x.get("nonce"),
               "old_pubkey": x.get("old_pubkey")}
        digest = sha256(canonical_json(msg)).hexdigest()
        if (None in msg.values() or digest != rec["input_hash"]
                or not proof_valid(msg["old_pubkey"], str(x.get("proof_old", "")), digest)
                or not proof_valid(msg["new_pubkey"], str(x.get("proof_new", "")), digest)):
            raise Fail("agent_rotation_proof_invalid", "agent rotation proof invalid")
        a["current_pubkey"] = msg["new_pubkey"]
    elif t == "agent_revoke":                                                         # K3
        a = st.agents.get(aid)
        if a is None:
            raise Fail("agent_not_registered", "agent not registered")
        if a["revoked"]:
            raise Fail("agent_already_revoked", "agent already revoked")
        if x.get("pubkey") != a["current_pubkey"]:
            raise Fail("revoke_key_mismatch", "revoke key mismatch")
        a["revoked"] = True
    elif t == "agent_identity_update" and x.get("action") == "add":                  # S1 itself: a later row
        declare(st, x.get("runtime_identity"))
    elif t == "task_end":                                                             # L, L2
        if task["ended"]:
            raise Fail("duplicate_task_end", "duplicate task_end")
        want = {**task["counts"], "last_seq": task["last_seq"]}
        if {k: x.get(k) for k in want} != want:
            raise Fail("task_end_counts_mismatch", "task_end counts mismatch")
        task["ended"] = True
    if task is not None and t != "task_end":
        c, decision = task["counts"], rec["decision"]
        confirmation = x.get("confirmation") if t == "tool_call" else None
        c["inference"] += t == "inference"
        c["tool_calls"] += t == "tool_call"
        c["blocked"] += decision == "block"
        c["flagged"] += decision == "flag"
        c["egress"] += t == "egress"
        c["confirmed"] += confirmation == "granted"
        c["denied"] += confirmation in ("denied", "unavailable")
        task["last_seq"] = seq


def start_task(st, rec, x):
    """N (enum, none), J, N (consistency with the registration), M; then open the task."""
    seq, auth = rec["seq"], x.get("agent_auth")
    if auth not in AGENT_AUTH or x.get("principal_auth") not in ("oidc", "key", "none"):
        raise Fail("unauthenticated_agent", "unauthenticated agent")
    if auth == "none":
        if not st.allow_unauthenticated:
            raise Fail("unauthenticated_agent", "unauthenticated agent")
        st.unauthenticated += 1
    else:
        a = registered(st, rec["agent_id"])
        if auth not in REGISTER_AUTH[a["auth"]]:
            raise Fail("agent_auth_inconsistent", "agent_auth inconsistent with registration")
    d = x.get("delegated_from", "")
    if d and not (isinstance(d, str) and DECIMAL.fullmatch(d) and int(d) < seq
                  and getattr(st.seen.get(int(d)), "type", None) == "task_start"):
        raise Fail("delegated_from_missing", "delegated_from missing")
    st.agent_auth[auth] += 1
    st.principals[PRINCIPAL_KINDS.get(rec["principal"].split(":", 1)[0], "none")] += 1
    st.tasks[seq] = {"agent_id": rec["agent_id"], "principal": rec["principal"], "ended": False,
                     "counts": dict.fromkeys(TASK_COUNTS, 0), "last_seq": seq, "claims": x.get("principal_claims"),
                     "pending": set(), "calls": [], "hosts": set(), "spend": 0}


def ms_of(t):
    """Epoch milliseconds of a sealed timestamp, None when it is not in the sealed form."""
    if not isinstance(t, str) or not SEALED_TS.fullmatch(t):
        return None
    try:
        return int(datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()) * 1000 \
            + int(t[20:23])
    except ValueError:
        return None


def claims_ok(c):
    """U: every §17.2.5 key, the jwt keys when validation is jwt, enums in range, value types as sealed."""
    if not (isinstance(c, dict) and all(k in c for k in CLAIMS_REQ)):
        return False
    if not (c["profile"] in ("entra", "uaepass", "oidc") and c["validation"] in ("jwt", "userinfo")
            and c["assurance"] in ASSURANCE):
        return False
    if not (all(isinstance(c[k], str) for k in ("issuer_id", "iss", "aud", "tenant")) and isinstance(c["delegated"], bool)
            and isinstance(c["token_hash"], str) and HEX64.fullmatch(c["token_hash"])):
        return False
    if c["validation"] != "jwt":
        return True
    return (all(k in c for k in CLAIMS_JWT) and isinstance(c["kid"], str) and isinstance(c["alg"], str)
            and isinstance(c["jwks_hash"], str) and bool(HEX64.fullmatch(c["jwks_hash"]))
            and ms_of(c["nbf"]) is not None and ms_of(c["exp"]) is not None)


def principal_checks(st, rec, x, task):
    """U-U3 (spec §17.7) on a task_start or an inference: claims shape and issuer, the token lifetime at ts,
    the customer-kept token when --token-dir is given, and the assurance floor."""
    principal, claims = rec["principal"], x.get("principal_claims")
    human = HUMAN.fullmatch(principal)
    # Ruling: only a sealed refusal (§17.2.7: a blocked inference outside any task, with a known code and no
    # claims) skips the claims requirement and the lifetime check.
    refusal = (rec["type"] == "inference" and rec["decision"] == "block" and task is None and claims is None
               and isinstance(x.get("principal_error"), str) and bool(REFUSAL_CODES.fullmatch(x["principal_error"])))
    if claims is not None and not claims_ok(claims):
        raise Fail("principal_claims_malformed", "principal claims malformed")
    if human and claims is None and not refusal and (rec["type"] == "task_start" or task is None):
        raise Fail("principal_claims_malformed", "principal claims malformed")
    if claims is not None and human and claims["issuer_id"] != human.group(1):
        raise Fail("principal_claims_malformed", "principal claims malformed")
    if rec["type"] == "task_start" and claims is not None and x.get("principal_auth") != "oidc":
        raise Fail("principal_claims_malformed", "principal claims malformed")
    if task is not None and claims is not None:                                       # U1, issuer
        if task["claims"] is None or claims["issuer_id"] != task["claims"]["issuer_id"]:
            raise Fail("principal_claims_malformed", "principal claims malformed")
        task["claims"] = claims
    in_force = claims if claims is not None else (task or {}).get("claims")
    if in_force is not None and in_force["validation"] == "jwt" and not refusal:      # U1, lifetime
        ts = ms_of(rec["ts"])
        if ts is None or not ms_of(in_force["nbf"]) <= ts + SKEW_MS or not ts < ms_of(in_force["exp"]):
            raise Fail("principal_token_not_valid", "principal token not valid at ts")
    if claims is not None:
        token_check(st, principal, claims)                                            # U2
    if (rec["type"] == "task_start" and human and st.min_assurance and claims is not None      # U3
            and ASSURANCE.index(claims["assurance"]) < ASSURANCE.index(st.min_assurance)):
        raise Fail("principal_assurance_low", f"principal assurance below {st.min_assurance}")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ts_of(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def jws_valid(token, kid, alg, jwks):
    """The compact JWS verifies under the JWKS key named kid, with alg EdDSA or RS256."""
    parts = token.split(".")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if len(parts) != 3 or not isinstance(keys, list):
        return False
    head, body, sig = parts
    key = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if key and (key.get("use", "sig") != "sig" or key.get("alg", alg) != alg):
        return False
    try:
        if alg == "EdDSA" and key and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(b64d(key["x"])).verify(b64d(sig), f"{head}.{body}".encode())
        elif alg == "RS256" and key and key.get("kty") == "RSA":
            n, e = (int.from_bytes(b64d(key[k]), "big") for k in ("n", "e"))
            if n.bit_length() < 2048:
                return False
            rsa.RSAPublicNumbers(e, n).public_key().verify(b64d(sig), f"{head}.{body}".encode(),
                                                            padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def token_check(st, principal, c):
    """U2: with --token-dir, the kept token is the sealed one, verifies under the kept JWKS, and its claims are
    the sealed claims and the principal. A token not kept is unverified; userinfo tokens are unverifiable."""
    if c["validation"] != "jwt":
        st.principal_tokens["unverifiable"] += 1
        return
    path = os.path.join(st.token_dir or "", c["token_hash"] + ".jwt")
    if not st.token_dir or not os.path.exists(path):
        st.principal_tokens["unverified"] += 1
        return
    mismatch = Fail("principal_token_mismatch", "principal token mismatch")
    try:
        with open(path, "rb") as f:
            raw = f.read()
        with open(os.path.join(st.jwks_dir or st.token_dir, c["jwks_hash"] + ".json"), "rb") as f:
            jwks_raw = f.read()
        token = raw.decode()
        head, payload = (json.loads(b64d(p)) for p in token.split(".")[:2])
        jwks = json.loads(jwks_raw)
        if not (isinstance(head, dict) and isinstance(payload, dict) and isinstance(jwks, dict)):
            raise mismatch
    except (OSError, ValueError, RecursionError):        # UnicodeDecodeError and binascii.Error are ValueErrors
        raise mismatch
    if (sha256(raw).hexdigest() != c["token_hash"] or sha256(jwks_raw).hexdigest() != c["jwks_hash"]
            or head.get("kid") != c["kid"] or head.get("alg") != c["alg"]
            or not jws_valid(token, c["kid"], c["alg"], jwks)):
        raise mismatch
    aud = payload.get("aud")
    subject = payload.get("oid" if c["profile"] == "entra" else "sub")     # Ruling: the default subject_claim
    try:
        times = ts_of(payload.get("nbf", payload.get("iat"))) == c["nbf"] and ts_of(payload["exp"]) == c["exp"]
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        times = False
    human = HUMAN.fullmatch(principal)
    if (payload.get("iss") != c["iss"] or not (aud == c["aud"] or (isinstance(aud, list) and c["aud"] in aud))
            or (c["profile"] == "entra" and payload.get("tid") != c["tenant"]) or not times or not human
            or sha256(canonical_json({"iss": payload.get("iss"), "sub": subject})).hexdigest() != human.group(2)):
        raise mismatch
    st.principal_tokens["verified"] += 1


def rule_hits(rec):
    """The record's rule_hits as a list of strings; anything else is a FAIL (sijill/record.py refuses it too)."""
    try:
        hits = json.loads(rec["rule_hits"])
    except (ValueError, RecursionError):
        hits = None
    if not (isinstance(hits, list) and all(isinstance(h, str) for h in hits)):
        raise Fail("rule_hits_malformed", "rule_hits malformed")
    return hits


def pack_checks(st, rec, x):
    """W2 cost on any inference, in a task or not: under the pack's hash, whether a model is priced is the
    pack's word; a priced, forwarded inference carries the pack's price_rule and the cost it gives, an unpriced
    one carries neither."""
    if rec["type"] != "inference":
        return
    if "cost_micro" in x and (type(x["cost_micro"]) is not int or x["cost_micro"] < 0):
        raise Fail("cost_mismatch", "cost mismatch")
    if st.pack and rec["rulepack_hash"] == st.pack["hash"]:
        st.rulepack_matched += 1
        digest = rec["model_digest"]
        price = next((p for p in st.pack["pricing"] if fnmatch.fnmatchcase(digest, str(p.get("model")))), None)
        carried = any(k in x for k in ("price_rule", "cost_micro"))
        if price is None:                       # the pack does not price this model: the record claims no price
            ok = not carried
        elif rec["decision"] == "block" and not carried:     # blocked before the forward: nothing was priced
            ok = True
        else:
            want = cost(st.pack, digest, x)
            ok = x.get("price_rule") == price.get("id") and want is not None and x.get("cost_micro") == want
        if not ok:
            raise Fail("cost_mismatch", "cost mismatch")


def approval_checks(st, rec, x, parent, task):
    """V-V4 (spec §17.7): named approval requests and decisions, the tool_call that cites one, none left open."""
    t, seq = rec["type"], rec["seq"]
    if t == "approval" and x.get("phase") == "decision":
        approval_decision(st, rec, x)
    elif t == "approval":                                                              # V
        aid, at = x.get("approval_id"), ms_of(rec["ts"])
        ok = (task is not None and at is not None and x.get("phase") == "request"
              and all(k in x for k in APPROVAL_REQUEST) and isinstance(aid, str) and aid not in st.approvals
              and APPROVAL_ID.fullmatch(aid) and (rec["mode"], rec["decision"]) == ("record", "flag")
              and type(x["timeout_ms"]) is int and x["timeout_ms"] > 0 and x["on_timeout"] == "deny"
              and x["min_assurance"] in ASSURANCE)
        if parent is None:
            ok = ok and x.get("correlation") == "none" and st.allow_orphans
        else:
            ok = ok and parent.type == "inference"
        if not ok:
            raise Fail("approval_request_malformed", "approval request malformed")
        st.approvals[aid] = {"seq": seq, "task": rec["task_seq"], "qualified": x["qualified"],
                             "input_hash": rec["input_hash"], "deadline": at + x["timeout_ms"],
                             "min_assurance": x["min_assurance"], "sod": x["sod"] is True, "decided": None}
        task["pending"].add(aid)
    elif t == "tool_call" and "approval_seq" in x:                                    # V2, V3
        d = st.decisions.get(x["approval_seq"]) if type(x["approval_seq"]) is int else None
        granted = d is not None and d["outcome"] == "granted"
        if (d is None or d["request"]["task"] != rec["task_seq"] or d["request"]["qualified"] != x.get("qualified")
                or d["request"]["input_hash"] != rec["input_hash"] or (x.get("confirmation") == "granted") != granted
                or (rec["decision"], rec["mode"]) != (("flag", "record") if granted else ("block", "enforce"))):
            raise Fail("approval_mismatch", "tool_call approval mismatch")
        if d["used"]:
            raise Fail("approval_reused", "approval reused")
        d["used"] = True
    elif (t == "tool_call" and st.pack and rec["rulepack_hash"] == st.pack["hash"] and st.pack["entra"]   # V2
          and rec["decision"] != "block" and x.get("after_the_fact") is not True
          and (x.get("confirmation") == "granted" or any(confirm_hit(st.pack, h) for h in rule_hits(rec)))):
        raise Fail("approval_mismatch", "tool_call approval mismatch")      # a confirm hit let through uncited
    elif t == "task_end" and task is not None and task["pending"]:                    # V4
        raise Fail("approval_undecided", "approval undecided at task_end")


def confirm_hit(pack, h):
    """A hit a named approver answers: a confirm rule of the pack, or an excess of one of its confirm budgets."""
    return h in pack["confirm"] or (h.startswith("budget:") and h.split(":")[1] in pack["confirm_budgets"])


def approval_decision(st, rec, x):
    """V1: the decision answers its own request, once, in time, by a well-formed approver who may answer."""
    aid, outcome, at = x.get("approval_id"), x.get("outcome"), ms_of(rec["ts"])
    req = st.approvals.get(aid) if isinstance(aid, str) else None
    invalid = Fail("approval_decision_invalid", "approval decision invalid")
    if (req is None or at is None or req["decided"] is not None or rec["parent_seq"] != str(req["seq"])
            or rec["task_seq"] != req["task"] or rec["input_hash"] != req["input_hash"]
            or (rec["mode"], rec["decision"]) != (("record", "allow") if outcome == "granted" else ("enforce", "block"))):
        raise invalid
    if outcome in ("granted", "refused"):
        if at >= req["deadline"]:
            raise Fail("approval_after_deadline", "approval after deadline")
        claims = x.get("approver_claims")
        if not (isinstance(x.get("approver"), str) and HUMAN.fullmatch(x["approver"]) and isinstance(claims, dict)
                and claims.get("assurance") in ASSURANCE
                and ASSURANCE.index(claims["assurance"]) >= ASSURANCE.index(req["min_assurance"])):
            raise invalid
        if req["sod"] and x["approver"] == rec["principal"]:
            raise Fail("approver_is_principal", "approver is task principal")
    elif outcome != "timeout" or at < req["deadline"] or "approver" in x:
        raise invalid
    req["decided"] = rec["seq"]
    st.decisions[rec["seq"]] = {"request": req, "outcome": outcome, "used": False}
    st.approval_counts[outcome] += 1
    st.tasks[int(rec["task_seq"])]["pending"].discard(x["approval_id"])


def budget_checks(st, rec, x, task):
    """X, X1 and W-W2 (spec §17.6, §17.7) on a record inside a task; then this record's own contribution to the
    task's counters, which the next record's `used` must equal."""
    t, hits = rec["type"], rule_hits(rec)
    if t == "tool_call" and x.get("observed_by") == "http_adapter":                  # X
        summary = x.get("summary")
        if not (HTTP_QUALIFIED.fullmatch(str(x.get("qualified"))) and isinstance(summary, dict)
                and all(k in summary for k in ("method", "host", "path_template"))):
            raise Fail("http_tool_call_malformed", "http tool_call malformed")
    if t == "tool_call" and x.get("after_the_fact") is True:                          # X1
        if rec["mode"] != "record" or rec["decision"] == "block":
            raise Fail("after_the_fact_enforced", "after-the-fact tool_call claims enforcement")
        st.after_the_fact += 1
    budget, failed = x.get("budget") if t in METRIC_TYPE.values() else None, set()
    if budget is not None and not isinstance(budget, dict):
        raise Fail("budget_counter_mismatch", "budget counter mismatch")
    for bid, metrics in (budget or {}).items():
        for metric, v in (metrics.items() if isinstance(metrics, dict) else [(None, None)]):
            limit, used = (v.get("limit"), v.get("used")) if isinstance(v, dict) else (None, None)
            kind = "tool_calls_by" if str(metric).startswith("tool_calls_by:") else metric
            if (type(limit) is not int or type(used) is not int or not isinstance(metric, str)
                    or METRIC_TYPE.get(kind) != t or used != own_count(task, metric)):
                raise Fail("budget_counter_mismatch", "budget counter mismatch")             # W
            if metric == "egress_hosts" and isinstance(x.get("host"), str) and x["host"].lower() in task["hosts"]:
                admitted = True
            else:
                admitted = used < limit if metric == "model_spend_micro" else used + 1 <= limit
            hit = f"budget:{bid}:{metric}"
            if not admitted:                                                          # W1
                d = st.decisions.get(x["approval_seq"]) if type(x.get("approval_seq")) is int else None
                granted = d is not None and d["outcome"] == "granted"
                if hit not in hits or not (rec["decision"] == "block" or granted):
                    raise Fail("budget_unenforced", "budget exceeded without enforcement")
                failed.add(hit)
            if st.pack and rec["rulepack_hash"] == st.pack["hash"] and pack_limit(st.pack, bid, metric) != limit:
                raise Fail("budget_limit_not_in_pack", "budget limit not in rule pack")      # W2
    if t != "approval" and any(h.startswith("budget:") and h not in failed for h in hits):
        raise Fail("budget_spurious_hit", "budget hit without excess")    # an approval request names its hits
    st.budget_hits += bool(failed)
    if t == "tool_call" and rec["decision"] != "block":
        task["calls"].append(str(x.get("qualified", "")))
    elif t == "egress" and rec["decision"] != "block" and isinstance(x.get("host"), str):
        task["hosts"].add(x["host"].lower())
    elif t == "inference" and type(x.get("cost_micro")) is int:
        task["spend"] += x["cost_micro"]


def own_count(task, metric):
    """The verifier's own value of a budget metric over the task's earlier records (§17.6.2)."""
    # ponytail: recounts the task's calls per record, O(n^2) per task; keep running counters per glob if tasks grow
    if metric == "tool_calls":
        return len(task["calls"])
    if metric.startswith("tool_calls_by:"):
        return sum(fnmatch.fnmatchcase(q, metric.split(":", 1)[1]) for q in task["calls"])
    return len(task["hosts"]) if metric == "egress_hosts" else task["spend"]


def pack_limit(pack, bid, metric):
    limits = pack["budgets"].get(bid, {})
    if metric.startswith("tool_calls_by:"):
        by = limits.get("tool_calls_by")
        return by.get(metric.split(":", 1)[1]) if isinstance(by, dict) else None
    return limits.get(metric)


def cost(pack, digest, x):
    """cost_micro from usage and the first pricing entry whose model glob matches the digest (§17.6.2)."""
    price = next((p for p in pack["pricing"] if fnmatch.fnmatchcase(digest, str(p.get("model")))), None)
    if price is None or price.get("id") != x.get("price_rule"):
        return None
    u = x.get("usage")
    if not isinstance(u, dict):
        return price.get("missing_usage_cost_micro")
    n = (u.get("input_tokens", 0), price.get("input_per_mtok_micro", 0),
         u.get("output_tokens", 0), price.get("output_per_mtok_micro", 0))
    if any(type(v) is not int or v < 0 for v in n):
        return None
    return (n[0] * n[1] + n[2] * n[3]) // 1_000_000


def load_pack(path):
    """--rulepack: the budgets, pricing and confirm hits of a rule pack file, keyed by the SHA-256 of its bytes
    (W2, and V2's uncited confirm hit under an entra channel). PyYAML is
    read only here (Ruling: the pack is YAML; the verifier's other checks need nothing beyond `cryptography`)."""
    import yaml
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = yaml.safe_load(raw) or {}
    except (yaml.YAMLError, RecursionError) as e:
        raise ValueError(f"not YAML: {type(e).__name__}") from None
    if not isinstance(doc, dict):
        raise ValueError("not a mapping")
    listed = lambda key: [e for e in doc.get(key) or [] if isinstance(e, dict)] if isinstance(doc.get(key), list) else []
    hitl = doc.get("hitl") if isinstance(doc.get("hitl"), dict) else {}
    return {"hash": sha256(raw).hexdigest(), "pricing": listed("pricing"),
            "budgets": {b["id"]: b["limits"] if isinstance(b.get("limits"), dict) else {}
                        for b in listed("budgets") if isinstance(b.get("id"), str)},
            "entra": hitl.get("channel") == "entra",
            "confirm": {r["id"] for r in listed("rules") if isinstance(r.get("id"), str) and r.get("action") == "confirm"},
            "confirm_budgets": {b["id"] for b in listed("budgets")
                                if isinstance(b.get("id"), str) and b.get("on_exceed") == "confirm"}}


def register_agent(st, rec, x):
    """K: structure per auth, and for auth=key the self-proof over the v2.1 or v2.2 message."""
    seq, aid, auth = rec["seq"], rec["agent_id"], x.get("auth")
    if aid in st.agents:
        raise Fail("agent_already_registered", "agent already registered")
    if auth == "key":
        msg = {"agent_id": aid, "agent_pubkey": x.get("agent_pubkey"), "nonce": x.get("nonce"),
               "registered_by": x.get("registered_by")}
        msg.update({k: x[k] for k in CONTINUITY if k in x})              # v2.2 form when present (§2.4.7)
        if None in msg.values() or not isinstance(x.get("self_proof"), str):
            raise Fail("agent_register_malformed", "agent register malformed")
        digest = sha256(canonical_json(msg)).hexdigest()
        if digest != rec["input_hash"] or not proof_valid(msg["agent_pubkey"], x["self_proof"], digest):
            raise Fail("agent_self_proof_invalid", "agent self-proof invalid")
        key = msg["agent_pubkey"]
    elif auth in ("oidc", "relay"):
        binding, keys = (x.get("oidc_binding"), ("issuer", "sub_pattern")) if auth == "oidc" else \
            (x.get("relay_binding"), ("platform", "endpoint_host", "agent_name"))
        if not isinstance(binding, dict) or not all(binding.get(k) for k in keys) or "agent_pubkey" in x:
            raise Fail("agent_register_malformed", "agent register malformed")
        key = ""
    else:
        raise Fail("agent_register_malformed", "agent register malformed")
    st.agents[aid] = {"registered_seq": seq, "current_pubkey": key, "auth": auth, "revoked": False}


def counts(d):
    return ",".join(f"{k}:{v}" for k, v in d.items())


def read_rows(conn):
    """Lazy iterator of records in seq order as full-width FIELDS dicts (v1 and v2.0 stores: missing
    columns are ""). None when the database has no records table."""
    have = {r["name"] for r in conn.execute("PRAGMA table_info(records)")}
    if not have:
        return None
    cols = [f for f in FIELDS if f in have]
    return ({**dict.fromkeys(FIELDS, ""), **dict(row)}
            for row in conn.execute(f"SELECT {', '.join(cols)} FROM records ORDER BY seq ASC"))


def verify_full(db_path, pubkey_path, allow_orphans=False, allow_unauthenticated=False, token_dir=None,
                jwks_dir=None, min_assurance=None, rulepack=None):
    """Walk the chain in seq order, stop at the first failure. Returns the --json object."""
    st = State(allow_orphans, allow_unauthenticated, token_dir, jwks_dir, min_assurance)
    res = {"ok": False, "line": "", "seq": None, "code": None, "records": 0, "attestation": st.attestation,
           "agent_auth": st.agent_auth, "orphans": 0, "unauthenticated": 0, "agents": {},
           "principals": st.principals, "principal_tokens": st.principal_tokens, "approvals": st.approval_counts,
           "budget_hits": 0, "after_the_fact": 0, "rulepack_matched": 0}

    def fail(seq, code, reason):
        res.update(seq=seq, code=code, line=f"FAIL seq={seq} {reason}" if seq is not None else f"FAIL {reason}",
                   orphans=st.orphans, unauthenticated=st.unauthenticated, budget_hits=st.budget_hits,
                   after_the_fact=st.after_the_fact, rulepack_matched=st.rulepack_matched)
        return res

    if not os.path.exists(db_path):
        return fail(None, "database_not_found", f"database not found: {db_path}")
    if rulepack is not None:
        try:
            st.pack = load_pack(rulepack)
        except (OSError, ValueError, ImportError) as e:
            return fail(None, "rulepack_unreadable", f"rule pack unreadable: {e}")
    try:
        public_key = load_public_key(pubkey_path)
    except (OSError, ValueError) as e:
        return fail(None, "public_key_unreadable", f"public key unreadable: {e}")

    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = read_rows(conn)
        if rows is None:
            return fail(None, "database_unreadable", "database unreadable: no records table")
        prev_seq, prev_hash, first_ts, last_ts = 0, GENESIS, None, None
        for record in rows:
            seq = record["seq"]
            try:
                if seq != prev_seq + 1:
                    raise Fail("gap", "gap")
                try:
                    computed = record_hash(record)
                except (TypeError, ValueError):  # e.g. a BLOB where text belongs
                    computed = None
                if computed != record["record_hash"]:
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
        if conn is not None:
            conn.close()
    line = (f"PASS records={res['records']} first={first_ts or '-'} last={last_ts or '-'} "
            f"attestation={counts(st.attestation)} agent_auth={counts(st.agent_auth)} "
            f"principals={counts(st.principals)} principal_tokens={counts(st.principal_tokens)} "
            f"approvals={counts(st.approval_counts)} budgets=hits:{st.budget_hits} after_the_fact={st.after_the_fact}")
    if rulepack is not None:
        line += f" rulepack_matched={st.rulepack_matched}"
    if allow_orphans and st.orphans:
        line += f" orphans={st.orphans}"
    if allow_unauthenticated and st.unauthenticated:
        line += f" unauthenticated={st.unauthenticated}"
    res.update(ok=True, line=line, orphans=st.orphans, unauthenticated=st.unauthenticated,
               budget_hits=st.budget_hits, after_the_fact=st.after_the_fact,
               rulepack_matched=st.rulepack_matched,
               agents={k: {f: a[f] for f in ("registered_seq", "current_pubkey", "revoked")}
                       for k, a in st.agents.items()})
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
    parser.add_argument("--token-dir", help="customer-kept principal tokens, <token_hash>.jwt (check U2)")
    parser.add_argument("--jwks-dir", help="JWKS snapshots, <jwks_hash>.json (check U2; default: --token-dir)")
    parser.add_argument("--min-principal-assurance", choices=ASSURANCE,
                        help="every task with a human principal has at least this assurance (check U3)")
    parser.add_argument("--rulepack", help="rule pack file: sealed budget limits and costs recompute (check W2)")
    args = parser.parse_args(argv)
    if args.rulepack == "":
        parser.error("--rulepack needs a file path")

    res = verify_full(args.db, args.pubkey, allow_orphans=args.allow_orphan_tool_calls,
                      allow_unauthenticated=args.allow_unauthenticated_agents, token_dir=args.token_dir,
                      jwks_dir=args.jwks_dir, min_assurance=args.min_principal_assurance, rulepack=args.rulepack)
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
