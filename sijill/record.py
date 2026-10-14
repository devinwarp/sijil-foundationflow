"""Record schema, canonicalisation, hashing and signing. Schema v2.

FROZEN at H1, thawed once for v2 (spec §2, §17.1; §11 rows 1 and 1g), and frozen again at v2.4.
Any change here changes every hash; the independent verifier in verifier/sijill_verify.py must keep
agreeing with this module. Hashing rule v2 (§2.2): an EXT_FIELDS member whose value is "" is left out of the
canonical object, so every record written before v2 keeps its hash.
"""

import hashlib
import json
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIELDS = (
    "seq", "type", "ts", "model_id", "model_digest", "node_id", "node_region",
    "policy_id", "policy_hash", "approval_ref", "mode", "decision", "rule_hits",
    "input_hash", "output_hash",
    "parent_seq", "source_label", "rulepack_hash", "ext",      # v2: causality, policy
    "agent_id", "principal", "task_seq",                        # v2: identity
    "prev_hash", "record_hash", "signature",
)
EXT_FIELDS = ("parent_seq", "source_label", "rulepack_hash", "ext", "agent_id", "principal", "task_seq")
SEALED_FIELDS = FIELDS[:-2]
BODY_FIELDS = tuple(f for f in SEALED_FIELDS if f not in ("seq", "prev_hash"))
GENESIS_HASH = "0" * 64

TYPES = ("inference", "policy_change",
         "tool_call", "tool_result", "egress",
         "integrity_baseline", "integrity_drift", "rulepack_change",
         "agent_register", "agent_rotate", "agent_revoke", "task_start", "task_end",
         "scitt_receipt",
         "agent_identity_update",                                   # v2.2 (§2.4.12)
         "approval")                                                # v2.4 (§17.5)
MODES = ("record", "enforce")
DECISIONS = ("allow", "flag", "block")
SOURCE_LABELS = ("user", "repo", "telemetry", "web", "memory")   # plus "mcp:<server>" and "http:<server>" (v2.4)
AGENT_AUTH = ("key", "mtls", "oidc", "relay", "none")            # "relay": v2.4 (§17.4.5)
PRINCIPAL_AUTH = ("oidc", "key", "none")
PRINCIPAL_SCHEMES = ("oidc", "email", "local", "human")          # "human": v2.4 (§17.2.5)
LIFECYCLE_CLASSES = ("ephemeral", "persistent", "derived")       # v2.2
ID_SCHEMES = ("wimse", "spiffe", "did", "entra", "cloud-native", "other")   # v2.2
HARNESSES = ("claude-code", "codex", "cursor", "gemini-cli", "foundry", "http-agent", "other")
OBSERVED_BY = ("mcp_guard", "claude_code_hook", "egress_proxy", "http_adapter", "foundry_relay")
APPROVAL_PHASES = ("request", "decision")
APPROVAL_OUTCOMES = ("granted", "refused", "timeout")
PRINCIPAL_ASSURANCE = ("low", "substantial", "high")

LEDGER_TYPES = ("policy_change", "rulepack_change")             # no agent, principal or task (§2.3)
TASK_REQUIRED = ("tool_call", "tool_result", "egress", "task_end", "approval")
TASK_FORBIDDEN = ("task_start", "agent_register", "agent_rotate", "agent_revoke", "agent_identity_update",
                  *LEDGER_TYPES)
PARENT_TYPES = ("tool_call", "tool_result", "egress", "integrity_drift", "approval")

_DECIMAL = re.compile(r"[1-9][0-9]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SOURCE_LABEL = re.compile(r"user|repo|telemetry|web|memory|mcp:[a-z0-9_-]{1,32}|http:[a-z0-9_-]{1,32}")
_HUMAN = re.compile(r"human:[a-z0-9-]{1,32}:[0-9a-f]{64}")
_PRINCIPAL = re.compile(r"oidc:[a-z0-9.-]+:\S+|email:[0-9a-f]{64}|local:[0-9a-f]{64}|" + _HUMAN.pattern)
_AGENT_ID = re.compile(r"\S{1,512}")
_APPROVAL_ID = re.compile(r"ap_[0-9A-Z]{26}")

# ext keys per type: (required, optional). §2.4 tables plus the §17.1 deltas. Unknown keys are refused.
# inference and scitt_receipt payloads belong to later rows (3, 3g, 15, 21); only their v2.4 keys are typed here.
_CLAIMS_REQ = {"issuer_id", "profile", "validation", "iss", "aud", "tenant", "assurance", "assurance_rule",
               "delegated", "token_hash"}
_CLAIMS_JWT = {"kid", "alg", "jwks_hash", "nbf", "exp"}
_CLAIMS_OPT = _CLAIMS_JWT | {"amr", "user_type", "roles_matched"}
EXT_KEYS = {
    "policy_change": (set(), set()),
    "tool_call": ({"harness", "session_id", "tool", "server", "qualified", "correlation", "observed_by"},
                  {"tool_use_id", "summary", "context_labels", "context_seqs", "confirmation", "aip", "aip_meta",
                   "approval_seq", "budget", "foundry_item_id", "after_the_fact"}),
    "tool_result": ({"tool", "server", "status", "bytes", "content_types", "invisible_unicode"},
                    {"exec_hints", "truncated", "http_status", "withheld"}),
    "egress": ({"host", "port", "proto", "observed_by", "allowed_by"},
               {"method", "bytes_out", "bytes_in", "pin_source", "budget"}),
    "integrity_baseline": ({"lockfile", "lockfile_hash", "entries", "files", "mcp_tools", "roots", "tool",
                            "invisible_unicode_entries"}, {"config_digest"}),
    "integrity_drift": ({"lockfile_hash_before", "lockfile_hash_after", "changed", "trigger"},
                        {"config_digest_before", "config_digest_after", "truncated"}),
    "rulepack_change": ({"rulepack_id", "version", "path", "before", "after", "rules_changed", "trigger"},
                        {"lineage"}),
    "agent_register": ({"auth", "registered_by", "principal_auth", "id_form"},
                       {"agent_pubkey", "nonce", "self_proof", "oidc_binding", "display_name", "aip_agent_id",
                        "description", "logical_agent_id", "responsible_entity", "lifecycle_class", "derived_from",
                        "runtime_identities", "issuer_countersig", "relay_binding"}),
    "agent_rotate": ({"old_pubkey", "new_pubkey", "nonce", "proof_old", "proof_new", "rotated_by",
                      "principal_auth"}, set()),
    "agent_revoke": ({"pubkey", "revoked_by", "principal_auth"}, {"reason"}),
    "task_start": ({"intent_hash", "harness", "session_id", "repo", "commit", "lockfile_hash", "delegated_from",
                    "agent_auth", "principal_auth", "agent_session"},
                   {"cwd", "config_digest", "logical_agent_id", "assurance_level", "assurance_seq",
                    "principal_claims"}),
    "task_end": ({"outcome", "inference", "tool_calls", "blocked", "confirmed", "denied", "flagged", "egress",
                  "last_seq"}, set()),
    "agent_identity_update": ({"action", "logical_agent_id", "runtime_identity", "nonce", "updated_by",
                               "principal_auth"}, {"self_proof", "issuer_countersig", "agent_id"}),
    "approval": ({"phase", "approval_id"},
                 {"tool", "server", "qualified", "correlation", "route_id", "approver_set", "min_assurance",
                  "timeout_ms", "on_timeout", "sod", "outcome", "approver", "approver_claims"}),
}
_APPROVAL_REQUEST = {"tool", "server", "qualified", "correlation", "route_id", "approver_set", "min_assurance",
                     "timeout_ms", "on_timeout", "sod"}
# §17.1 typed keys, wherever they appear
_TYPED = {"approval_seq": int, "after_the_fact": bool, "foundry_item_id": str, "http_status": int,
          "cost_micro": int, "price_rule": str, "budget": dict, "foundry": dict, "usage": dict,
          "timeout_ms": int, "sod": bool, "relay_binding": dict, "approver_set": dict}


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> str:
    """ISO 8601 UTC, millisecond precision, e.g. 2026-09-25T10:00:00.123Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def input_hash(messages) -> str:
    return sha256_hex(canonical_json(messages))


def output_hash(text: str) -> str:
    return sha256_hex(text.encode("utf-8"))


def compute_record_hash(record: dict) -> str:
    obj = {k: v for k, v in record.items() if k not in ("record_hash", "signature")}
    for f in EXT_FIELDS:
        if obj.get(f, "") == "":
            obj.pop(f, None)
    return sha256_hex(canonical_json(obj))


def _has_null(v) -> bool:
    if v is None:
        return True
    if isinstance(v, dict):
        return any(_has_null(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_null(x) for x in v)
    return False


def _ext(body: dict) -> dict:
    ext = body["ext"]
    if ext == "":
        return {}
    try:
        obj = json.loads(ext)
    except ValueError:
        obj = None
    if not isinstance(obj, dict) or canonical_json(obj).decode("utf-8") != ext:
        raise ValueError("ext must be a canonical JSON object serialised to a string")
    if _has_null(obj):
        raise ValueError("ext must not contain null")
    return obj


def _claims(c, where: str) -> None:
    if not isinstance(c, dict):
        raise ValueError(f"{where} must be an object")
    need = _CLAIMS_REQ | (_CLAIMS_JWT if c.get("validation") == "jwt" else set())
    if need - set(c) or set(c) - _CLAIMS_REQ - _CLAIMS_OPT:
        raise ValueError(f"{where} keys: missing={sorted(need - set(c))} extra={sorted(set(c) - _CLAIMS_REQ - _CLAIMS_OPT)}")
    if (c["profile"] not in ("entra", "uaepass", "oidc") or c["validation"] not in ("jwt", "userinfo")
            or c["assurance"] not in PRINCIPAL_ASSURANCE):
        raise ValueError(f"{where}: profile/validation/assurance not in their enums")


def _check_ext(t: str, x: dict) -> None:
    if t in EXT_KEYS:
        req, opt = EXT_KEYS[t]
        if req - set(x) or set(x) - req - opt:
            raise ValueError(f"{t} ext keys: missing={sorted(req - set(x))} extra={sorted(set(x) - req - opt)}")
    for k, typ in _TYPED.items():
        if k in x and type(x[k]) is not typ:
            raise ValueError(f"ext.{k} must be {typ.__name__}")
    if "harness" in x and x["harness"] not in HARNESSES:
        raise ValueError(f"ext.harness {x['harness']!r} not in {HARNESSES}")
    if t == "tool_call" and x["observed_by"] not in OBSERVED_BY:
        raise ValueError(f"ext.observed_by {x['observed_by']!r} not in {OBSERVED_BY}")
    if t == "egress" and x["observed_by"] not in (*OBSERVED_BY, "static"):
        raise ValueError(f"ext.observed_by {x['observed_by']!r} not allowed on egress")
    if x.get("withheld", True) is not True:                            # §2.4.2: true, or absent
        raise ValueError("ext.withheld must be true when present")
    if "principal_auth" in x and x["principal_auth"] not in PRINCIPAL_AUTH:
        raise ValueError(f"ext.principal_auth {x['principal_auth']!r} not in {PRINCIPAL_AUTH}")
    if t == "task_start" and x["agent_auth"] not in AGENT_AUTH:
        raise ValueError(f"ext.agent_auth {x['agent_auth']!r} not in {AGENT_AUTH}")
    if "principal_claims" in x:
        _claims(x["principal_claims"], "ext.principal_claims")
    if "usage" in x and (set(x["usage"]) != {"input_tokens", "output_tokens"}
                         or any(type(v) is not int for v in x["usage"].values())):
        raise ValueError("ext.usage must be {input_tokens, output_tokens} integers")
    if t == "agent_register":
        auth = x["auth"]
        need = {"key": {"agent_pubkey", "nonce", "self_proof"}, "oidc": {"oidc_binding"},
                "relay": {"relay_binding"}}.get(auth)
        if need is None:
            raise ValueError(f"agent_register ext.auth {auth!r} not in key|oidc|relay")
        if need - set(x) or ("relay_binding" in x) != (auth == "relay"):
            raise ValueError(f"agent_register auth={auth} needs {sorted(need)}; relay_binding only with relay")
        if auth == "relay" and set(x["relay_binding"]) != {"platform", "endpoint_host", "agent_name"}:
            raise ValueError("relay_binding must be {platform, endpoint_host, agent_name}")
    if t == "approval":
        _check_approval(x)


def _check_approval(x: dict) -> None:
    if x["phase"] not in APPROVAL_PHASES or not _APPROVAL_ID.fullmatch(x["approval_id"]):
        raise ValueError("approval phase or approval_id malformed")
    if x["phase"] == "request":
        if set(x) != _APPROVAL_REQUEST | {"phase", "approval_id"}:
            raise ValueError(f"approval request needs exactly {sorted(_APPROVAL_REQUEST)}")
        if x["min_assurance"] not in PRINCIPAL_ASSURANCE or x["on_timeout"] != "deny":
            raise ValueError("approval request min_assurance/on_timeout invalid")
        return
    outcome = x.get("outcome")
    if outcome not in APPROVAL_OUTCOMES or set(x) & _APPROVAL_REQUEST:
        raise ValueError("approval decision needs outcome and no request keys")
    named = outcome in ("granted", "refused")
    if named != ("approver" in x) or named != ("approver_claims" in x):
        raise ValueError("approver and approver_claims iff outcome is granted or refused")
    if named:
        if not _HUMAN.fullmatch(x["approver"]):
            raise ValueError("approver must be a human: principal")
        _claims(x["approver_claims"], "ext.approver_claims")


def _validate(body: dict, seq: int) -> None:
    if set(body) != set(BODY_FIELDS):
        missing, extra = set(BODY_FIELDS) - set(body), set(body) - set(BODY_FIELDS)
        raise ValueError(f"record fields mismatch: missing={sorted(missing)} extra={sorted(extra)}")
    bad = [k for k, v in body.items() if not isinstance(v, str)]
    if bad:
        raise TypeError(f"fields must be strings: {bad}")
    t = body["type"]
    if t not in TYPES or body["mode"] not in MODES or body["decision"] not in DECISIONS:
        raise ValueError(f"invalid type/mode/decision: {t}/{body['mode']}/{body['decision']}")
    hits = json.loads(body["rule_hits"])
    if not isinstance(hits, list) or not all(isinstance(h, str) for h in hits):
        raise ValueError("rule_hits must be a JSON array of strings")
    x = _ext(body)
    for col in ("parent_seq", "task_seq"):
        v = body[col]
        if v and (not _DECIMAL.fullmatch(v) or int(v) >= seq):
            raise ValueError(f"{col} must be '' or the decimal seq of an earlier record")
    p = body["parent_seq"]
    if p and t not in PARENT_TYPES:
        raise ValueError(f"parent_seq not allowed on {t}")
    orphan_ok = t in ("tool_call", "approval") and x.get("correlation") == "none"   # §5.4, §17.5.3
    if not p and t in PARENT_TYPES and not orphan_ok:
        raise ValueError(f"{t} requires parent_seq")
    if (body["source_label"] != "") != (t == "tool_result") or (
            body["source_label"] and not _SOURCE_LABEL.fullmatch(body["source_label"])):
        raise ValueError("source_label is required on tool_result, forbidden elsewhere, and must match the enum")
    if body["rulepack_hash"] and not _HEX64.fullmatch(body["rulepack_hash"]):
        raise ValueError("rulepack_hash must be '' or 64 lower-case hex")
    if body["agent_id"] and not _AGENT_ID.fullmatch(body["agent_id"]):
        raise ValueError("agent_id malformed")
    if body["principal"] and not _PRINCIPAL.fullmatch(body["principal"]):
        raise ValueError("principal malformed")
    if t in LEDGER_TYPES and (body["agent_id"] or body["principal"]):
        raise ValueError(f"{t} is ledger-originated: agent_id and principal must be ''")
    if body["task_seq"] and t in TASK_FORBIDDEN:
        raise ValueError(f"task_seq not allowed on {t}")
    if not body["task_seq"] and t in TASK_REQUIRED:
        raise ValueError(f"{t} requires task_seq")
    _check_ext(t, x)


def seal(body: dict, seq: int, prev_hash: str, key: Ed25519PrivateKey) -> dict:
    """Return a complete, signed record: body + seq + prev_hash + record_hash + signature."""
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ValueError("seq must be a positive integer")
    _validate(body, seq)
    record = {**body, "seq": seq, "prev_hash": prev_hash}
    record["record_hash"] = compute_record_hash(record)
    record["signature"] = key.sign(bytes.fromhex(record["record_hash"])).hex()
    return {f: record[f] for f in FIELDS}
