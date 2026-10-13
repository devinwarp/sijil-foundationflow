"""Row 4: rule pack loading, rulepack_change at startup and reload, rulepack_hash on every record (spec §2.4.6)."""

import json

import pytest

from conftest import ask, make_node, rows, stub_model, verify
from sijill import record, rulepack

PACK = """rulepack_id: moi-case-pack
version: 0.1.0
rules:
  - id: case-closure-needs-approval
    on: tool_call
    match: {tool: ["http:case-api:closeCase"]}
    action: confirm
  - id: no-write-after-citizen-upload
    on: tool_call
    match: {http_method: [POST], context_labels_any: ["http:document-intake"]}
    action: block
"""


def pack_node(tmp_path, text=PACK):
    (tmp_path / "pack.yaml").write_text(text)
    return make_node(tmp_path, stub_model, rulepack_path=str(tmp_path / "pack.yaml"))


def test_first_adoption_is_sealed_before_anything_else(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert ask(client, "hello").status_code == 200
    change, inference = rows(s.db_path)
    h = record.sha256_hex(PACK.encode())
    assert (change["type"], change["agent_id"], change["principal"], change["rulepack_hash"]) == \
        ("rulepack_change", "", "", h)
    ids = ["case-closure-needs-approval", "no-write-after-citizen-upload"]
    assert json.loads(change["rule_hits"]) == ids
    assert json.loads(change["ext"]) == {"rulepack_id": "moi-case-pack", "version": "0.1.0",
                                         "path": str(tmp_path / "pack.yaml"), "before": "", "after": h,
                                         "rules_changed": ids, "trigger": "startup"}
    assert inference["rulepack_hash"] == h
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_restart_with_the_same_pack_seals_nothing(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = pack_node(tmp_path)
    with client:
        pass
    assert len(rows(s.db_path)) == 1


def test_reload_seals_only_changed_actions(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert client.post("/api/admin/rulepack/reload").json()["seq"] is None
        (tmp_path / "pack.yaml").write_text(PACK.replace("action: block", "action: record"))
        r = client.post("/api/admin/rulepack/reload").json()
        assert r["changed"] == ["no-write-after-citizen-upload"] and r["seq"] == 2
        assert ask(client, "after").status_code == 200
    first, second, inference = rows(s.db_path)
    x = json.loads(second["ext"])
    assert (x["before"], x["after"], x["trigger"]) == (first["rulepack_hash"], second["rulepack_hash"], "reload")
    assert inference["rulepack_hash"] == second["rulepack_hash"]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_pack_edited_while_down_is_sealed_at_startup(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = pack_node(tmp_path, PACK.replace("0.1.0", "0.2.0"))
    with client:
        pass
    _, change = rows(s.db_path)
    x = json.loads(change["ext"])
    assert (x["version"], x["rules_changed"], x["trigger"]) == ("0.2.0", [], "startup")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_m1_chain_adopts_a_pack_without_a_downgrade(tmp_path):
    client, s = make_node(tmp_path, stub_model)
    with client:
        ask(client, "before any pack")
    client, s = pack_node(tmp_path)
    with client:
        ask(client, "after")
    assert [r["rulepack_hash"] != "" for r in rows(s.db_path)] == [False, True, True]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_dropping_the_pack_from_config_refuses_to_start(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        pass
    client, s = make_node(tmp_path, stub_model)
    with pytest.raises(RuntimeError, match="SIJILL_RULEPACK_PATH"):
        with client:
            pass


def test_reload_needs_the_admin_token(tmp_path):
    client, s = pack_node(tmp_path)
    with client:
        assert client.post("/api/admin/rulepack/reload", headers={"Authorization": "Bearer no"}).status_code == 401


@pytest.mark.parametrize("text, match", [
    ("version: 1\nrules: []\n", "rulepack_id"),
    (PACK.replace("case-closure-needs-approval", "Case_Closure"), "kebab-case"),
    (PACK.replace("case-closure-needs-approval", "principal-missing"), "reserved"),
    (PACK.replace("no-write-after-citizen-upload", "case-closure-needs-approval"), "duplicate"),
    (PACK.replace("action: confirm", "action: maybe"), "action"),
    (PACK.replace("on: tool_call", "on: inference", 1), "on in"),
])
def test_loader_refuses_bad_packs(tmp_path, text, match):
    (tmp_path / "p.yaml").write_text(text)
    with pytest.raises(ValueError, match=match):
        rulepack.load(str(tmp_path / "p.yaml"))


# ---- §17.5.1 hitl:, §17.6.1 budgets: and pricing: (row 18g and 41 inputs)

GOV = PACK + """hitl:
  timeout_seconds: 300
  on_timeout: deny
  channel: entra
  entra: {issuer_id: entra-moi, audience: "api://sijil-approvals"}
  separation_of_duties: true
  routes:
    - id: case-closure
      rules: ["case-closure-*"]
      approvers: {role: Sijil.Approver.CaseClosure}
      min_assurance: high
      timeout_seconds: 900
    - id: budget-overrun
      rules: ["budget:*"]
      approvers: {oids: ["7a8b9c0d-2e3f-4a5b-9c6d-1e2f3a4b5c6d"]}
  notify: {teams_webhook_env: SIJIL_TEAMS_WEBHOOK}
budgets:
  - id: case-agent
    match: {harness: [foundry, http-agent]}
    limits:
      tool_calls: 40
      tool_calls_by: {"http:case-api:addCaseNote": 5, "mcp:*:send_*": 2}
      egress_hosts: 4
      model_spend_micro: 3000000
    currency: AED
    on_exceed: confirm
pricing:
  - {id: aoai-gpt41-uae, model: "api:azure-openai:gpt-4.1*", input_per_mtok_micro: 7340000,
     output_per_mtok_micro: 29360000, missing_usage_cost_micro: 50000}
  - {id: local, model: "sha256:*", input_per_mtok_micro: 0, output_per_mtok_micro: 0, missing_usage_cost_micro: 0}
"""


def test_hitl_budgets_and_pricing_load(tmp_path):
    (tmp_path / "p.yaml").write_text(GOV)
    p = rulepack.load(str(tmp_path / "p.yaml"))
    h = p.hitl
    assert (h.channel, h.timeout_seconds, h.separation_of_duties, h.issuer_id, h.audience, h.teams_webhook_env) == \
        ("entra", 300, True, "entra-moi", "api://sijil-approvals", "SIJIL_TEAMS_WEBHOOK")
    closure, overrun = h.routes
    assert (closure.role, closure.oids, closure.min_assurance, closure.timeout_seconds) == \
        ("Sijil.Approver.CaseClosure", (), "high", 900)
    assert (overrun.role, overrun.min_assurance, overrun.timeout_seconds) == ("", "substantial", 300)
    assert p.route(["no-write-after-citizen-upload", "case-closure-needs-approval"]) is closure
    assert p.route(["budget:case-agent:tool_calls"]) is overrun and p.route(["other"]) is None
    [b] = p.budgets
    assert (b.match, b.on_exceed, b.currency) == ({"harness": ("foundry", "http-agent")}, "confirm", "AED")
    assert b.limits == {"tool_calls": 40, "tool_calls_by": {"http:case-api:addCaseNote": 5, "mcp:*:send_*": 2},
                        "egress_hosts": 4, "model_spend_micro": 3000000}
    assert p.price("api:azure-openai:gpt-4.1-2025-04-14")["id"] == "aoai-gpt41-uae"
    assert p.price("sha256:" + "a" * 64)["id"] == "local" and p.price("api:anthropic:claude") is None


def test_the_guard_reads_the_channel_and_hashes_the_same_bytes(tmp_path):
    from guard import rules
    (tmp_path / "p.yaml").write_text(GOV)
    g = rules.load(str(tmp_path / "p.yaml"))
    assert g.approval == "entra" and g.hash == rulepack.load(str(tmp_path / "p.yaml")).hash
    (tmp_path / "p.yaml").write_text(PACK)
    assert rules.load(str(tmp_path / "p.yaml")).approval == "self"


@pytest.mark.parametrize("change, match", [
    (("channel: entra", "channel: email"), "channel self|entra"),
    (("on_timeout: deny", "on_timeout: allow"), "on_timeout deny"),
    (("  entra: {issuer_id: entra-moi, audience: \"api://sijil-approvals\"}\n", ""), "entra.issuer_id"),
    (("approvers: {role: Sijil.Approver.CaseClosure}", "approvers: {group: x}"), "approvers"),
    (("[\"7a8b9c0d-2e3f-4a5b-9c6d-1e2f3a4b5c6d\"]", "[alice]"), "GUIDs"),
    (("min_assurance: high", "min_assurance: top"), "min_assurance"),
    (("timeout_seconds: 900", "timeout_seconds: 0"), "at least 1"),
    (("  notify:", "  show_values: true\n  notify:"), "hitl keys"),
    (("egress_hosts: 4", "egress_hosts: -1"), "non-negative"),
    (("model_spend_micro: 3000000", "model_spend_euros: 3"), "limits among"),
    (("rules: [\"budget:*\"]", "rules: [\"budgets-*\"]"), "needs a hitl route"),
    (("match: {harness: [foundry, http-agent]}", "match: {user: [x]}"), "match keys"),
    (("missing_usage_cost_micro: 50000}", "missing_usage_cost_micro: 0.5}"), "non-negative"),
    (("  - {id: local, model", "  - {id: aoai-gpt41-uae, model"), "duplicate pricing"),
])
def test_loader_refuses_bad_hitl_budgets_and_pricing(tmp_path, change, match):
    assert GOV.count(change[0]) == 1
    (tmp_path / "p.yaml").write_text(GOV.replace(*change))
    with pytest.raises(ValueError, match=match):
        rulepack.load(str(tmp_path / "p.yaml"))


def test_named_approval_needs_its_issuer_in_the_policy(tmp_path):
    with pytest.raises(ValueError, match="principals.issuers"):
        with pack_node(tmp_path, GOV)[0]:
            pass
    client, s = pack_node(tmp_path, PACK)
    with client:
        (tmp_path / "pack.yaml").write_text(GOV)
        r = client.post("/api/admin/rulepack/reload")
        assert r.status_code == 400 and "principals.issuers" in r.json()["detail"]
