"""Row 6b: the guard's key, registration, sessions and tasks against a real ledger (spec §5.8, §5.9)."""

import json
import os
import stat

import httpx
import pytest

from agentkit import AGENT, OPEN_POLICY, chat
from conftest import rows, verify
from guard import config, identity, task
from guard.__main__ import main
from guard.ledger import Ledger, Unreachable
from guardkit import guard_yaml, ledger_node, ledger_of
from jwtkit import ENTRA_ISS, Idp, claims, jws, rsa_jwk
from test_oidc import MI, WORKLOAD_POLICY, register_oidc


def run(argv, client, capsys) -> tuple[int, str]:
    code = main(argv, ledger=ledger_of(client))
    return code, capsys.readouterr().out.strip()


def test_identity_init_session_and_task_round_trip(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)
    client, s = ledger_node(tmp_path)
    with client:
        args = ["--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        code, out = run(["identity", "init", *args], client, capsys)
        assert code == 0 and out.startswith(f"registered {AGENT} pubkey=")
        key_file = tmp_path / "home" / ".sijil" / "agent.key"
        assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
        code, out = run(["task", "start", *args], client, capsys)
        task_seq = int(out)
        state_file = tmp_path / "run" / "case-agent.json"
        assert stat.S_IMODE(os.stat(state_file).st_mode) == 0o600
        state = task.load(state_file, AGENT)
        assert state.tasks == [task_seq]
        assert chat(client, None, "hello", **state.headers()).status_code == 200      # the agent's model call
        code, out = run(["session", "open", *args], client, capsys)          # reused, not reopened
        assert out.startswith(f"agent_session={state.agent_session} ")
        code, out = run(["task", "end", *args, "--outcome", "completed"], client, capsys)
        assert code == 0 and out.endswith("tool_calls=0 blocked=0")
    recs = rows(s.db_path)
    assert [r["type"] for r in recs] == ["rulepack_change", "agent_register", "task_start", "inference", "task_end"]
    start, inference = recs[2], recs[3]
    assert start["input_hash"] == identity.sha256_hex(b"Case MOI-2026-004211")
    assert json.loads(start["ext"])["harness"] == "http-agent" and inference["task_seq"] == str(task_seq)
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_delegated_task_stacks_on_its_parent(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)
    client, s = ledger_node(tmp_path)
    with client:
        args = ["--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        run(["identity", "init", *args], client, capsys)
        parent = int(run(["task", "start", *args], client, capsys)[1])
        child = int(run(["task", "start", *args, "--delegate", "--intent", "verify salary"], client, capsys)[1])
        assert task.load(tmp_path / "run" / "case-agent.json", AGENT).tasks == [parent, child]
        run(["task", "end", *args], client, capsys)
        assert task.load(tmp_path / "run" / "case-agent.json", AGENT).tasks == [parent]
        run(["task", "end", *args], client, capsys)
    sub = rows(s.db_path, f"seq = {child}")[0]
    assert json.loads(sub["ext"])["delegated_from"] == str(parent)
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_the_key_stays_outside_the_repo_and_private(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError, match="outside the repository"):
        identity.create_key(str(repo / ".sijil" / "agent.key"), str(repo))
    key_path = tmp_path / "agent.key"
    identity.create_key(str(key_path), str(repo))
    with pytest.raises(FileExistsError):
        identity.create_key(str(key_path), str(repo))              # never overwrites a key
    os.chmod(key_path, 0o644)
    with pytest.raises(ValueError, match="readable by other users"):
        identity.load_key(str(key_path))


def test_oidc_session_from_env_and_from_github_actions(tmp_path, monkeypatch):
    cfg_path = guard_yaml(tmp_path)
    cfg_path.write_text(cfg_path.read_text().replace("auth: key", "auth: oidc"))
    cfg = config.load(str(cfg_path))
    client, s = ledger_node(tmp_path, policy_text=WORKLOAD_POLICY, idp=Idp({"keys": [rsa_jwk()]}))
    with client:
        assert register_oidc(client).status_code == 200
        monkeypatch.setenv("SIJIL_OIDC_TOKEN", jws(claims(sub=MI, jti="j-env")))
        sess = identity.open_session(ledger_of(client), cfg)
        assert (sess["agent_auth"], sess["principal"]) == ("oidc", f"oidc:login.microsoftonline.com:{MI}")
        monkeypatch.delenv("SIJIL_OIDC_TOKEN")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://actions.test/token?api-version=2.0")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")
        seen = []

        def actions(request: httpx.Request) -> httpx.Response:
            seen.append((request.url.params["audience"], request.headers["authorization"]))
            return httpx.Response(200, json={"value": jws(claims(sub=MI, jti="j-gha"))})
        sess = identity.open_session(ledger_of(client), cfg, http=httpx.Client(transport=httpx.MockTransport(actions)))
        assert sess["agent_auth"] == "oidc" and seen == [("sijil:auh-node-01", "bearer runner-bearer")]
        monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL")
        with pytest.raises(ValueError, match="no OIDC token"):
            identity.open_session(ledger_of(client), cfg)


def test_closed_registration_needs_the_operator_token(tmp_path, capsys, monkeypatch):
    cfg_path = guard_yaml(tmp_path)
    client, s = ledger_node(tmp_path, policy_text=OPEN_POLICY.replace("open", "closed"))
    with client:
        client.headers.pop("Authorization")
        args = ["--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        assert run(["identity", "init", *args], client, capsys)[0] == 1
        (tmp_path / "home" / ".sijil" / "agent.key").unlink()
        monkeypatch.setenv("SIJILL_ADMIN_TOKEN", "test-admin")
        code, out = run(["identity", "init", *args], client, capsys)
        assert code == 0 and "seq=2" in out


def test_unreachable_ledger_fails_closed(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)

    def down(request):
        raise httpx.ConnectError("refused")
    dead = Ledger("http://ledger.test", "t", http=httpx.Client(base_url="http://ledger.test",
                                                                transport=httpx.MockTransport(down)))
    with pytest.raises(Unreachable, match="unreachable"):
        dead.node_id()
    identity.create_key(str(tmp_path / "home" / ".sijil" / "agent.key"), str(tmp_path / "repo"))
    assert main(["task", "start", "--config", str(cfg_path)], ledger=dead) == 3
    assert "Sijil ledger unreachable" in capsys.readouterr().err


@pytest.mark.parametrize("edit,message", [
    (("auth: key", "auth: mtls"), "mtls is not built"),
    (("sijil:\n", "sijil:\n  on_unreachable: open\n"), "on_unreachable must be closed"),
    (("version: 1\n", "version: 1\naip: {}\n"), "not supported"),
    (("registered_by: local:", "registered_by: someone:"), "must be a principal"),
])
def test_config_refuses_what_it_does_not_honour(tmp_path, edit, message):
    p = guard_yaml(tmp_path)
    p.write_text(p.read_text().replace(*edit))
    with pytest.raises(ValueError, match=message):
        config.load(str(p))
