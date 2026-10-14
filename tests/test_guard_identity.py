"""Row 6b: the guard's key, registration, sessions and tasks against a real ledger (spec §5.8, §5.9)."""

import json
import multiprocessing
import os
import stat
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from agentkit import AGENT, OPEN_POLICY, chat
from conftest import rows, verify
from guard import config, identity, task
from guard.__main__ import main
from guard.ledger import Ledger, Refused, Unreachable
from guardkit import guard_yaml, ledger_node, ledger_of
from jwtkit import ENTRA_ISS, Idp, claims, jws, rsa_jwk
from test_oidc import MI, WORKLOAD_POLICY, register_oidc


def run(argv, client, capsys) -> tuple[int, str]:
    """(exit code, stdout); stderr of the last call is kept in run.err."""
    code = main(argv, ledger=ledger_of(client))
    out = capsys.readouterr()
    run.err = out.err
    return code, out.out.strip()


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
        key_file = tmp_path / "home" / ".sijil" / "agent.key"
        pem = key_file.read_bytes()                                  # the refused attempt left its key behind
        monkeypatch.setenv("SIJILL_ADMIN_TOKEN", "test-admin")
        code, out = run(["identity", "init", *args], client, capsys)
        assert key_file.read_bytes() == pem                          # the retry registers it, never replaces it
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


def mock_ledger(handler) -> Ledger:
    return Ledger("http://ledger.test", "t", http=httpx.Client(base_url="http://ledger.test",
                                                                transport=httpx.MockTransport(handler)))


def in_an_hour() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


@pytest.mark.parametrize("status,body,error", [
    (301, "<html>moved</html>", Unreachable), (307, "", Unreachable), (404, '{"detail": "no"}', Refused),
    (401, "not json", Refused), (503, "down", Unreachable), (200, "<html>proxy login</html>", Unreachable)])
def test_only_a_json_2xx_is_success(status, body, error):
    ledger = mock_ledger(lambda request: httpx.Response(status, text=body))
    with pytest.raises(error):
        ledger.call("GET", "/api/policy")


def test_a_bad_url_is_unreachable_and_redirects_are_not_followed():
    def bad(request):
        raise httpx.InvalidURL("no host")
    with pytest.raises(Unreachable):
        mock_ledger(bad).call("GET", "/x")
    assert Ledger("http://ledger.test").http.follow_redirects is False


def test_init_refuses_a_corrupt_key_and_leaves_it(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)
    key_file = tmp_path / "home" / ".sijil" / "agent.key"
    key_file.parent.mkdir(parents=True)
    key_file.touch(mode=0o600)                                       # what a crash mid-create leaves
    client, _ = ledger_node(tmp_path)
    with client:
        code, _ = run(["identity", "init", "--config", str(cfg_path), "--repo", str(tmp_path / "repo")], client, capsys)
    assert code == 1 and "remove it" in run.err and key_file.read_bytes() == b""


def write_yaml(tmp_path, replace: str = "", name: str = "guard.yaml") -> str:
    """A minimal guard.yaml; `replace` swaps in one top-level line, keyed by its name."""
    lines = {"sijil": "sijil: {url: 'http://x'}", "identity": "identity: {agent_id: a, key_path: k}"}
    if replace:
        lines[replace.split(":")[0]] = replace
    p = tmp_path / name
    p.write_text("version: 1\n" + "\n".join(lines.values()) + "\n")
    return str(p)


@pytest.mark.parametrize("line,message", [
    ("identity: {agent_id: a, key_path: '${NO_SUCH_KEYDIR_X}/k'}", "unset variable"),
    ("identity: {agent_id: a, key_path: '~no_such_user_x/k'}", "unset variable or an unknown home"),
    ("state_path: '${NO_SUCH_KEYDIR_X}/s.json'", "unset variable"),
    ("sijil: {url: 'http://x', token_env: NO_SUCH_TOKEN_X}", "token_env names NO_SUCH_TOKEN_X"),
    ("sijil: {url: 'http://x', timeout: 5}", "sijil.timeout is not supported"),
    ("identity: {agent_id: a, key_path: k, principal: x}", "identity.principal is not supported"),
    ("task: nope", "task: must be a mapping"),
])
def test_config_refuses_unresolved_paths_unset_token_env_and_nested_unknowns(tmp_path, line, message):
    with pytest.raises(ValueError, match=message):
        config.load(write_yaml(tmp_path, line))


def test_relative_paths_resolve_against_the_config_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "conf").mkdir()
    cfg = config.load(write_yaml(tmp_path / "conf", "state_path: run/s.json"))
    assert cfg.key_path == str(tmp_path / "conf" / "k") and cfg.state_path == str(tmp_path / "conf" / "run" / "s.json")


def test_state_files_differ_for_agents_with_the_same_last_segment(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    paths = {task.state_path(SimpleNamespace(state_path="", agent_id=a)) for a in ("org/a/bot", "org/b/bot", "bot")}
    assert len(paths) == 3 and all(p.name.endswith("-bot.json") for p in paths)


def test_a_session_about_to_expire_is_not_reused(tmp_path):
    def saved(seconds):
        at = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="milliseconds")
        task.save(task.State("s", AGENT, "p", at.replace("+00:00", "Z")), tmp_path / "s.json")
        return task.load(tmp_path / "s.json", AGENT)
    assert saved(10) is None and saved(120) is not None


def test_a_dropped_session_is_replaced_once_and_a_second_401_is_final(tmp_path):
    path, opened = tmp_path / "s.json", []

    def open_session():
        opened.append(1)
        return {"agent_session": f"s{len(opened)}", "principal": "p", "expires_at": in_an_hour()}
    task.shared(path, AGENT, open_session)
    calls = []

    def fn(state):
        calls.append(state.agent_session)
        if state.agent_session == "s1":
            raise Refused(401, "unknown session")
        return state.agent_session
    assert task.update(path, AGENT, open_session, fn) == "s2" and calls == ["s1", "s2"]
    assert task.load(path, AGENT).agent_session == "s2"

    def always(state):
        raise Refused(401, "again")
    with pytest.raises(Refused):
        task.update(path, AGENT, open_session, always)
    assert len(opened) == 3                                          # one retry, not a loop


def test_task_start_never_drops_an_open_task(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)
    client, s = ledger_node(tmp_path)
    with client:
        args = ["--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        run(["identity", "init", *args], client, capsys)
        assert run(["task", "start", *args, "--delegate"], client, capsys)[0] == 1        # nothing to delegate from
        first = int(run(["task", "start", *args], client, capsys)[1])
        assert run(["task", "start", *args], client, capsys)[0] == 1                      # still open
        assert "still open" in run.err
        assert run(["task", "start", *args, "--delegate", "--intent", " "], client, capsys)[0] == 1
        assert task.load(tmp_path / "run" / "case-agent.json", AGENT).tasks == [first]
        assert len(rows(s.db_path, "type = 'task_start'")) == 1


def test_a_malformed_ledger_reply_is_a_clean_exit(tmp_path, capsys):
    cfg_path = guard_yaml(tmp_path)
    identity.create_key(str(tmp_path / "home" / ".sijil" / "agent.key"), str(tmp_path / "repo"))

    def handler(request):
        reply = {"/api/policy": {"node_id": "n"}, "/api/agent/challenge": {"nonce": "x"},
                 "/api/agent/session": {"agent_session": "s", "principal": "p", "expires_at": in_an_hour()}}
        return httpx.Response(200, json=reply.get(request.url.path, {}))      # task/start answers without a seq
    assert main(["task", "start", "--config", str(cfg_path)], ledger=mock_ledger(handler)) == 3
    assert "unexpected reply" in capsys.readouterr().err


def start_worker(path, delay):
    """One guard process: delegate a child task onto the shared stack (the ledger is a slow stub)."""
    def handler(request):
        time.sleep(delay)
        return httpx.Response(200, json={"seq": os.getpid()})
    task.update(path, AGENT, lambda: pytest.fail("no session expected"),
                lambda st: task.start(mock_ledger(handler), st, "i", "other", delegate=True))


def end_worker(path, delay):
    def handler(request):
        time.sleep(delay)
        return httpx.Response(200, json={"seq": 1})
    task.update(path, AGENT, lambda: pytest.fail("no session expected"),
                lambda st: task.end(mock_ledger(handler), st, "completed"))


def test_concurrent_guard_processes_lose_no_task_update(tmp_path):
    path, n = tmp_path / "run" / "s.json", 6
    task.save(task.State("s", AGENT, "p", in_an_hour(), [1000000]), path)
    ctx = multiprocessing.get_context("fork")

    def fan_out(worker):
        procs = [ctx.Process(target=worker, args=(path, 0.05)) for _ in range(n)]
        [p.start() for p in procs]
        [p.join(30) for p in procs]
        assert [p.exitcode for p in procs] == [0] * n
    fan_out(start_worker)
    assert len(task.load(path, AGENT).tasks) == n + 1               # every start is on the stack
    fan_out(end_worker)
    assert task.load(path, AGENT).tasks == [1000000]                # every end popped exactly one
    assert [f.name for f in path.parent.iterdir() if f.suffix == ".tmp"] == []


def test_load_key_reports_an_empty_file(tmp_path):
    key_file = tmp_path / "k"
    key_file.touch(mode=0o600)
    with pytest.raises(ValueError, match="empty or corrupt"):
        identity.load_key(str(key_file))


@pytest.mark.parametrize("answer", [httpx.Response(500), httpx.Response(200, content=b"<html>"),
                                    httpx.Response(200, json={"nope": 1}), httpx.Response(200, json=[1]),
                                    httpx.Response(200, json={"value": 7})])
def test_github_oidc_failures_are_a_clean_refusal(monkeypatch, answer):
    """Final review Minor 10: every door maps ValueError to a refusal; a raw httpx or KeyError was a 500."""
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://actions.test/token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")
    with pytest.raises(ValueError, match="GitHub Actions OIDC token request failed"):
        identity.github_token("n", httpx.Client(transport=httpx.MockTransport(lambda r: answer)))


def test_identity_init_registers_under_principal_oidc_with_the_principal_token(tmp_path, capsys, monkeypatch):
    """register_policy: principal_oidc takes registered_by from the human's token, sent in the guard's principal
    header from --principal-token-env (default SIJIL_PRINCIPAL_TOKEN), as task start does."""
    from test_principals import HUMAN, POLICY, node, officer
    cfg_path = guard_yaml(tmp_path)
    client, s = node(tmp_path, POLICY.replace("register_policy: open", "register_policy: principal_oidc"))
    with client:
        args = ["identity", "init", "--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        monkeypatch.delenv("SIJIL_PRINCIPAL_TOKEN", raising=False)
        assert run(args, client, capsys)[0] == 1
        monkeypatch.setenv("SIJIL_PRINCIPAL_TOKEN", officer())
        code, out = run(args, client, capsys)
        assert code == 0 and out.startswith(f"registered {AGENT} "), run.err
    rec = rows(s.db_path)[-1]
    assert (rec["type"], rec["principal"], json.loads(rec["ext"])["principal_auth"]) == ("agent_register", HUMAN, "oidc")
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_a_task_the_ledger_already_closed_leaves_the_stack(tmp_path, capsys, monkeypatch):
    """A task the ledger closed (timeout, or ended elsewhere) is taken off the state file when `task end` is refused
    for it, so the guards stop sending its seq; a transient refusal (an approval pending) keeps it."""
    cfg_path = guard_yaml(tmp_path)
    client, s = ledger_node(tmp_path)
    state_file = tmp_path / "run" / "case-agent.json"
    with client:
        args = ["--config", str(cfg_path), "--repo", str(tmp_path / "repo")]
        run(["identity", "init", *args], client, capsys)
        first = int(run(["task", "start", *args], client, capsys)[1])
        real = Ledger.call

        def pending(self, method, path, *a, **kw):
            if path == "/api/agent/task/end":
                raise Refused(409, "approval pending in this task")
            return real(self, method, path, *a, **kw)
        monkeypatch.setattr(Ledger, "call", pending)
        assert run(["task", "end", *args], client, capsys)[0] == 1
        assert task.load(state_file, AGENT).tasks == [first]                     # transient: kept
        monkeypatch.setattr(Ledger, "call", real)
        st = task.load(state_file, AGENT)
        assert task.end_task(ledger_of(client), st.agent_session, first, "timeout")["seq"]   # closed meanwhile
        assert run(["task", "end", *args], client, capsys)[0] == 1 and "409" in run.err
        assert task.load(state_file, AGENT).tasks == []                          # closed: dropped
        second = int(run(["task", "start", *args], client, capsys)[1])
        assert task.load(state_file, AGENT).tasks == [second]
    assert [json.loads(r["ext"])["outcome"] for r in rows(s.db_path, "type = 'task_end'")] == ["timeout"]
    assert verify(s.db_path, s.pubkey_path)[0] == 0


def test_limits_set_the_rule_engines_size_caps(tmp_path):
    from guard import rules
    cfg = config.load(write_yaml(tmp_path, ""))
    assert (cfg.max_command, cfg.max_args) == (rules.MAX_COMMAND, rules.MAX_ARGS) == (2048, 32768)
    cfg = config.load(write_yaml(tmp_path, "limits: {max_command: 1024, max_args: 1048576}"))
    assert (cfg.max_command, cfg.max_args) == (1024, 1048576)
    for bad in ("limits: {max_args: 0}", "limits: {max_command: '4096'}", "limits: {max_command: true}",
                "limits: {max_body: 1}"):
        with pytest.raises(ValueError, match="limits"):
            config.load(write_yaml(tmp_path, bad))
