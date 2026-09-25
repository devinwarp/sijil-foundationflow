import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from sijill import keys, record
from sijill.proxy import Settings, create_app
from sijill.store import Store

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier" / "sijill_verify.py"
TAMPER = ROOT / "scripts" / "tamper.sh"
APPROVED_DIGEST = "sha256:0fbba6b2d3fb9d319e546e91f7f04c44ce8278f1c2a133ca6db1e76619256be1"
MODEL = "llama-3.2-3b-instruct"


def verify(db, pub) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(VERIFIER), "--db", str(db), "--pubkey", str(pub), "--plain"],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def sqlite(db, sql: str) -> str:
    """Edit the store the way the demo does: the sqlite3 CLI, outside the application."""
    return subprocess.run(["sqlite3", str(db), sql], capture_output=True, text=True, check=True).stdout.strip()


def tamper(db, *args) -> str:
    r = subprocess.run(["bash", str(TAMPER), *args], capture_output=True, text=True, check=True,
                       env={"DATABASE_PATH": str(db), "PATH": "/usr/bin:/bin:/opt/homebrew/bin"})
    return r.stdout.strip()


def make_chain(db: Path, key, n: int = 50) -> None:
    store = Store(str(db))
    prev = record.GENESIS_HASH
    for seq in range(1, n + 1):
        decision, mode, hits = [("allow", "record", []), ("flag", "record", ["sensitive_terms"]),
                                ("block", "enforce", ["residency"])][seq % 3]
        body = dict(type="inference", ts=record.now_ts(), model_id=MODEL, model_digest=APPROVED_DIGEST,
                    node_id="auh-node-01", node_region="AE-AZ", policy_id="gov-assistant", policy_hash="a" * 64,
                    approval_ref="APR-0147", mode=mode, decision=decision, rule_hits=json.dumps(hits),
                    input_hash=record.input_hash([{"role": "user", "content": f"question {seq} سؤال"}]),
                    output_hash="" if decision == "block" else record.output_hash(f"answer {seq}"))
        rec = record.seal(body, seq, prev, key)
        store.append(rec)
        prev = rec["record_hash"]
    store.close()


@pytest.fixture
def chain(tmp_path):
    """A valid 50-record chain written by sijill.record, plus its public key."""
    key = keys.generate(tmp_path / "node.key", tmp_path / "node.pub")
    db = tmp_path / "sijill.db"
    make_chain(db, key)
    return db, tmp_path / "node.pub"


class StubResolver:
    def resolve(self, model_id: str) -> str:
        return APPROVED_DIGEST if model_id == MODEL else ""


def stub_model(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    prompt = body["messages"][-1]["content"]
    return httpx.Response(200, json={
        "id": "chatcmpl-stub", "object": "chat.completion", "model": body["model"],
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": f"Stub answer to: {prompt}"}}]})


@pytest.fixture
def node(tmp_path):
    """A running proxy (in-process) against a stub model runtime. Yields (client, settings)."""
    shutil.copy(ROOT / "policy.yaml", tmp_path / "policy.yaml")
    settings = Settings(db_path=str(tmp_path / "sijill.db"), policy_path=str(tmp_path / "policy.yaml"),
                        key_path=str(tmp_path / "node.key"), pubkey_path=str(tmp_path / "node.pub"),
                        upstream="http://model.test/v1")
    app = create_app(settings, transport=httpx.MockTransport(stub_model), resolver=StubResolver())
    with TestClient(app) as client:
        yield client, settings


@pytest.fixture
def node_with(tmp_path):
    """Factory: node_with(handler) -> (TestClient, settings) on one shared db/policy.

    Enter the client with `with client:`; each app on the same paths sees the
    previous app's chain, so restarts exercise the startup policy-drift path.
    """
    def make(handler):
        if not (tmp_path / "policy.yaml").exists():
            shutil.copy(ROOT / "policy.yaml", tmp_path / "policy.yaml")
        settings = Settings(db_path=str(tmp_path / "sijill.db"), policy_path=str(tmp_path / "policy.yaml"),
                            key_path=str(tmp_path / "node.key"), pubkey_path=str(tmp_path / "node.pub"),
                            upstream="http://model.test/v1")
        app = create_app(settings, transport=httpx.MockTransport(handler), resolver=StubResolver())
        return TestClient(app), settings
    return make


def ask(client, content: str, model: str = MODEL):
    return client.post("/v1/chat/completions",
                       json={"model": model, "messages": [{"role": "user", "content": content}], "max_tokens": 16})


def rows(db, where: str = "1=1") -> list[dict]:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    out = [dict(r) for r in conn.execute(f"SELECT * FROM records WHERE {where} ORDER BY seq")]
    conn.close()
    return out
