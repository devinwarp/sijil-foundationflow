"""Admin endpoints: token required; no token configured means disabled, never open."""

import shutil

import httpx
from fastapi.testclient import TestClient

from conftest import ADMIN_TOKEN, ROOT, StubResolver, rows, stub_model
from sijill.proxy import Settings, create_app


def make_client(tmp_path, admin_token: str, headers: dict | None = None) -> tuple[TestClient, Settings]:
    shutil.copy(ROOT / "policy.yaml", tmp_path / "policy.yaml")
    s = Settings(db_path=str(tmp_path / "sijill.db"), policy_path=str(tmp_path / "policy.yaml"),
                 key_path=str(tmp_path / "node.key"), pubkey_path=str(tmp_path / "node.pub"),
                 upstream="http://model.test/v1", admin_token=admin_token,
                 halt_path=str(tmp_path / "sijill.halt"))
    app = create_app(s, transport=httpx.MockTransport(stub_model), resolver=StubResolver())
    return TestClient(app, headers=headers or {}), s


def test_admin_without_token_is_401_and_seals_nothing(tmp_path):
    client, s = make_client(tmp_path, ADMIN_TOKEN)
    with client:
        r = client.post("/api/admin/node/region", json={"region": "US-VA"})
        assert r.status_code == 401
        assert client.post("/api/admin/policy/reload").status_code == 401
    assert rows(s.db_path) == []


def test_admin_with_wrong_token_is_401(tmp_path):
    client, _ = make_client(tmp_path, ADMIN_TOKEN, {"Authorization": "Bearer nope"})
    with client:
        assert client.post("/api/admin/policy/reload").status_code == 401


def test_admin_with_token_works(tmp_path):
    client, s = make_client(tmp_path, ADMIN_TOKEN, {"Authorization": f"Bearer {ADMIN_TOKEN}"})
    with client:
        r = client.post("/api/admin/node/region", json={"region": "US-VA"})
        assert r.status_code == 200 and r.json()["seq"] == 1


def test_no_token_configured_disables_admin(tmp_path):
    client, _ = make_client(tmp_path, "", {"Authorization": "Bearer "})
    with client:
        assert client.post("/api/admin/policy/reload").status_code == 503
        assert client.get("/api/policy").json()["admin_auth"] == "disabled"


def test_policy_reports_token_auth(tmp_path):
    client, _ = make_client(tmp_path, ADMIN_TOKEN)
    with client:
        assert client.get("/api/policy").json()["admin_auth"] == "token"
