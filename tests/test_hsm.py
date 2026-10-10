"""Signing with a key that never leaves a PKCS#11 token (SoftHSM2 in tests)."""

import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import ADMIN, ADMIN_TOKEN, ROOT, StubResolver, ask, stub_model, verify
from sijill.proxy import Settings, create_app

MODULE = next((p for p in ("/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so",
                           "/usr/lib/softhsm/libsofthsm2.so") if Path(p).exists()), None)
pytestmark = pytest.mark.skipif(not MODULE or not shutil.which("pkcs11-tool"),
                                reason="SoftHSM2 and OpenSC not installed")


@pytest.fixture
def hsm(tmp_path, monkeypatch):
    (tmp_path / "tokens").mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tmp_path / 'tokens'}\nobjectstore.backend = file\n")
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "sijil", "--pin", "1234",
                    "--so-pin", "5678"], check=True, capture_output=True)
    subprocess.run(["pkcs11-tool", "--module", MODULE, "--token-label", "sijil", "--login", "--pin", "1234",
                    "--keypairgen", "--key-type", "EC:edwards25519", "--label", "node"],
                   check=True, capture_output=True)
    return MODULE


def settings(tmp_path, module: str) -> Settings:
    shutil.copy(ROOT / "policy.yaml", tmp_path / "policy.yaml")
    return Settings(db_path=str(tmp_path / "sijill.db"), policy_path=str(tmp_path / "policy.yaml"),
                    key_path=str(tmp_path / "node.key"), pubkey_path=str(tmp_path / "node.pub"),
                    upstream="http://model.test/v1", admin_token=ADMIN_TOKEN, pkcs11_module=module,
                    pkcs11_token="sijil", pkcs11_key="node", pkcs11_pin="1234")


def test_signer_signature_verifies(hsm):
    from sijill.hsm import Pkcs11Signer
    signer = Pkcs11Signer(hsm, "sijil", "node", "1234")
    try:
        signer.public_key().verify(signer.sign(b"\x01" * 32), b"\x01" * 32)  # raises if invalid
    finally:
        signer.close()  # SoftHSM tracks login per token; a lingering session breaks the next test


def test_proxy_chain_signed_in_hsm_passes_verifier(hsm, tmp_path):
    s = settings(tmp_path, hsm)
    app = create_app(s, transport=httpx.MockTransport(stub_model), resolver=StubResolver())
    with TestClient(app, headers=ADMIN) as client:
        for i in range(3):
            assert ask(client, f"q{i}").status_code == 200
    assert not Path(s.key_path).exists()  # no key file was ever written
    assert verify(s.db_path, s.pubkey_path)[1].startswith("PASS records=3")


def test_unreachable_hsm_refuses_to_start(hsm, tmp_path):
    s = settings(tmp_path, hsm)
    s.pkcs11_pin = "wrong"
    app = create_app(s, transport=httpx.MockTransport(stub_model), resolver=StubResolver())
    with pytest.raises(Exception):
        with TestClient(app):
            pass
    assert not Path(s.key_path).exists()
