"""The agent's identity (spec §5.8): its Ed25519 key, registration, and challenge-response or OIDC sessions.

The key lives outside the repository, mode 0600; the agent's tools never need it. On a developer laptop that
makes agent_auth=key an asserted identity with a tamper-evident trail, not a proven one (spec §5.8.4).
"""

import getpass
import os
import socket
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canon import canonical_json, sha256_hex
from .ledger import Ledger


def proof(key: Ed25519PrivateKey, msg: dict) -> str:
    """Ed25519 over the 32 raw bytes of sha256(canonical_json(msg)) (spec §5.8.2, §2.4.7)."""
    return key.sign(bytes.fromhex(sha256_hex(canonical_json(msg)))).hex()


def pubkey(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def _inside(path: str, root: str) -> bool:
    p, r = os.path.realpath(path), os.path.realpath(root)
    return p == r or p.startswith(r.rstrip("/") + "/")


def create_key(path: str, repo: str) -> Ed25519PrivateKey:
    """A new key at `path`, which must be outside the repository (spec §5.2). Never overwrites."""
    if _inside(path, repo):
        raise ValueError(f"{path}: the agent key must live outside the repository ({repo})")
    Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def ensure_key(path: str, repo: str) -> Ed25519PrivateKey:
    """`identity init` is safe to repeat: an existing key is loaded (never overwritten or deleted), else created."""
    if not os.path.lexists(path):
        return create_key(path, repo)
    if _inside(path, repo):
        raise ValueError(f"{path}: the agent key must live outside the repository ({repo})")
    return load_key(path)


def load_key(path: str) -> Ed25519PrivateKey:
    fd = os.open(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as f:                   # check the file we read, not the name (no TOCTOU)
        st = os.fstat(f.fileno())
        if st.st_uid != os.geteuid():
            raise ValueError(f"{path}: the agent key is not owned by you")
        if st.st_mode & 0o077:
            raise ValueError(f"{path}: the agent key is readable by other users; chmod 600 it")
        try:
            key = serialization.load_pem_private_key(f.read(), password=None)
        except ValueError as e:
            raise ValueError(f"{path}: not a usable key file (empty or corrupt); remove it and run "
                             f"identity init again") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: not an Ed25519 key")
    return key


def local_principal() -> str:
    """`principal: auto` on a laptop: local:<sha256 of user@host> (spec §5.2)."""
    return "local:" + sha256_hex(f"{getpass.getuser()}@{socket.gethostname()}".encode())


def register(ledger: Ledger, agent_id: str, key: Ed25519PrivateKey, registered_by: str, display_name: str = "",
             admin_token: str = "") -> int:
    """Seal agent_register for a key agent (spec §2.4.7). Under register_policy: closed the operator's admin
    token is required; under principal_oidc the ledger takes registered_by from the principal token."""
    nonce = ledger.challenge(agent_id, "register")
    msg = {"agent_id": agent_id, "agent_pubkey": pubkey(key), "nonce": nonce, "registered_by": registered_by}
    body = {**msg, "self_proof": proof(key, msg), **({"display_name": display_name} if display_name else {})}
    headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
    return ledger.call("POST", "/api/agent/register", json=body, headers=headers)["seq"]


def github_token(node_id: str, http: httpx.Client | None = None) -> str | None:
    """A GitHub Actions OIDC token for audience sijil:<node_id>, when the job has id-token: write (§5.8.5)."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        return None
    r = (http or httpx.Client(timeout=10.0)).get(url, params={"audience": f"sijil:{node_id}"},
                                                  headers={"Authorization": f"bearer {bearer}"})
    r.raise_for_status()
    return r.json()["value"]


def open_session(ledger: Ledger, cfg, key: Ed25519PrivateKey | None = None, http: httpx.Client | None = None) -> dict:
    """{agent_session, agent_auth, principal, principal_auth, expires_at}. The ledger, not the guard, decides
    both auth stamps (spec §5.8.1)."""
    if cfg.auth == "oidc":
        token = os.environ.get(cfg.oidc_token_env) or github_token(ledger.node_id(), http)
        if not token:
            raise ValueError(f"no OIDC token: set {cfg.oidc_token_env} or run in a job with id-token: write")
        return ledger.call("POST", "/api/agent/session", json={"oidc_token": token})
    key = key or load_key(cfg.key_path)
    nonce = ledger.challenge(cfg.agent_id, "session")
    msg = {"agent_id": cfg.agent_id, "node_id": ledger.node_id(), "nonce": nonce, "purpose": "session"}
    return ledger.call("POST", "/api/agent/session",
                       json={"agent_id": cfg.agent_id, "nonce": nonce, "proof": proof(key, msg)})
