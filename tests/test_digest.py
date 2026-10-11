import asyncio
import hashlib
from pathlib import Path

from sijill.digest import DigestResolver
from sijill.proxy import Node, Settings


def _weights(tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "m.gguf").write_bytes(b"weights")
    return models, "sha256:" + hashlib.sha256(b"weights").hexdigest()


def test_unwritable_cache_keeps_digest(tmp_path, capsys):
    models, want = _weights(tmp_path)
    r = DigestResolver(models, cache_path=tmp_path / "no-such-dir" / "cache.json")
    assert r.resolve("m") == want
    assert r.resolve("m") == want  # served from memory
    assert "digest cache" in capsys.readouterr().err


def test_digest_cache_env_reaches_resolver(tmp_path, monkeypatch):
    monkeypatch.setenv("SIJILL_DIGEST_CACHE", str(tmp_path / "d.json"))
    s = Settings.from_env()
    assert s.digest_cache == str(tmp_path / "d.json")
    assert Settings().digest_cache == ".sijill_digests.json"
    (tmp_path / "policy.yaml").write_text((Path(__file__).parent.parent / "policy.yaml").read_text())
    node = Node(Settings(db_path=str(tmp_path / "s.db"), policy_path=str(tmp_path / "policy.yaml"),
                         key_path=str(tmp_path / "k"), pubkey_path=str(tmp_path / "p"),
                         digest_cache=s.digest_cache))
    try:
        assert node.resolver.cache_path == tmp_path / "d.json"
    finally:
        node.store.close()
        asyncio.run(node.aclose())
