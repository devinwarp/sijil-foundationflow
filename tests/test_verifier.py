"""Acceptance tests 1-4 (docs/README.md) against a chain written by sijill.record,
tampered with the sqlite3 CLI and scripts/tamper.sh — never through the application."""

from conftest import sqlite, tamper, verify


def test_1_valid_chain_passes(chain):
    code, out = verify(*chain)
    assert code == 0
    assert out.startswith("PASS records=50 first=") and " last=" in out


def test_2_altered_output_hash_is_content_altered(chain):
    db, pub = chain
    sqlite(db, "UPDATE records SET output_hash = '" + "d" * 64 + "' WHERE seq = 17;")
    assert sqlite(db, "SELECT output_hash FROM records WHERE seq = 17;") == "d" * 64
    assert verify(db, pub) == (1, "FAIL seq=17 content altered")


def test_3_forged_hash_without_key_is_signature_invalid(chain):
    """The attacker knows the algorithm and recomputes record_hash with only sqlite3 and shasum.
    Getting `signature invalid` rather than `content altered` proves the forged hash is canonical."""
    db, pub = chain
    before = sqlite(db, "SELECT record_hash FROM records WHERE seq = 17;")
    tamper(db, "forge", "17")
    assert sqlite(db, "SELECT record_hash FROM records WHERE seq = 17;") != before
    assert verify(db, pub) == (1, "FAIL seq=17 signature invalid")


def test_4_deleted_record_is_gap_at_next_seq(chain):
    db, pub = chain
    sqlite(db, "DELETE FROM records WHERE seq = 17;")
    assert verify(db, pub) == (1, "FAIL seq=18 gap")


def test_chain_broken_when_prev_hash_rewritten_and_rehashed(chain):
    db, pub = chain
    sqlite(db, "UPDATE records SET prev_hash = '" + "e" * 64 + "' WHERE seq = 17;")
    tamper(db, "forge", "17")  # recompute record_hash over the rewritten prev_hash
    assert verify(db, pub) == (1, "FAIL seq=17 chain broken")


def test_first_record_must_chain_from_genesis(chain):
    db, pub = chain
    sqlite(db, "UPDATE records SET prev_hash = '" + "1" * 64 + "' WHERE seq = 1;")
    tamper(db, "forge", "1")
    assert verify(db, pub) == (1, "FAIL seq=1 chain broken")


def test_tamper_alter_then_restore(chain):
    db, pub = chain
    assert tamper(db, "backup").startswith("backup   50 records")
    tamper(db, "alter", "17")
    assert verify(db, pub) == (1, "FAIL seq=17 content altered")
    assert tamper(db, "restore") == "restore  1 record(s) returned to their sealed state"
    assert verify(db, pub)[0] == 0


def test_wrong_public_key_fails_at_first_record(chain, tmp_path):
    from sijill import keys
    db, _ = chain
    keys.generate(tmp_path / "other.key", tmp_path / "other.pub")
    assert verify(db, tmp_path / "other.pub") == (1, "FAIL seq=1 signature invalid")


def test_hex_public_key_accepted(chain, tmp_path):
    from cryptography.hazmat.primitives import serialization
    db, pub = chain
    key = serialization.load_pem_public_key(pub.read_bytes())
    hex_pub = tmp_path / "node.hex"
    hex_pub.write_text(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    assert verify(db, hex_pub)[0] == 0


def test_empty_and_missing_database(tmp_path, chain):
    _, pub = chain
    sqlite(tmp_path / "empty.db", "CREATE TABLE records (seq INTEGER PRIMARY KEY, type TEXT, ts TEXT, "
           "model_id TEXT, model_digest TEXT, node_id TEXT, node_region TEXT, policy_id TEXT, policy_hash TEXT, "
           "approval_ref TEXT, mode TEXT, decision TEXT, rule_hits TEXT, input_hash TEXT, output_hash TEXT, "
           "prev_hash TEXT, record_hash TEXT, signature TEXT);")
    assert verify(tmp_path / "empty.db", pub) == (0, "PASS records=0 first=- last=-")
    code, out = verify(tmp_path / "nope.db", pub)
    assert code == 1 and out.startswith("FAIL database not found")
