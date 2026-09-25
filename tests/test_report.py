import subprocess
import sys

from conftest import ROOT, sqlite


def generate(db, pub, out, *extra):
    return subprocess.run([sys.executable, str(ROOT / "report" / "generate.py"), "--db", str(db), "--pubkey", str(pub),
                           "--out", str(out), *extra], capture_output=True, text=True)


def test_report_pdf_for_intact_chain(chain, tmp_path):
    db, pub = chain
    r = generate(db, pub, tmp_path / "r.pdf")
    assert r.returncode == 0, r.stderr
    assert "PASS records=50" in r.stdout
    assert (tmp_path / "r.pdf").read_bytes().startswith(b"%PDF")


def test_report_carries_verifier_failure(chain, tmp_path):
    db, pub = chain
    sqlite(db, "UPDATE records SET output_hash = 'x' WHERE seq = 17;")
    r = generate(db, pub, tmp_path / "r.pdf", "--from", "2000-01-01", "--to", "2100-12-31")
    assert r.returncode == 0 and "FAIL seq=17 content altered" in r.stdout
