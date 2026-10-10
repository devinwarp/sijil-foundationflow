"""CEF formatting and lossless forwarding of the ledger to a SIEM."""

import importlib.util
import json
import socket

from conftest import ROOT, ask
from sijill.store import Store

spec = importlib.util.spec_from_file_location("siem_forward", ROOT / "scripts" / "siem_forward.py")
siem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(siem)

REC = {"seq": 7, "type": "inference", "ts": "2026-10-10T08:00:00.000Z", "model_id": "m|x",
       "node_id": "auh-node-01", "policy_id": "gov=assistant", "decision": "block",
       "rule_hits": '["residency","approved_models"]', "record_hash": "ab" * 32}


def test_cef_header_and_escaping():
    line = siem.cef(REC)
    assert line.startswith("CEF:0|FoundationFlow|Sijil|1|inference:block|inference block|8|")
    assert "cs1=gov\\=assistant" in line            # '=' escaped in extension values
    assert "cs4=m|x" in line                         # '|' is legal in extension values
    assert "cs2=residency,approved_models" in line
    assert "cn1=7" in line and "rt=1791619200000" in line


def test_severity_by_decision():
    assert "|8|" in siem.cef({**REC, "decision": "block"})
    assert "|5|" in siem.cef({**REC, "decision": "flag"})
    assert "|3|" in siem.cef({**REC, "decision": "allow"})


def test_after_reads_oldest_first(chain):
    db, _ = chain
    store = Store(str(db))
    assert [r["seq"] for r in store.after(0, 5)] == [1, 2, 3, 4, 5]
    assert [r["seq"] for r in store.after(48, 5)] == [49, 50]


def test_api_after_pages_without_skipping(node):
    client, _ = node
    for i in range(7):
        ask(client, f"q{i}")
    first = client.get("/api/records?after=0&limit=3").json()["records"]
    second = client.get("/api/records?after=3&limit=3").json()["records"]
    assert [r["seq"] for r in first + second] == [1, 2, 3, 4, 5, 6]


def test_syslog_over_udp(tmp_path):
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    siem.send_udp(("127.0.0.1", sink.getsockname()[1]), siem.syslog_line(REC, "auh-node-01"))
    data = sink.recv(65535).decode()
    assert data.startswith("<132>1 2026-10-10T08:00:00.000Z auh-node-01 sijil - - - CEF:0|")
