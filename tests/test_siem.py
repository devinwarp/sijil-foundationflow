"""CEF formatting and lossless forwarding of the ledger to a SIEM."""

import importlib.util
import json
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

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


def test_backlog_larger_than_one_page_forwards_contiguously(chain, tmp_path):
    db, _ = chain                                    # 50 records
    store = Store(str(db))

    class Pages(BaseHTTPRequestHandler):
        def do_GET(self):
            q = parse_qs(urlparse(self.path).query)
            body = json.dumps({"records": store.after(int(q["after"][0]), int(q["limit"][0]))}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    http = HTTPServer(("127.0.0.1", 0), Pages)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received = []

    def reader():
        conn, _ = listener.accept()
        with conn:
            buf = b""
            while chunk := conn.recv(65535):
                buf += chunk
        received.extend(buf.decode().splitlines())

    t = threading.Thread(target=reader)
    t.start()
    state = tmp_path / "siem.state"
    try:
        last = siem.run(f"http://127.0.0.1:{http.server_port}", ("127.0.0.1", listener.getsockname()[1]),
                        state, page=3, once=True)
        t.join(5)
    finally:
        http.shutdown()
        http.server_close()
        listener.close()
    seqs = [int(re.search(r" cn1=(\d+) ", line).group(1)) for line in received]
    assert seqs == list(range(1, 51))
    assert last == 50 and state.read_text() == "50"


def test_daemon_survives_non_json_response(tmp_path, monkeypatch, capsys):
    """An SSO proxy answering with an HTML login page must not kill the daemon; it retries and says so."""
    import pytest
    served = []

    class LoginThenRecords(BaseHTTPRequestHandler):
        def do_GET(self):
            served.append(self.path)
            if len(served) == 1:
                body, ctype = b"<html>Sign in</html>", "text/html"
            else:
                after = int(parse_qs(urlparse(self.path).query)["after"][0])
                body, ctype = json.dumps({"records": [REC] if after < REC["seq"] else []}).encode(), "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class Stop(Exception):
        pass

    sleeps = []

    def sleep(_):                      # 1st: retry after the HTML page; 2nd: idle with nothing new, stop
        sleeps.append(1)
        if len(sleeps) == 2:
            raise Stop

    monkeypatch.setattr(siem.time, "sleep", sleep)
    http = HTTPServer(("127.0.0.1", 0), LoginThenRecords)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    url, state = f"http://127.0.0.1:{http.server_port}", tmp_path / "siem.state"
    try:
        with pytest.raises(Stop):
            siem.run(url, ("127.0.0.1", sink.getsockname()[1]), state, udp=True)
        err = capsys.readouterr().err.splitlines()
        assert len(err) == 1 and "JSONDecodeError" in err[0]
        assert "attempt 1" in err[0] and "retrying in 2.0s" in err[0]
        served.clear()
        with pytest.raises(ValueError):  # once mode still propagates
            siem.run(url, ("127.0.0.1", sink.getsockname()[1]), tmp_path / "other.state", udp=True, once=True)
    finally:
        http.shutdown()
        http.server_close()
    assert " cn1=7 " in sink.recv(65535).decode()
    assert state.read_text() == "7"
    sink.close()
