#!/usr/bin/env python3
"""Forward Sijil ledger records to a SIEM as CEF over syslog (RFC 5424; UDP, or TCP newline-framed).

    python scripts/siem_forward.py --url http://127.0.0.1:8000 --sink siem.local:514 [--tcp]

Stdlib only. Remembers the last forwarded seq in --state so restarts neither skip nor repeat records.
"""

import argparse
import json
import socket
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

SEVERITY = {"block": 8, "flag": 5}          # CEF 0-10; anything else 3
SYSLOG_PRI = {"block": 132, "flag": 133}    # local0.warning, local0.notice; else local0.info (134)


def _hdr(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _ext(v) -> str:
    return (str(v).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def cef(rec: dict) -> str:
    t, d = rec["type"], rec["decision"]
    rt = int(datetime.fromisoformat(rec["ts"].replace("Z", "+00:00")).timestamp() * 1000)
    hits = ",".join(json.loads(rec.get("rule_hits") or "[]"))
    ext = {"rt": rt, "dvchost": rec["node_id"], "act": d, "cn1Label": "seq", "cn1": rec["seq"],
           "cs1Label": "policy", "cs1": rec["policy_id"], "cs2Label": "rule_hits", "cs2": hits,
           "cs3Label": "record_hash", "cs3": rec["record_hash"], "cs4Label": "model", "cs4": rec.get("model_id", "")}
    head = f"CEF:0|FoundationFlow|Sijil|1|{_hdr(f'{t}:{d}')}|{_hdr(f'{t} {d}')}|{SEVERITY.get(d, 3)}|"
    return head + " ".join(f"{k}={_ext(v)}" for k, v in ext.items())


def syslog_line(rec: dict, host: str) -> str:
    return f"<{SYSLOG_PRI.get(rec['decision'], 134)}>1 {rec['ts']} {host} sijil - - - {cef(rec)}"


def send_udp(addr: tuple[str, int], line: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode(), addr)


def run(url: str, sink: tuple[str, int], state_path: Path, tcp: bool = False, interval: float = 2.0,
        token: str = "", once: bool = False) -> int:
    """Forward records after the saved seq. `once` drains the whole backlog, then returns."""
    last = int(state_path.read_text()) if state_path.exists() else 0
    conn = socket.create_connection(sink) if tcp else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        while True:
            with urlopen(Request(f"{url}/api/records?after={last}&limit=1000", headers=headers)) as r:
                page = json.load(r)["records"]
            for rec in page:
                line = syslog_line(rec, rec["node_id"])
                conn.sendall((line + "\n").encode()) if conn else send_udp(sink, line)
                last = rec["seq"]
            if page:
                state_path.write_text(str(last))
            if not page:
                if once:
                    return last
                time.sleep(interval)
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--sink", required=True, help="host:port of the syslog receiver")
    ap.add_argument("--tcp", action="store_true")
    ap.add_argument("--state", default=".siem_state")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()
    host, port = a.sink.rsplit(":", 1)
    run(a.url, (host, int(port)), Path(a.state), a.tcp, a.interval)
