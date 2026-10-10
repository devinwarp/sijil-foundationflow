#!/usr/bin/env python3
"""Forward Sijil ledger records to a SIEM as CEF over syslog (RFC 5424).

    python scripts/siem_forward.py --url http://127.0.0.1:8000 --sink siem.local:514 [--udp]

Transport is TCP (newline-framed) by default. --udp opts in to UDP, which is fire-and-forget:
it can silently drop records under load, so use it only where the SIEM cannot take TCP.

Stdlib only. Remembers the last forwarded seq in --state. Delivery is at-least-once: a crash
mid-page resends up to one page on restart; no record is skipped.
"""

import argparse
import json
import os
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


def _load_state(path: Path) -> int:
    return int(path.read_text()) if path.exists() else 0


def _save_state(path: Path, seq: int) -> None:
    tmp = path.with_name(path.name + ".tmp")     # same directory, so os.replace is atomic
    tmp.write_text(str(seq))
    os.replace(tmp, path)


def run(url: str, sink: tuple[str, int], state_path: Path, udp: bool = False, interval: float = 2.0,
        token: str = "", once: bool = False, page: int = 1000) -> int:
    """Forward records after the saved seq; returns the last forwarded seq.

    `once` drains the whole backlog then returns, and errors propagate. Otherwise the loop
    retries forever: on a network error or a response that is not the records JSON (e.g. an SSO
    login page) it sleeps, reconnects TCP, and resumes from the saved seq.
    State advances only after a whole page has been sent.
    """
    state = _load_state(state_path)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    conn = None
    try:
        while True:
            try:
                if not udp and conn is None:
                    conn = socket.create_connection(sink)
                with urlopen(Request(f"{url}/api/records?after={state}&limit={page}", headers=headers)) as r:
                    recs = json.load(r)["records"]
                cursor = state
                for rec in recs:
                    line = syslog_line(rec, rec["node_id"])
                    if udp:
                        send_udp(sink, line)
                    else:
                        conn.sendall((line + "\n").encode())
                    cursor = rec["seq"]
            except (OSError, ValueError, KeyError):  # ValueError/KeyError: not the records API (e.g. SSO page)
                if once:
                    raise
                if conn is not None:
                    conn.close()
                    conn = None
                time.sleep(interval)
                continue
            if recs:
                _save_state(state_path, cursor)
                state = cursor
            elif once:
                return state
            else:
                time.sleep(interval)
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--sink", required=True, help="host:port of the syslog receiver")
    ap.add_argument("--udp", action="store_true", help="UDP instead of TCP; may drop records under load")
    ap.add_argument("--state", default=".siem_state")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()
    host, port = a.sink.rsplit(":", 1)
    run(a.url, (host, int(port)), Path(a.state), udp=a.udp, interval=a.interval)
