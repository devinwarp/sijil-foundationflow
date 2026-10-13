"""The ledger's /api/agent/* endpoints as the guard sees them (spec §5.6). Every record is sealed by the ledger;
the guard holds no chain state.

Fail closed: a transport error, a 5xx, a redirect or any other non-2xx/4xx answer, and a 2xx that is not JSON are
`Unreachable`; a 4xx is `Refused`. Callers refuse the tool call (spec §5.3). Redirects are never followed.
"""

import httpx


class Unreachable(Exception):
    """No answer the guard can act on: the call does not proceed."""


class Refused(Exception):
    def __init__(self, status: int, detail):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class Ledger:
    def __init__(self, url: str, token: str = "", http: httpx.Client | None = None):
        self.token = token
        self.http = http or httpx.Client(base_url=url, timeout=10.0, follow_redirects=False)

    def call(self, method: str, path: str, session: str | None = None, task_seq: int | str | None = None,
             headers: dict | None = None, **kw) -> dict:
        h = {**({"X-Sijil-Token": self.token} if self.token else {}),
             **({"X-Sijil-Agent-Session": session} if session else {}),
             **({"X-Sijil-Task-Seq": str(task_seq)} if task_seq not in (None, "") else {}), **(headers or {})}
        try:
            r = self.http.request(method, path, headers=h, **kw)
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            raise Unreachable(f"Sijil ledger unreachable: {e}") from e
        if 400 <= r.status_code < 500:
            try:
                body = r.json()
            except ValueError:
                body = {"detail": r.text[:200]}
            raise Refused(r.status_code, body.get("detail", body) if isinstance(body, dict) else body)
        if not 200 <= r.status_code < 300:
            raise Unreachable(f"Sijil ledger unreachable: {r.status_code} {r.text[:200]}")
        try:
            return r.json()
        except ValueError as e:
            raise Unreachable(f"Sijil ledger unreachable: {r.status_code} reply is not JSON") from e

    def node_id(self) -> str:
        return self.call("GET", "/api/policy")["node_id"]

    def challenge(self, agent_id: str, purpose: str) -> str:
        return self.call("POST", "/api/agent/challenge", json={"agent_id": agent_id, "purpose": purpose})["nonce"]

    def seal(self, session: str, body: dict, task_seq=None) -> dict:
        """The ledger reads the task from the body (spec §5.6); None leaves it to the session's only open task."""
        return self.call("POST", "/api/agent/seal", session, json={
            **body, **({"task_seq": str(task_seq)} if task_seq not in (None, "") else {})})

    def parent(self, session: str, task_seq, **params) -> dict | None:
        """The parent inference (§5.4 mechanisms 1 and 2), or None when the ledger has none."""
        try:
            return self.call("GET", "/api/agent/parent", session, task_seq, params=params)
        except Refused as e:
            if e.status == 404:
                return None
            raise

    def context(self, session: str, task_seq, before_seq: int, window: str) -> dict:
        return self.call("GET", "/api/agent/context", session, task_seq,
                         params={"before_seq": before_seq, "window": window})
