"""OpenAI chat-completions shape: `tool_uses` extraction (spec §17.1.1) and the inference `ext` (§3.2)."""

import json
import re

from . import record

API = "openai_chat"
PROVIDER = re.compile(r"[a-z0-9-]+")    # the <provider> of api:<provider>:<model> (verifier check G)
MODEL = re.compile(r"\S{1,256}")


def tool_use(id_, name, arguments) -> dict:
    """{id, name, args_hash}. Arguments that do not parse as JSON (nesting past the parser's limit included) hash
    as UTF-8 and carry args_raw: true."""
    use = {"id": id_ if isinstance(id_, str) else "", "name": name if isinstance(name, str) else ""}
    if not isinstance(arguments, str):
        return {**use, "args_hash": record.sha256_hex(record.canonical_json(arguments))}
    try:
        parsed = json.loads(arguments)
    except (ValueError, RecursionError):
        return {**use, "args_hash": record.sha256_hex(arguments.encode()), "args_raw": True}
    return {**use, "args_hash": record.sha256_hex(record.canonical_json(parsed))}


def tool_uses(message: dict) -> list[dict]:
    """Every choices[0].message.tool_calls[] entry of type function, in response order."""
    calls = message.get("tool_calls")
    return [tool_use(c.get("id"), c["function"].get("name"), c["function"].get("arguments", ""))
            for c in (calls if isinstance(calls, list) else [])
            if isinstance(c, dict) and c.get("type", "function") == "function" and isinstance(c.get("function"), dict)]


class StreamCalls:
    """Streamed tool calls: delta.tool_calls[i].function.arguments fragments concatenated per index."""

    def __init__(self):
        self.calls: dict[int, dict] = {}

    def add(self, delta: dict) -> None:
        calls = delta.get("tool_calls")
        for c in calls if isinstance(calls, list) else []:
            if not isinstance(c, dict) or type(c.get("index")) is not int:
                continue
            slot = self.calls.setdefault(c["index"], {"id": "", "name": "", "arguments": ""})
            fn = c.get("function") if isinstance(c.get("function"), dict) else {}
            if isinstance(c.get("id"), str) and c["id"]:
                slot["id"] = c["id"]
            if isinstance(fn.get("name"), str) and fn["name"]:
                slot["name"] = fn["name"]
            if isinstance(fn.get("arguments"), str):
                slot["arguments"] += fn["arguments"]

    def tool_uses(self) -> list[dict]:
        return [tool_use(c["id"], c["name"], c["arguments"]) for _, c in sorted(self.calls.items())]


def ext(attestation: str, *, request_hash: str, session_id: str = "", response_hash: str = "",
        provider_request_id: str = "", stop_reason: str = "", tool_uses: list | None = None, **extra) -> dict:
    """The inference ext payload. api mode: every §3.2 key, "" or [] where there is no answer.
    weights mode: nothing unless the answer requested tools, so a plain M1 answer keeps ext == ""."""
    uses = tool_uses or []
    if attestation == "api":
        x = {"api": API, "attestation": "api", "request_hash": request_hash, "system_hash": "",
             "response_hash": response_hash, "provider_request_id": provider_request_id,
             "stop_reason": stop_reason, "tool_uses": uses, "session_id": session_id}
    elif uses:
        x = {"api": API, "stop_reason": stop_reason, "tool_uses": uses}
    else:
        x = {}
    return {**x, **extra}
