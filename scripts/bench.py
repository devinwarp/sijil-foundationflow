#!/usr/bin/env python3
"""Measure Sijill's latency overhead, excluding model time (acceptance test 7).

The proxy reports its own overhead per call in `X-Sijill-Overhead-Ms`: total
handler time minus the time spent waiting on the model runtime. That covers
policy evaluation, digest lookup, hashing, signing and the SQLite insert.

    python scripts/bench.py --n 100
"""

import argparse
import asyncio
import statistics
import sys
import time

import httpx


def pct(values: list[float], p: int) -> float:
    return statistics.quantiles(values, n=100, method="inclusive")[p - 1]


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--model", default="llama-3.2-3b-instruct")
    ap.add_argument("--max-tokens", type=int, default=8)
    ap.add_argument("--target-ms", type=float, default=50.0)
    args = ap.parse_args()

    body = {"model": args.model, "max_tokens": args.max_tokens,
            "messages": [{"role": "user", "content": "Reply with one word: ready."}]}
    overhead, total = [], []
    async with httpx.AsyncClient(base_url=args.url, timeout=180) as client:
        await client.post("/v1/chat/completions", json=body)  # warm-up: digest cache, model load
        for i in range(args.n):
            t = time.perf_counter()
            r = await client.post("/v1/chat/completions", json=body)
            total.append((time.perf_counter() - t) * 1000)
            if r.status_code != 200:
                print(f"call {i}: HTTP {r.status_code} {r.text[:200]}", file=sys.stderr)
                return 1
            overhead.append(float(r.headers["x-sijill-overhead-ms"]))

    p50, p95 = pct(overhead, 50), pct(overhead, 95)
    ok = p95 < args.target_ms
    print(f"calls={args.n}  model={args.model}")
    print(f"end-to-end   p50={pct(total, 50):8.1f} ms  p95={pct(total, 95):8.1f} ms  (includes model)")
    print(f"overhead     p50={p50:8.2f} ms  p95={p95:8.2f} ms  max={max(overhead):.2f} ms")
    print(f"{'PASS' if ok else 'FAIL'} p95 overhead {'<' if ok else '>='} {args.target_ms:g} ms target")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
