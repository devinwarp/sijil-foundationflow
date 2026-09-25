#!/usr/bin/env python3
"""Generate N calls through the Sijill proxy: mostly plain questions, some with sensitive terms.

    python scripts/seed.py --n 50
"""

import argparse
import asyncio
import sys
import time

import httpx

PLAIN = [
    "What documents do I need to renew a trade licence?",
    "What are the opening hours of the customer happiness centre?",
    "How long does a building permit application usually take?",
    "Summarise the steps to register a new vehicle.",
    "How can I pay a municipality fine online?",
    "What is the process for requesting a copy of a birth certificate?",
]
SENSITIVE = [
    "My Emirates ID expired last month. How do I renew it?",
    "Can I use my passport number instead of my visa number on the form?",
]


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--model", default="llama-3.2-3b-instruct")
    ap.add_argument("--max-tokens", type=int, default=48)
    ap.add_argument("--sensitive-every", type=int, default=6, help="every Nth call carries a sensitive term")
    args = ap.parse_args()

    counts: dict[str, int] = {}
    start = time.perf_counter()
    async with httpx.AsyncClient(base_url=args.url, timeout=180) as client:
        for i in range(args.n):
            every = args.sensitive_every
            prompt = SENSITIVE[(i // every) % len(SENSITIVE)] if every and i % every == every - 1 \
                else PLAIN[i % len(PLAIN)]
            r = await client.post("/v1/chat/completions", json={
                "model": args.model, "max_tokens": args.max_tokens,
                "messages": [{"role": "user", "content": prompt}]})
            decision = r.headers.get("x-sijill-decision", f"http {r.status_code}")
            counts[decision] = counts.get(decision, 0) + 1
            print(f"seq={r.headers.get('x-sijill-seq', '?'):>5}  {decision:<6} {r.status_code}  {prompt[:60]}")
    summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"\nseeded {args.n} calls in {time.perf_counter() - start:.1f}s  {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
