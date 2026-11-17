"""Typed-data decodes per second and a scan over a synthetic chain with many approvals."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from chain import OWNER, FakeChain, addr, block_time  # noqa: E402

from approvalaudit import Rpc, decode_typed, scan  # noqa: E402


def main() -> None:
    doc = json.loads((ROOT / "examples" / "permit2-batch.json").read_text())
    n = 2_000
    t0 = time.perf_counter()
    for _ in range(n):
        decode_typed(doc, now=1_790_000_000)
    print(f"{n} typed-data decodes in {time.perf_counter() - t0:.2f}s")
    c = FakeChain()
    for i in range(500):
        c.approve20(addr(f"{i % 200 + 16:02x}"), addr(f"{i % 50 + 100:02x}"), i + 1, 1_000_000 + i)
    t0 = time.perf_counter()
    rows = scan(Rpc(c), OWNER, now=block_time(2_000_000))
    print(f"scan of 500 approval events, {len(rows)} live rows, in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    main()
