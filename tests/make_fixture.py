"""Rebuild tests/fixtures/scan.json from the fake chain: python tests/make_fixture.py"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from chain import DAY, OWNER, FakeChain, addr, block_time

from approvalaudit import RecordingTransport, Rpc, abi, scan

NOW = block_time(2_000_000)


def build() -> FakeChain:
    c = FakeChain()
    c.contracts |= {addr("c1"), addr("c2"), addr("d1"), abi.PERMIT2}
    c.approve20(addr("c1"), addr("e1"), abi.UINT256_MAX, 1_999_000)
    c.approve20(addr("c1"), abi.PERMIT2, abi.UINT256_MAX, 1_500_000)
    c.permit2(addr("c1"), addr("d1"), 5_000_000, NOW + 20 * DAY, 1_999_900)
    c.for_all(addr("c2"), addr("d1"), True, 1_200_000)
    return c


if __name__ == "__main__":
    rec = RecordingTransport(build())
    scan(Rpc(rec), OWNER, now=NOW)
    rec.save(Path(__file__).parent / "fixtures" / "scan.json")
