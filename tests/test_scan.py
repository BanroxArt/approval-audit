from __future__ import annotations

import json
from pathlib import Path

import pytest
from chain import DAY, OWNER, FakeChain, addr, block_time
from hypothesis import given, settings
from hypothesis import strategies as st

from approvalaudit import FixtureTransport, RecordingTransport, Rpc, SpenderLists, abi, scan
from approvalaudit.scan import collect

USDX, NFT, DEX, DRAINER, VAULT = addr("c1"), addr("c2"), addr("d1"), addr("e1"), addr("d2")
NOW = block_time(2_000_000)
MAX = abi.UINT256_MAX


def chain() -> FakeChain:
    c = FakeChain()
    c.contracts |= {USDX, NFT, DEX, VAULT, abi.PERMIT2}
    return c


def by(rows, standard: str, spender: str):  # type: ignore[no-untyped-def]
    return next(r for r in rows if r.standard == standard and r.spender == spender)


def codes(r) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.code for f in r.findings}


def test_unlimited_approval_to_a_plain_account_is_high() -> None:
    c = chain()
    c.approve20(USDX, DRAINER, MAX, 1_999_000)
    c.approve20(USDX, DEX, 5_000_000, 1_999_500)
    rows = scan(Rpc(c), OWNER, now=NOW)
    drained = by(rows, "erc20", DRAINER)
    assert drained.severity == "high"
    assert codes(drained) == {"AA-UNLIMITED", "AA-SPENDER-EOA"}
    assert by(rows, "erc20", DEX).severity == "info"
    assert rows[0].spender == DRAINER  # worst first


def test_spent_down_allowance_is_not_live() -> None:
    c = chain()
    c.approve20(USDX, DEX, 1_000, 1_000_000, current=0)
    assert scan(Rpc(c), OWNER, now=NOW) == []
    rows = scan(Rpc(c), OWNER, now=NOW, include_inactive=True)
    assert codes(rows[0]) == {"AA-INACTIVE"}


def test_latest_event_wins_and_reapproval_to_zero_clears() -> None:
    c = chain()
    c.approve20(USDX, DEX, MAX, 1_000_000)
    c.approve20(USDX, DEX, 0, 1_500_000)
    assert scan(Rpc(c), OWNER, now=NOW) == []


def test_nft_token_and_operator_approvals() -> None:
    c = chain()
    c.approve721(NFT, VAULT, 7, 1_900_000)
    c.approve721(NFT, VAULT, 8, 1_900_001)
    c.approve721(NFT, "0x" + "0" * 40, 8, 1_900_002)
    c.nft[(NFT, 8)] = "0x" + "0" * 40
    c.for_all(NFT, DEX, True, 1_900_003)
    c.for_all(NFT, VAULT, True, 1_900_004)
    c.for_all(NFT, VAULT, False, 1_900_005)
    rows = scan(Rpc(c), OWNER, now=NOW)
    assert {(r.standard, r.spender, r.token_id) for r in rows} == {
        ("erc721-token", VAULT, 7),
        ("erc721-all", DEX, None),
    }
    assert "AA-APPROVAL-FOR-ALL" in codes(by(rows, "erc721-all", DEX))


def test_permit2_rows() -> None:
    c = chain()
    c.approve20(USDX, abi.PERMIT2, MAX, 1_000_000)
    c.permit2(USDX, DEX, abi.UINT160_MAX, NOW + 30 * DAY, 1_999_000)
    c.permit2(USDX, VAULT, 10_000, NOW - 1, 1_999_100)  # expired
    c.permit2(USDX, DRAINER, 50_000, NOW + 900 * DAY, 1_999_200)
    rows = scan(Rpc(c), OWNER, now=NOW)
    assert codes(by(rows, "erc20", abi.PERMIT2)) == {"AA-PERMIT2-ROUTER"}
    assert codes(by(rows, "permit2", DEX)) == {"AA-UNLIMITED"}
    assert codes(by(rows, "permit2", DRAINER)) == {"AA-SPENDER-EOA", "AA-LONG-EXPIRY"}
    assert not any(r.spender == VAULT for r in rows)
    to, data = by(rows, "permit2", DEX).revoke()
    assert to == abi.PERMIT2 and data.startswith(abi.SEL["permit2Approve"])


def test_lists_and_stale() -> None:
    c = chain()
    c.approve20(USDX, DEX, 100, 100_000)  # about 263 days before head
    c.approve20(USDX, VAULT, 100, 1_999_000)
    lists = SpenderLists(allow={VAULT: "our vault"}, flagged={})
    rows = scan(Rpc(c), OWNER, now=NOW, lists=lists)
    assert codes(by(rows, "erc20", DEX)) == {"AA-SPENDER-UNKNOWN", "AA-STALE"}
    assert by(rows, "erc20", VAULT).label == "our vault"
    lists.flagged[DEX] = ("drainer contract", "published postmortem")
    rows = scan(Rpc(c), OWNER, now=NOW, lists=lists)
    assert "AA-SPENDER-FLAGGED" in codes(by(rows, "erc20", DEX))


def test_log_ranges_are_split_when_the_node_refuses() -> None:
    c = chain()
    c.max_range = 3_000
    c.approve20(USDX, DEX, 100, 1_234_567)
    rows = scan(Rpc(c), OWNER, from_block=1_200_000, now=NOW, chunk=50_000)
    assert len(rows) == 1
    c.max_range = 10
    with pytest.raises(Exception, match="narrow"):
        scan(Rpc(c), OWNER, from_block=1_200_000, now=NOW, chunk=50_000)


def test_non_standard_token_falls_back_to_the_event() -> None:
    c = chain()
    c.approve20(USDX, DEX, 500, 1_999_000)
    c.broken.add(USDX)
    rows = scan(Rpc(c), OWNER, now=NOW)
    assert "AA-STATE-UNKNOWN" in codes(rows[0])
    assert rows[0].amount == 500


def test_rpc_refuses_anything_but_reads() -> None:
    rpc = Rpc(chain())
    for m in ("eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "personal_sign", "eth_signTypedData_v4"):
        with pytest.raises(PermissionError):
            rpc.call(m, [])


def test_record_and_replay(tmp_path: Path) -> None:
    c = chain()
    c.approve20(USDX, DRAINER, MAX, 1_999_000)
    c.for_all(NFT, DEX, True, 1_999_001)
    rec = RecordingTransport(c)
    first = [r.to_dict() for r in scan(Rpc(rec), OWNER, now=NOW)]
    f = tmp_path / "rec.json"
    rec.save(f)
    again = [r.to_dict() for r in scan(Rpc(FixtureTransport(f)), OWNER, now=NOW)]
    assert first == again
    assert json.loads(f.read_text())


@settings(max_examples=50, deadline=None)
@given(st.lists(st.tuples(st.sampled_from([DEX, VAULT, DRAINER]), st.integers(0, 2**256 - 1)), min_size=1, max_size=12))
def test_collect_keeps_the_last_event_per_spender(events: list[tuple[str, int]]) -> None:
    c = FakeChain()
    for i, (sp, amt) in enumerate(events):
        c.approve20(USDX, sp, amt, 1_000 + i)
    got = {k[2]: v.amount for k, v in collect(list(reversed(c.logs))).items()}
    want: dict[str, int] = {}
    for sp, amt in events:
        want[sp] = amt
    assert got == want


def test_token_filter_limits_the_search() -> None:
    c = chain()
    c.approve20(USDX, DRAINER, MAX, 1_999_000)
    c.approve20(VAULT, DRAINER, MAX, 1_999_001)
    rows = scan(Rpc(c), OWNER, now=NOW, tokens=[VAULT])
    assert [r.token for r in rows] == [VAULT]
