from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from approvalaudit import abi, decode_call, decode_typed, load_lists
from approvalaudit.findings import SpenderLists

EX = Path(__file__).resolve().parents[1] / "examples"
NOW = 1_794_000_000 - 10 * 86_400
OWNER, DRAINER, ROUTER, TOKEN = "0x" + "0a" * 20, "0x" + "e1" * 20, "0x" + "d1" * 20, "0x" + "c1" * 20
USDC_MAINNET = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"  # public contract address used in the example


def load(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((EX / f"{name}.json").read_text())
    return doc


def codes(r) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.code for f in r.findings}


def test_eip2612_unlimited_with_long_deadline() -> None:
    r = decode_typed(load("permit-eip2612-unlimited"), load_lists(EX / "lists.json"), NOW, 1, OWNER)
    assert r.kind == "eip2612" and r.severity == "high"
    assert {"AA-UNLIMITED", "AA-SPENDER-FLAGGED", "AA-LONG-EXPIRY", "AA-ALLOWANCE-PERSISTS"} <= codes(r)
    assert r.grants[0].token == USDC_MAINNET
    assert r.digest.startswith("0x") and len(r.digest) == 66


def test_chain_and_owner_mismatch() -> None:
    r = decode_typed(load("permit-eip2612-unlimited"), None, NOW, expected_chain=8453, signer=ROUTER)
    assert {"AA-CHAIN-MISMATCH", "AA-OWNER-MISMATCH"} <= codes(r)


def test_permit2_single_never_expires() -> None:
    r = decode_typed(load("permit2-single-unlimited"), None, NOW)
    assert r.kind == "permit2-permitSingle"
    assert r.grants[0].unlimited and r.grants[0].expires is None
    assert {"AA-UNLIMITED", "AA-NO-EXPIRY"} <= codes(r)
    assert "AA-PERMIT2-IMPOSTOR" not in codes(r)


def test_permit2_impostor_domain() -> None:
    doc = load("permit2-single-unlimited")
    doc["domain"]["verifyingContract"] = "0x" + "99" * 20
    assert "AA-PERMIT2-IMPOSTOR" in codes(decode_typed(doc, None, NOW))
    doc = load("permit2-single-unlimited")
    doc["domain"]["name"] = "Permit2 "
    assert "AA-PERMIT2-IMPOSTOR" in codes(decode_typed(doc, None, NOW))


def test_permit2_batch_with_allowlisted_spender() -> None:
    r = decode_typed(load("permit2-batch"), load_lists(EX / "lists.json"), NOW)
    assert len(r.grants) == 2
    assert codes(r) == {"AA-MULTI-TOKEN"}
    assert r.severity == "medium"


def test_witness_transfer_is_shown() -> None:
    r = decode_typed(load("permit2-witness-transfer"), None, NOW)
    assert r.kind == "permit2-permitWitnessTransferFrom"
    assert r.witness == {"exampleTokenAddress": "0x" + "c3" * 20, "exampleMinimumAmountOut": "2400000"}
    assert "AA-WITNESS" in codes(r)
    assert r.grants[0].amount == 2_500_000 and not r.grants[0].unlimited


def test_expired_signature_is_info_only() -> None:
    r = decode_typed(load("permit2-witness-transfer"), None, 1_800_000_000)
    assert "AA-EXPIRED" in codes(r)
    assert r.severity == "info"


def test_dai_permit() -> None:
    doc = load("permit-eip2612-unlimited")
    doc["types"]["Permit"] = [
        {"name": "holder", "type": "address"},
        {"name": "spender", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiry", "type": "uint256"},
        {"name": "allowed", "type": "bool"},
    ]
    doc["message"] = {"holder": OWNER, "spender": DRAINER, "nonce": 0, "expiry": 0, "allowed": True}
    r = decode_typed(doc, None, NOW)
    assert r.kind == "dai-permit"
    assert {"AA-UNLIMITED", "AA-NO-EXPIRY"} <= codes(r)


def test_unrecognized_and_malformed() -> None:
    doc = load("permit-eip2612-unlimited")
    doc["primaryType"] = "Order"
    doc["types"]["Order"] = doc["types"].pop("Permit")
    assert "AA-UNRECOGNIZED" in codes(decode_typed(doc, None, NOW))
    broken = copy.deepcopy(load("permit2-batch"))
    del broken["message"]["details"][0]["nonce"]
    with pytest.raises(KeyError):
        decode_typed(broken, None, NOW)
    bad = load("permit-eip2612-unlimited")
    bad["message"]["value"] = str(1 << 256)
    assert "AA-MALFORMED" in codes(decode_typed(bad, None, NOW))


def test_calldata_approve_unlimited_and_to_permit2() -> None:
    r = decode_call(TOKEN, abi.call_data("approve", DRAINER, abi.UINT256_MAX))
    assert codes(r) == {"AA-UNLIMITED"}
    r = decode_call(TOKEN, abi.call_data("approve", abi.PERMIT2, abi.UINT256_MAX))
    assert codes(r) == {"AA-PERMIT2-ROUTER"}
    r = decode_call(TOKEN, abi.call_data("approve", ROUTER, 5))
    assert codes(r) == {"AA-AMBIGUOUS-721"}


def test_calldata_other_shapes() -> None:
    r = decode_call(TOKEN, abi.call_data("setApprovalForAll", DRAINER, True))
    assert "AA-APPROVAL-FOR-ALL" in codes(r)
    assert decode_call(TOKEN, abi.call_data("setApprovalForAll", DRAINER, False)).severity == "info"
    data = abi.call_data("permit2Approve", TOKEN, DRAINER, abi.UINT160_MAX, abi.UINT48_MAX)
    assert codes(decode_call(abi.PERMIT2, data)) == {"AA-UNLIMITED"}
    assert "AA-PERMIT2-IMPOSTOR" in codes(decode_call(TOKEN, data))
    lists = SpenderLists(allow={ROUTER: "router"})
    assert "AA-SPENDER-UNKNOWN" in codes(decode_call(TOKEN, abi.call_data("increaseAllowance", DRAINER, 10), lists))
    assert decode_call(TOKEN, "0xa9059cbb" + "00" * 64).kind == "unrecognized"


def test_pinned_selectors_and_topics() -> None:
    assert abi.SEL["approve"] == "0x095ea7b3"
    assert abi.SEL["setApprovalForAll"] == "0xa22cb465"
    assert abi.SEL["permit"] == "0xd505accf"
    assert abi.SEL["daiPermit"] == "0x8fcbaf0c"
    assert abi.SEL["allowance"] == "0xdd62ed3e"
    assert abi.SEL["isApprovedForAll"] == "0xe985e9c5"
    assert abi.TOPIC_APPROVAL_FOR_ALL == "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
