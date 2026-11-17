"""Find every approval an address has granted and what is still live.

Steps:

1. ``eth_getLogs`` for ERC-20 and ERC-721 ``Approval`` and ``ApprovalForAll``
   events with the owner as the first indexed topic, from any contract, and for
   Permit2 ``Approval`` and ``Permit`` events. Block ranges are split, and split
   again when a node refuses a range.
2. Keep the latest event per (standard, token, spender, token id).
3. Ask the token (or Permit2) for the current state with ``eth_call``, because
   allowances are spent down by ``transferFrom`` without an event and Permit2
   allowances expire on their own.
4. For each live approval, check the spender (contract or plain account, your
   lists) and how long ago it was granted.

An ERC-20 ``Approval`` has three topics and the amount in data; an ERC-721
``Approval`` has the same signature with the token id as a fourth topic. That
is how the two are told apart.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from . import abi
from .findings import Finding, SpenderLists, spender_findings, worst
from .permits import unlimited
from .rpc import Rpc, RpcError

ZERO = "0x" + "0" * 40


@dataclass
class Allowance:
    standard: str  # erc20, erc721-token, erc721-all, permit2
    token: str
    spender: str
    token_id: int | None
    last_block: int
    last_tx: str
    amount: int | None = None
    live: bool = False
    expiration: int | None = None
    granted_at: int | None = None
    spender_is_contract: bool | None = None
    state_known: bool = True
    label: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return worst(self.findings)

    def revoke(self) -> tuple[str, str]:
        """(to, calldata) that removes this approval. The caller signs and sends it, not this tool."""
        if self.standard == "erc20":
            return self.token, abi.call_data("approve", self.spender, 0)
        if self.standard == "erc721-token":
            return self.token, abi.call_data("approve", ZERO, self.token_id or 0)
        if self.standard == "erc721-all":
            return self.token, abi.call_data("setApprovalForAll", self.spender, False)
        return abi.PERMIT2, abi.call_data("permit2Approve", self.token, self.spender, 0, 0)

    def to_dict(self) -> dict[str, Any]:
        to, data = self.revoke()
        return {
            "standard": self.standard,
            "token": self.token,
            "spender": self.spender,
            "label": self.label,
            "token_id": self.token_id,
            "amount": None if self.amount is None else str(self.amount),
            "live": self.live,
            "expiration": self.expiration,
            "granted_at": self.granted_at,
            "last_block": self.last_block,
            "last_tx": self.last_tx,
            "spender_is_contract": self.spender_is_contract,
            "state_known": self.state_known,
            "severity": self.severity,
            "findings": [f.__dict__ for f in self.findings],
            "revoke": {"to": to, "data": data},
        }


def fetch_logs(
    rpc: Rpc, flt: dict[str, Any], start: int, end: int, chunk: int, min_chunk: int = 64
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    lo = start
    size = chunk
    while lo <= end:
        hi = min(end, lo + size - 1)
        try:
            out += rpc.logs({**flt, "fromBlock": hex(lo), "toBlock": hex(hi)})
        except RpcError:
            if size <= min_chunk:
                raise
            size = max(min_chunk, size // 2)
            continue
        lo = hi + 1
    return out


def _order(log: dict[str, Any]) -> tuple[int, int]:
    return int(log["blockNumber"], 16), int(log.get("logIndex", "0x0"), 16)


def collect(logs: list[dict[str, Any]]) -> dict[tuple[str, str, str, int | None], Allowance]:
    """Latest approval event per key. Zero-address ERC-721 approvals clear the key."""
    latest: dict[tuple[str, str, str, int | None], Allowance] = {}
    for log in sorted(logs, key=_order):
        topics = log["topics"]
        t0, addr = topics[0].lower(), log["address"].lower()
        blk, tx = int(log["blockNumber"], 16), str(log.get("transactionHash", ""))
        if t0 == abi.TOPIC_APPROVAL and len(topics) == 3:
            spender = abi.topic_address(topics[2])
            a = Allowance("erc20", addr, spender, None, blk, tx, amount=abi.as_uint(abi.words(log["data"])[0]))
            latest[("erc20", addr, spender, None)] = a
        elif t0 == abi.TOPIC_APPROVAL and len(topics) == 4:
            spender, tid = abi.topic_address(topics[2]), int(topics[3], 16)
            for k in [k for k in latest if k[0] == "erc721-token" and k[1] == addr and k[3] == tid]:
                del latest[k]
            if spender != ZERO:
                latest[("erc721-token", addr, spender, tid)] = Allowance("erc721-token", addr, spender, tid, blk, tx)
        elif t0 == abi.TOPIC_APPROVAL_FOR_ALL:
            op = abi.topic_address(topics[2])
            on = abi.as_bool(abi.words(log["data"])[0])
            latest[("erc721-all", addr, op, None)] = Allowance("erc721-all", addr, op, None, blk, tx, live=on)
        elif t0 in (abi.TOPIC_PERMIT2_APPROVAL, abi.TOPIC_PERMIT2_PERMIT) and addr == abi.PERMIT2:
            token, spender = abi.topic_address(topics[2]), abi.topic_address(topics[3])
            w = abi.words(log["data"])
            a = Allowance("permit2", token, spender, None, blk, tx, amount=abi.as_uint(w[0]))
            a.expiration = abi.as_uint(w[1])
            latest[("permit2", token, spender, None)] = a
    return latest


def _current(rpc: Rpc, owner: str, a: Allowance, now: int) -> None:
    try:
        if a.standard == "erc20":
            a.amount = abi.as_uint(abi.words(rpc.eth_call(a.token, abi.call_data("allowance", owner, a.spender)))[0])
            a.live = a.amount > 0
        elif a.standard == "erc721-token":
            res = rpc.eth_call(a.token, abi.call_data("getApproved", a.token_id or 0))
            a.live = abi.as_address(abi.words(res)[0]) == a.spender
        elif a.standard == "erc721-all":
            res = rpc.eth_call(a.token, abi.call_data("isApprovedForAll", owner, a.spender))
            a.live = abi.as_bool(abi.words(res)[0])
        else:
            data = abi.SEL["permit2Allowance"] + "".join(abi.word_address(x) for x in (owner, a.token, a.spender))
            w = abi.words(rpc.eth_call(abi.PERMIT2, data))
            a.amount, a.expiration = abi.as_uint(w[0]), abi.as_uint(w[1])
            a.live = a.amount > 0 and a.expiration >= now
    except (RpcError, abi.AbiError, IndexError):
        # Non-standard token or a node hiccup: keep the event's view and say so.
        a.state_known = False
        a.live = a.live or bool(a.amount)


def scan(
    rpc: Rpc,
    owner: str,
    from_block: int = 0,
    to_block: int | None = None,
    lists: SpenderLists | None = None,
    now: int | None = None,
    stale_days: int = 180,
    chunk: int = 50_000,
    include_inactive: bool = False,
    tokens: list[str] | None = None,
) -> list[Allowance]:
    """``tokens`` limits the ERC-20/721 search to those contracts. Free public
    nodes usually refuse ``eth_getLogs`` without an address, so pass the tokens
    you care about there; with your own node, leave it empty to find everything."""
    owner = abi.norm(owner)
    lists = lists or SpenderLists()
    now = int(dt.datetime.now(dt.UTC).timestamp()) if now is None else now
    end = rpc.block_number() if to_block is None else to_block
    owner_topic = "0x" + abi.word_address(owner)
    base: dict[str, Any] = {"topics": [[abi.TOPIC_APPROVAL, abi.TOPIC_APPROVAL_FOR_ALL], owner_topic]}
    if tokens:
        base["address"] = [abi.norm(t) for t in tokens]
    logs = fetch_logs(rpc, base, from_block, end, chunk)
    logs += fetch_logs(
        rpc,
        {"address": abi.PERMIT2, "topics": [[abi.TOPIC_PERMIT2_APPROVAL, abi.TOPIC_PERMIT2_PERMIT], owner_topic]},
        from_block,
        end,
        chunk,
    )
    found = collect(logs)
    code_cache: dict[str, bool] = {}
    out: list[Allowance] = []
    for a in found.values():
        _current(rpc, owner, a, now)
        if not a.live and not include_inactive:
            continue
        a.label = lists.label(a.spender)
        if a.spender not in code_cache:
            try:
                code_cache[a.spender] = rpc.code(a.spender) not in ("0x", "", None)
            except RpcError:
                code_cache[a.spender] = True
        a.spender_is_contract = code_cache[a.spender]
        try:
            a.granted_at = rpc.block_time(a.last_block)
        except RpcError:
            a.granted_at = None
        a.findings = assess(a, lists, now, stale_days)
        out.append(a)
    out.sort(key=lambda x: (-["info", "low", "medium", "high"].index(x.severity), x.token, x.spender))
    return out


def assess(a: Allowance, lists: SpenderLists, now: int, stale_days: int) -> list[Finding]:
    f: list[Finding] = []
    if not a.live:
        return [Finding("AA-INACTIVE", "info", "no longer live")]
    if a.standard == "erc20" and a.spender == abi.PERMIT2:
        f.append(
            Finding("AA-PERMIT2-ROUTER", "info", "allowance to Permit2 itself; see the Permit2 rows for who can use it")
        )
    elif a.amount is not None and unlimited(a.amount, 160 if a.standard == "permit2" else 256):
        f.append(Finding("AA-UNLIMITED", "high", "unlimited allowance"))
    if a.standard == "erc721-all":
        f.append(Finding("AA-APPROVAL-FOR-ALL", "high", "operator may move every token in this collection"))
    if a.spender != abi.PERMIT2:
        f += spender_findings(a.spender, lists)
    if a.spender_is_contract is False:
        f.append(
            Finding(
                "AA-SPENDER-EOA",
                "high",
                "spender is a plain account, not a contract; legitimate apps rarely ask for that",
            )
        )
    if a.granted_at is not None and (now - a.granted_at) > stale_days * 86400:
        days = (now - a.granted_at) // 86400
        f.append(Finding("AA-STALE", "medium", f"granted {days} days ago and still live"))
    if a.standard == "permit2" and a.expiration is not None and a.expiration - now > 365 * 86400:
        f.append(Finding("AA-LONG-EXPIRY", "medium", "Permit2 allowance expires more than a year from now"))
    if not a.state_known:
        f.append(Finding("AA-STATE-UNKNOWN", "low", "current state could not be read; shown from the last event"))
    return f
