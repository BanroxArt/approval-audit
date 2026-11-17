"""An in-memory chain that answers the read-only RPC calls the scanner makes.

Addresses are made up (repeated hex bytes). Only Permit2's address is real,
because the scanner and the decoder check for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from approvalaudit import abi
from approvalaudit.rpc import RpcError

OWNER = "0x" + "0a" * 20
DAY = 86_400
T0 = 1_700_000_000  # block 0 time; 12 seconds per block


def addr(b: str) -> str:
    return "0x" + b * 20


def _t(a: str) -> str:
    return "0x" + abi.word_address(a)


@dataclass
class FakeChain:
    head: int = 2_000_000
    max_range: int | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)
    erc20: dict[tuple[str, str, str], int] = field(default_factory=dict)
    nft: dict[tuple[str, int], str] = field(default_factory=dict)
    ops: dict[tuple[str, str, str], bool] = field(default_factory=dict)
    p2: dict[tuple[str, str, str], tuple[int, int, int]] = field(default_factory=dict)
    contracts: set[str] = field(default_factory=set)
    broken: set[str] = field(default_factory=set)
    calls: list[str] = field(default_factory=list)

    def _log(self, address: str, topics: list[str], data: str, block: int) -> None:
        self.logs.append(
            {
                "address": address,
                "topics": topics,
                "data": data,
                "blockNumber": hex(block),
                "logIndex": hex(len(self.logs)),
                "transactionHash": "0x" + f"{len(self.logs):064x}",
            }
        )

    def approve20(self, token: str, spender: str, amount: int, block: int, current: int | None = None) -> None:
        self._log(token, [abi.TOPIC_APPROVAL, _t(OWNER), _t(spender)], "0x" + abi.word_uint(amount), block)
        self.erc20[(token, OWNER, spender)] = amount if current is None else current

    def approve721(self, token: str, spender: str, tid: int, block: int) -> None:
        self._log(token, [abi.TOPIC_APPROVAL, _t(OWNER), _t(spender), "0x" + abi.word_uint(tid)], "0x", block)
        self.nft[(token, tid)] = spender

    def for_all(self, token: str, op: str, on: bool, block: int) -> None:
        self._log(token, [abi.TOPIC_APPROVAL_FOR_ALL, _t(OWNER), _t(op)], "0x" + abi.word_uint(int(on)), block)
        self.ops[(token, OWNER, op)] = on

    def permit2(self, token: str, spender: str, amount: int, expiration: int, block: int) -> None:
        data = "0x" + abi.word_uint(amount) + abi.word_uint(expiration)
        self._log(abi.PERMIT2, [abi.TOPIC_PERMIT2_APPROVAL, _t(OWNER), _t(token), _t(spender)], data, block)
        self.p2[(OWNER, token, spender)] = (amount, expiration, 0)

    def __call__(self, method: str, params: list[Any]) -> Any:
        self.calls.append(method)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getBlockByNumber":
            n = int(params[0], 16)
            return {"number": params[0], "timestamp": hex(T0 + 12 * n)}
        if method == "eth_getCode":
            return "0x6080" if params[0].lower() in self.contracts else "0x"
        if method == "eth_getLogs":
            return self._get_logs(params[0])
        if method == "eth_call":
            return self._call(params[0]["to"].lower(), params[0]["data"])
        raise RpcError(f"method {method} not supported by FakeChain")

    def _get_logs(self, f: dict[str, Any]) -> list[dict[str, Any]]:
        lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
        if self.max_range is not None and hi - lo + 1 > self.max_range:
            raise RpcError("query returned more than 10000 results; narrow the block range")
        out = []
        for log in self.logs:
            b = int(log["blockNumber"], 16)
            if not lo <= b <= hi:
                continue
            if "address" in f:
                want = f["address"] if isinstance(f["address"], list) else [f["address"]]
                if log["address"].lower() not in [w.lower() for w in want]:
                    continue
            ok = True
            for i, want in enumerate(f.get("topics", [])):
                if want is None:
                    continue
                opts = want if isinstance(want, list) else [want]
                if i >= len(log["topics"]) or log["topics"][i].lower() not in [o.lower() for o in opts]:
                    ok = False
            if ok:
                out.append(log)
        return out

    def _call(self, to: str, data: str) -> str:
        if to in self.broken:
            raise RpcError("execution reverted")
        sel, w = data[:10], abi.words(data[10:])
        if sel == abi.SEL["allowance"]:
            return "0x" + abi.word_uint(self.erc20.get((to, abi.as_address(w[0]), abi.as_address(w[1])), 0))
        if sel == abi.SEL["getApproved"]:
            return "0x" + abi.word_address(self.nft.get((to, abi.as_uint(w[0])), "0x" + "0" * 40))
        if sel == abi.SEL["isApprovedForAll"]:
            return "0x" + abi.word_uint(int(self.ops.get((to, abi.as_address(w[0]), abi.as_address(w[1])), False)))
        if sel == abi.SEL["permit2Allowance"] and to == abi.PERMIT2:
            amt, exp, nonce = self.p2.get((abi.as_address(w[0]), abi.as_address(w[1]), abi.as_address(w[2])), (0, 0, 0))
            return "0x" + abi.word_uint(amt) + abi.word_uint(exp) + abi.word_uint(nonce)
        raise RpcError("execution reverted")


def block_time(block: int) -> int:
    return T0 + 12 * block
