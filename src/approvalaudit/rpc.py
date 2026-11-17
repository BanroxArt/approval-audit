"""Read-only Ethereum JSON-RPC.

The client refuses every method that is not on a short read list, so nothing
built on it can send a transaction or ask a node to sign, whatever URL it is
pointed at. Transports are plain callables: one over HTTP, one that replays a
recorded JSON file (tests and reproducible evidence), and one that records.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

READ_ONLY = frozenset(
    {
        "eth_blockNumber",
        "eth_call",
        "eth_chainId",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getLogs",
    }
)
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"

Transport = Callable[[str, list[Any]], Any]


class RpcError(RuntimeError):
    """The node returned an error, or a fixture has no answer for a call."""


def _key(method: str, params: list[Any]) -> str:
    return json.dumps([method, params], sort_keys=True, separators=(",", ":"))


class HttpTransport:
    def __init__(self, url: str = DEFAULT_RPC, timeout: float = 30.0) -> None:
        if not url.startswith(("https://", "http://")):
            raise ValueError("RPC URL must be http(s)")
        self.url = url
        self.timeout = timeout
        self._id = 0

    def __call__(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "approval-audit/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                doc = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # Public nodes answer an oversized eth_getLogs with 4xx or 5xx; the
            # scanner treats that like any other refusal and splits the range.
            raise RpcError(f"HTTP {e.code} from node") from None
        if "error" in doc:
            raise RpcError(str(doc["error"].get("message", doc["error"])))
        return doc.get("result")


class FixtureTransport:
    """Replays answers recorded by :class:`RecordingTransport`."""

    def __init__(self, path: str | Path) -> None:
        self.answers: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

    def __call__(self, method: str, params: list[Any]) -> Any:
        k = _key(method, params)
        if k not in self.answers:
            raise RpcError(f"fixture has no answer for {method}")
        ans = self.answers[k]
        if isinstance(ans, dict) and "__error__" in ans:
            raise RpcError(str(ans["__error__"]))
        return ans


class RecordingTransport:
    def __init__(self, inner: Transport) -> None:
        self.inner = inner
        self.answers: dict[str, Any] = {}

    def __call__(self, method: str, params: list[Any]) -> Any:
        try:
            ans = self.inner(method, params)
        except RpcError as e:
            self.answers[_key(method, params)] = {"__error__": str(e)}
            raise
        self.answers[_key(method, params)] = ans
        return ans

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.answers, indent=1, sort_keys=True), encoding="utf-8")


class Rpc:
    def __init__(self, transport: Transport) -> None:
        self.t = transport

    def call(self, method: str, params: list[Any]) -> Any:
        if method not in READ_ONLY:
            raise PermissionError(f"{method} is not a read-only method; refusing")
        return self.t(method, params)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def eth_call(self, to: str, data: str) -> str:
        return str(self.call("eth_call", [{"to": to, "data": data}, "latest"]))

    def code(self, addr: str) -> str:
        return str(self.call("eth_getCode", [addr, "latest"]))

    def block_time(self, number: int) -> int:
        blk = self.call("eth_getBlockByNumber", [hex(number), False])
        if not blk:
            raise RpcError(f"block {number} not found")
        return int(blk["timestamp"], 16)

    def logs(self, flt: dict[str, Any]) -> list[dict[str, Any]]:
        out = self.call("eth_getLogs", [flt])
        return list(out or [])
