"""Command line.

    approvalaudit scan 0xOWNER [--rpc URL | --fixture rec.json] [--from-block N] [--lists l.json]
    approvalaudit typed request.json [--chain 1] [--signer 0x..] [--lists l.json]
    approvalaudit call --to 0xTOKEN --data 0x095ea7b3...

Exit codes: 0 nothing above low, 2 medium, 3 high, 1 bad input or RPC failure.
Nothing here signs or sends. ``scan`` prints revoke calldata for you to send
from your own wallet if you choose to.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from . import abi
from .eip712 import TypedDataError
from .findings import RANK, load_lists
from .permits import Request, decode_call, decode_typed
from .rpc import DEFAULT_RPC, FixtureTransport, HttpTransport, RecordingTransport, Rpc, RpcError, Transport
from .scan import scan

# Ethereum mainnet USD stablecoins, checked with symbol() against a public node on 2026-11-16.
PRESETS = {
    "usd-mainnet": [
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
        "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
        "0x6c3ea9036406852006290770bedfcaba0e23a0e8",  # PYUSD
    ]
}

EXIT = {"info": 0, "low": 0, "medium": 2, "high": 3}


def _when(t: int | None) -> str:
    if t is None:
        return "-"
    return dt.datetime.fromtimestamp(min(t, 253402300799), dt.UTC).strftime("%Y-%m-%d")


def _amount(a: int | None) -> str:
    if a is None:
        return "-"
    if a >= 1 << 159:
        return "unlimited"
    return f"{a:,}"


def _tokens(spec: str | None) -> list[str] | None:
    if not spec:
        return None
    out: list[str] = []
    for part in spec.split(","):
        out += PRESETS.get(part.strip(), [part.strip()])
    return out


def _cmd_scan(a: argparse.Namespace) -> int:
    transport: Transport = FixtureTransport(a.fixture) if a.fixture else HttpTransport(a.rpc)
    rec = RecordingTransport(transport) if a.record else None
    rpc = Rpc(rec or transport)
    now = int(dt.datetime.fromisoformat(a.now).timestamp()) if a.now else None
    try:
        rows = scan(
            rpc,
            a.owner,
            a.from_block,
            a.to_block,
            load_lists(a.lists),
            now,
            a.stale_days,
            a.chunk,
            a.all,
            _tokens(a.tokens),
        )
    finally:
        if rec:
            rec.save(a.record)
    if a.json:
        print(json.dumps([r.to_dict() for r in rows], indent=2))
    else:
        if not rows:
            print("no live approvals found in the scanned range")
        for r in rows:
            who = f"{r.spender}" + (f" ({r.label})" if r.label else "")
            tid = f" #{r.token_id}" if r.token_id is not None else ""
            print(f"{r.severity.upper():6} {r.standard:12} token {r.token}{tid}")
            print(f"       spender {who}  amount {_amount(r.amount)}  granted {_when(r.granted_at)}")
            for f in r.findings:
                print(f"       {f.severity:6} {f.code}: {f.message}")
            to, data = r.revoke()
            print(f"       revoke: to {to} data {data}")
    worst = max((RANK[r.severity] for r in rows), default=0)
    return EXIT[["info", "low", "medium", "high"][worst]]


def _print_request(req: Request, as_json: bool) -> int:
    if as_json:
        print(json.dumps(req.to_dict(), indent=2))
    else:
        print(f"{req.severity.upper():6} {req.kind}")
        if req.chain_id is not None:
            print(f"       chain {req.chain_id}  contract {req.contract}")
        if req.owner:
            print(f"       owner {req.owner}")
        print(f"       spender {req.spender or '-'}")
        for g in req.grants:
            exp = "never" if g.expires is None else _when(g.expires)
            print(f"       token {g.token}  amount {_amount(g.amount)}  allowance expires {exp}")
        if req.deadline is not None or req.kind.startswith(("eip2612", "permit2", "dai")):
            print(f"       signature valid until {_when(req.deadline) if req.deadline else 'never'}")
        if req.witness is not None:
            print(f"       witness {json.dumps(req.witness)}")
        if req.digest:
            print(f"       EIP-712 digest {req.digest}")
        for f in req.findings:
            print(f"       {f.severity:6} {f.code}: {f.message}")
    return EXIT[req.severity]


def _cmd_typed(a: argparse.Namespace) -> int:
    raw = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
    doc: Any = json.loads(raw)
    if isinstance(doc, str):  # some wallets pass the typed data as a JSON string
        doc = json.loads(doc)
    now = int(dt.datetime.fromisoformat(a.now).timestamp()) if a.now else None
    req = decode_typed(doc, load_lists(a.lists), now, a.chain, a.signer, a.max_days)
    return _print_request(req, a.json)


def _cmd_call(a: argparse.Namespace) -> int:
    return _print_request(decode_call(a.to, a.data, load_lists(a.lists)), a.json)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="approvalaudit", description="Token approval and permit audit (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="list live approvals granted by an address")
    s.add_argument("owner")
    s.add_argument("--rpc", default=DEFAULT_RPC, help=f"JSON-RPC URL (default {DEFAULT_RPC})")
    s.add_argument("--fixture", help="replay a recorded RPC file instead of the network")
    s.add_argument("--record", help="save every RPC answer to this file for later replay")
    s.add_argument("--from-block", type=int, default=0)
    s.add_argument("--to-block", type=int)
    s.add_argument("--chunk", type=int, default=50_000, help="blocks per eth_getLogs call")
    s.add_argument("--lists", help="allow and flagged spender lists, JSON or CSV")
    s.add_argument("--tokens", help="comma-separated token addresses or the preset usd-mainnet")
    s.add_argument("--stale-days", type=int, default=180)
    s.add_argument("--now", help="evaluate as of this ISO 8601 time (with offset)")
    s.add_argument("--all", action="store_true", help="include approvals that are no longer live")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=_cmd_scan)
    t = sub.add_parser("typed", help="decode eth_signTypedData_v4 JSON before signing")
    t.add_argument("file", help="path, or - for stdin")
    t.add_argument("--chain", type=int, help="chain id you expect to be on")
    t.add_argument("--signer", help="address that would sign")
    t.add_argument("--lists")
    t.add_argument("--max-days", type=int, default=30)
    t.add_argument("--now")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=_cmd_typed)
    c = sub.add_parser("call", help="decode approval calldata before sending")
    c.add_argument("--to", required=True)
    c.add_argument("--data", required=True)
    c.add_argument("--lists")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=_cmd_call)
    a = ap.parse_args(argv)
    try:
        rc: int = a.fn(a)
    except (RpcError, OSError, ValueError, KeyError, TypedDataError, abi.AbiError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
