"""Read a signature request or an approval transaction before it is signed.

``decode_typed`` takes the JSON a site passes to ``eth_signTypedData_v4`` and
says, in plain terms, who could move which tokens, how much, and until when.
``decode_call`` does the same for raw calldata of an ``approve``,
``increaseAllowance``, ``setApprovalForAll``, EIP-2612 ``permit``, DAI
``permit`` or Permit2 ``approve`` transaction.

An off-chain permit signature costs the signer no gas and shows up nowhere on
chain until the spender uses it, which is why drainers prefer it. Reading the
fields before signing is the only control the signer has.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from . import abi
from .eip712 import TypedDataError, digest
from .findings import Finding, SpenderLists, spender_findings, worst

PERMIT2_TYPES = {
    "PermitSingle",
    "PermitBatch",
    "PermitTransferFrom",
    "PermitBatchTransferFrom",
    "PermitWitnessTransferFrom",
    "PermitBatchWitnessTransferFrom",
}


@dataclass(frozen=True)
class Grant:
    token: str
    amount: int | None
    unlimited: bool
    expires: int | None  # unix seconds; None means never


@dataclass
class Request:
    kind: str
    chain_id: int | None
    contract: str
    owner: str
    spender: str
    grants: list[Grant]
    deadline: int | None
    nonce: int | None
    digest: str = ""
    witness: dict[str, Any] | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return worst(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "chain_id": self.chain_id,
            "contract": self.contract,
            "owner": self.owner,
            "spender": self.spender,
            "grants": [g.__dict__ | {"amount": str(g.amount) if g.amount is not None else None} for g in self.grants],
            "deadline": self.deadline,
            "nonce": self.nonce,
            "digest": self.digest,
            "witness": self.witness,
            "severity": self.severity,
            "findings": [f.__dict__ for f in self.findings],
        }


def _int(v: Any) -> int:
    if isinstance(v, bool):
        raise TypedDataError("bool where a number was expected")
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def unlimited(amount: int, bits: int = 256) -> bool:
    """Max value, or so large it is unlimited in practice (top bit set)."""
    return amount >= 1 << (bits - 1)


def _when(t: int | None) -> str:
    if t is None:
        return "never"
    return dt.datetime.fromtimestamp(min(t, 253402300799), dt.UTC).strftime("%Y-%m-%d %H:%M UTC")


def _expiry_findings(label: str, t: int | None, now: int, max_days: int) -> list[Finding]:
    if t is None:
        return [Finding("AA-NO-EXPIRY", "high", f"{label} never expires")]
    if t < now:
        return [Finding("AA-EXPIRED", "info", f"{label} already passed ({_when(t)}); a spender cannot use it")]
    days = (t - now) / 86400
    if days > max_days:
        return [Finding("AA-LONG-EXPIRY", "medium", f"{label} is {days:,.0f} days away ({_when(t)})")]
    return []


def decode_typed(
    doc: dict[str, Any],
    lists: SpenderLists | None = None,
    now: int | None = None,
    expected_chain: int | None = None,
    signer: str | None = None,
    max_days: int = 30,
) -> Request:
    lists = lists or SpenderLists()
    now = int(dt.datetime.now(dt.UTC).timestamp()) if now is None else now
    dom = doc.get("domain", {})
    msg = doc.get("message", {})
    primary = str(doc.get("primaryType", ""))
    chain = _int(dom["chainId"]) if "chainId" in dom else None
    contract = str(dom.get("verifyingContract", "")).lower()
    try:
        dig = "0x" + digest(doc).hex()
    except (TypedDataError, KeyError) as e:
        dig = ""
        bad = [Finding("AA-MALFORMED", "high", f"typed data does not hash: {e}")]
    else:
        bad = []

    fields = {f["name"] for f in doc.get("types", {}).get(primary, [])}
    f: list[Finding] = list(bad)
    grants: list[Grant] = []
    owner = spender = ""
    deadline: int | None = None
    nonce: int | None = None
    witness: dict[str, Any] | None = None

    if primary == "Permit" and {"owner", "spender", "value", "deadline"} <= fields:
        kind = "eip2612"
        owner, spender = str(msg["owner"]), str(msg["spender"])
        value, deadline, nonce = _int(msg["value"]), _int(msg["deadline"]), _int(msg.get("nonce", 0))
        if deadline == abi.UINT256_MAX:
            deadline = None
        grants.append(Grant(contract, value, unlimited(value), None))
        f += _expiry_findings("signature deadline", deadline, now, max_days)
        f.append(
            Finding(
                "AA-ALLOWANCE-PERSISTS",
                "info",
                "once used, the allowance stays on the token with no expiry until revoked",
            )
        )
    elif primary == "Permit" and {"holder", "spender", "allowed", "expiry"} <= fields:
        kind = "dai-permit"
        owner, spender = str(msg["holder"]), str(msg["spender"])
        allowed = bool(msg["allowed"])
        expiry = _int(msg["expiry"])
        deadline = None if expiry == 0 else expiry
        nonce = _int(msg.get("nonce", 0))
        grants.append(Grant(contract, abi.UINT256_MAX if allowed else 0, allowed, None))
        f += _expiry_findings("signature expiry", deadline, now, max_days)
    elif primary in PERMIT2_TYPES:
        kind = "permit2-" + primary[0].lower() + primary[1:]
        spender = str(msg.get("spender", ""))
        if contract != abi.PERMIT2 or dom.get("name") != "Permit2":
            f.append(
                Finding(
                    "AA-PERMIT2-IMPOSTOR",
                    "high",
                    f"{primary} message but the domain is {dom.get('name')!r} at {contract or 'no address'}, "
                    f"not Permit2 at {abi.PERMIT2}",
                )
            )
        if primary in ("PermitSingle", "PermitBatch"):
            details = msg["details"] if primary == "PermitBatch" else [msg["details"]]
            for d in details:
                amt, exp = _int(d["amount"]), _int(d["expiration"])
                expires = None if exp == abi.UINT48_MAX else exp
                grants.append(Grant(str(d["token"]).lower(), amt, unlimited(amt, 160), expires))
                f += _expiry_findings(f"allowance on {d['token']}", expires, now, max_days)
                if exp == 0:
                    f.append(
                        Finding("AA-EXPIRATION-ZERO", "info", "expiration 0 means the allowance ends in the same block")
                    )
            sd = _int(msg["sigDeadline"])
            deadline = None if sd == abi.UINT256_MAX else sd
            nonce = _int(details[0]["nonce"]) if details else None
        else:
            permitted = msg["permitted"] if isinstance(msg["permitted"], list) else [msg["permitted"]]
            dl = _int(msg["deadline"])
            deadline = None if dl == abi.UINT256_MAX else dl
            nonce = _int(msg["nonce"])
            for p in permitted:
                amt = _int(p["amount"])
                grants.append(Grant(str(p["token"]).lower(), amt, unlimited(amt), deadline))
            f += _expiry_findings("signature deadline", deadline, now, max_days)
            if "witness" in msg:
                witness = msg["witness"]
                f.append(
                    Finding(
                        "AA-WITNESS",
                        "info",
                        "the signature also commits to extra data (witness); read it, it is part of the deal",
                    )
                )
        if len(grants) > 1:
            f.append(Finding("AA-MULTI-TOKEN", "medium", f"one signature covers {len(grants)} tokens"))
    else:
        kind = "unrecognized"
        f.append(
            Finding(
                "AA-UNRECOGNIZED",
                "medium",
                f"primaryType {primary!r} is not a permit this tool knows; read every field before signing",
            )
        )

    for g in grants:
        if g.unlimited:
            f.append(Finding("AA-UNLIMITED", "high", f"unlimited amount of token {g.token}"))
    if spender:
        f += spender_findings(spender, lists)
    if expected_chain is not None and chain != expected_chain:
        f.append(Finding("AA-CHAIN-MISMATCH", "high", f"domain chainId is {chain}, expected {expected_chain}"))
    if signer and owner and owner.lower() != signer.lower():
        f.append(Finding("AA-OWNER-MISMATCH", "medium", f"message owner {owner} is not the signer {signer}"))
    return Request(kind, chain, contract, owner.lower(), spender.lower(), grants, deadline, nonce, dig, witness, f)


def decode_call(to: str, data: str, lists: SpenderLists | None = None) -> Request:
    """Decode approval calldata sent to ``to``. Unknown selectors are reported, not guessed."""
    lists = lists or SpenderLists()
    to = abi.norm(to)
    sel = data[:10].lower()
    w = abi.words(data[10:])
    f: list[Finding] = []
    names = {v: k for k, v in abi.SEL.items()}
    name = names.get(sel, "")
    grants: list[Grant] = []
    owner = spender = ""
    deadline: int | None = None
    if name in ("approve", "increaseAllowance", "increaseApproval"):
        spender, amt = abi.as_address(w[0]), abi.as_uint(w[1])
        grants.append(Grant(to, amt, unlimited(amt), None))
        if name == "approve" and amt < 1 << 64:
            f.append(
                Finding(
                    "AA-AMBIGUOUS-721",
                    "info",
                    "approve(address,uint256) is also ERC-721's per-token approve; on an NFT contract the "
                    "second argument is a token id",
                )
            )
    elif name == "setApprovalForAll":
        spender, on = abi.as_address(w[0]), abi.as_bool(w[1])
        grants.append(Grant(to, None, on, None))
        if on:
            f.append(
                Finding(
                    "AA-APPROVAL-FOR-ALL",
                    "high",
                    "operator may move every token you hold in this collection, now and later",
                )
            )
    elif name == "permit":
        owner, spender, amt, dl = abi.as_address(w[0]), abi.as_address(w[1]), abi.as_uint(w[2]), abi.as_uint(w[3])
        deadline = None if dl == abi.UINT256_MAX else dl
        grants.append(Grant(to, amt, unlimited(amt), None))
    elif name == "daiPermit":
        owner, spender, allowed = abi.as_address(w[0]), abi.as_address(w[1]), abi.as_bool(w[4])
        grants.append(Grant(to, abi.UINT256_MAX if allowed else 0, allowed, None))
    elif name == "permit2Approve":
        if to != abi.PERMIT2:
            f.append(Finding("AA-PERMIT2-IMPOSTOR", "high", f"Permit2 approve() sent to {to}, not {abi.PERMIT2}"))
        token, spender, amt, exp = abi.as_address(w[0]), abi.as_address(w[1]), abi.as_uint(w[2]), abi.as_uint(w[3])
        grants.append(Grant(token, amt, unlimited(amt, 160), None if exp == abi.UINT48_MAX else exp))
    else:
        f.append(Finding("AA-UNRECOGNIZED", "medium", f"selector {sel} is not an approval this tool decodes"))
        return Request("unrecognized", None, to, "", "", [], None, None, findings=f)
    for g in grants:
        if g.unlimited and g.amount is not None and spender != abi.PERMIT2:
            f.append(Finding("AA-UNLIMITED", "high", f"unlimited amount of token {g.token}"))
    if spender == abi.PERMIT2 and name in ("approve", "increaseAllowance"):
        f.append(
            Finding(
                "AA-PERMIT2-ROUTER",
                "info",
                "allowance to Permit2 itself is normal; what Permit2 may pass on is set by later Permit2 signatures",
            )
        )
    elif spender:
        f += spender_findings(spender, lists)
    return Request(name, None, to, owner.lower(), spender.lower(), grants, deadline, None, findings=f)
