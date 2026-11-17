"""The small slice of the Solidity ABI this package needs.

Static types only, plus the selectors and event topics for the approval
functions. Selectors and topics are computed from their signatures at import
time and pinned by tests, so a typo in a signature fails loudly.
"""

from __future__ import annotations

import re

from .keccak import keccak256

UINT256_MAX = (1 << 256) - 1
UINT160_MAX = (1 << 160) - 1
UINT48_MAX = (1 << 48) - 1

# Uniswap's Permit2 is deployed at the same address on every chain it supports.
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()[:8]


def topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode()).hex()


SIG = {
    "approve": "approve(address,uint256)",
    "increaseAllowance": "increaseAllowance(address,uint256)",
    "increaseApproval": "increaseApproval(address,uint256)",
    "setApprovalForAll": "setApprovalForAll(address,bool)",
    "permit": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "daiPermit": "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
    "permit2Approve": "approve(address,address,uint160,uint48)",
    "allowance": "allowance(address,address)",
    "getApproved": "getApproved(uint256)",
    "isApprovedForAll": "isApprovedForAll(address,address)",
    "permit2Allowance": "allowance(address,address,address)",
}
SEL = {k: selector(v) for k, v in SIG.items()}

TOPIC_APPROVAL = topic("Approval(address,address,uint256)")
TOPIC_APPROVAL_FOR_ALL = topic("ApprovalForAll(address,address,bool)")
TOPIC_PERMIT2_APPROVAL = topic("Approval(address,address,address,uint160,uint48)")
TOPIC_PERMIT2_PERMIT = topic("Permit(address,address,address,uint160,uint48,uint48)")


class AbiError(ValueError):
    """Data does not decode as the expected ABI shape."""


def is_address(v: str) -> bool:
    return bool(_ADDR.match(v))


def norm(addr: str) -> str:
    if not is_address(addr):
        raise AbiError(f"not an address: {addr!r}")
    return addr.lower()


def word_address(addr: str) -> str:
    return norm(addr)[2:].rjust(64, "0")


def word_uint(v: int) -> str:
    if not 0 <= v <= UINT256_MAX:
        raise AbiError("uint out of range")
    return f"{v:064x}"


def words(data: str) -> list[str]:
    body = data[2:] if data.startswith("0x") else data
    if len(body) % 64:
        raise AbiError("data is not a whole number of 32-byte words")
    return [body[i : i + 64] for i in range(0, len(body), 64)]


def as_address(word: str) -> str:
    if int(word[:24] or "0", 16):
        raise AbiError("address word has nonzero high bytes")
    return "0x" + word[24:]


def as_uint(word: str) -> int:
    return int(word, 16)


def as_bool(word: str) -> bool:
    v = int(word, 16)
    if v > 1:
        raise AbiError("bool word is not 0 or 1")
    return v == 1


def topic_address(t: str) -> str:
    return as_address(t[2:] if t.startswith("0x") else t)


def call_data(name: str, *args: str | int | bool) -> str:
    out = SEL[name]
    for a in args:
        if isinstance(a, bool):
            out += word_uint(int(a))
        elif isinstance(a, int):
            out += word_uint(a)
        else:
            out += word_address(a)
    return out
