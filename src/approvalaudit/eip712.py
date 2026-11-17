"""EIP-712 typed structured data: type encoding, struct hashing, signing digest.

This is what a wallet shows (or fails to show) when a site asks for
``eth_signTypedData_v4``. Computing the digest here lets a person confirm that
the message they are reading is the one their wallet will sign: same domain,
same fields, same hash.

Supports atomic types (address, bool, uintN, intN, bytesN, bytes, string),
nested structs and dynamic or fixed arrays of either, per the EIP.
"""

from __future__ import annotations

import re
from typing import Any

from .keccak import keccak256

Types = dict[str, list[dict[str, str]]]

_ARRAY = re.compile(r"^(.*)\[(\d*)\]$")
_INT = re.compile(r"^(u?)int(\d*)$")
_BYTES_N = re.compile(r"^bytes(\d+)$")


class TypedDataError(ValueError):
    """The typed data is malformed or a value does not fit its declared type."""


def _base(t: str) -> str:
    m = _ARRAY.match(t)
    return _base(m.group(1)) if m else t


def _deps(primary: str, types: Types, found: set[str]) -> None:
    if primary in found or primary not in types:
        return
    found.add(primary)
    for f in types[primary]:
        _deps(_base(f["type"]), types, found)


def encode_type(primary: str, types: Types) -> str:
    """``Mail(Person from,Person to,string contents)Person(string name,address wallet)``."""
    if primary not in types:
        raise TypedDataError(f"unknown type {primary!r}")
    found: set[str] = set()
    _deps(primary, types, found)
    found.discard(primary)
    out = ""
    for name in [primary, *sorted(found)]:
        out += name + "(" + ",".join(f"{f['type']} {f['name']}" for f in types[name]) + ")"
    return out


def type_hash(primary: str, types: Types) -> bytes:
    return keccak256(encode_type(primary, types).encode())


def _to_int(v: Any) -> int:
    if isinstance(v, bool):
        raise TypedDataError("bool where an integer was expected")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            raise TypedDataError(f"not an integer: {v!r}") from None
    raise TypedDataError(f"not an integer: {v!r}")


def _hexbytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str) and v.startswith("0x"):
        try:
            return bytes.fromhex(v[2:])
        except ValueError:
            raise TypedDataError(f"bad hex: {v!r}") from None
    raise TypedDataError(f"expected 0x-prefixed hex, got {v!r}")


def encode_value(t: str, v: Any, types: Types) -> bytes:
    m = _ARRAY.match(t)
    if m:
        if not isinstance(v, list):
            raise TypedDataError(f"{t} needs a list")
        if m.group(2) and len(v) != int(m.group(2)):
            raise TypedDataError(f"{t} needs exactly {m.group(2)} items")
        return keccak256(b"".join(encode_value(m.group(1), x, types) for x in v))
    if t in types:
        if not isinstance(v, dict):
            raise TypedDataError(f"{t} needs an object")
        return hash_struct(t, v, types)
    if t == "address":
        if not isinstance(v, str) or not re.match(r"^0x[0-9a-fA-F]{40}$", v):
            raise TypedDataError(f"bad address {v!r}")
        return bytes(12) + bytes.fromhex(v[2:])
    if t == "bool":
        if not isinstance(v, bool):
            raise TypedDataError(f"bool needs true or false, got {v!r}")
        return int(v).to_bytes(32, "big")
    if t == "string":
        if not isinstance(v, str):
            raise TypedDataError("string needs a string")
        return keccak256(v.encode("utf-8"))
    if t == "bytes":
        return keccak256(_hexbytes(v))
    mb = _BYTES_N.match(t)
    if mb:
        n = int(mb.group(1))
        b = _hexbytes(v)
        if not 1 <= n <= 32 or len(b) != n:
            raise TypedDataError(f"{t} needs exactly {n} bytes")
        return b.ljust(32, b"\0")
    mi = _INT.match(t)
    if mi:
        bits = int(mi.group(2) or 256)
        x = _to_int(v)
        if mi.group(1) == "u":
            if not 0 <= x < (1 << bits):
                raise TypedDataError(f"{x} does not fit {t}")
            return x.to_bytes(32, "big")
        if not -(1 << (bits - 1)) <= x < (1 << (bits - 1)):
            raise TypedDataError(f"{x} does not fit {t}")
        return (x % (1 << 256)).to_bytes(32, "big")
    raise TypedDataError(f"unsupported type {t!r}")


def hash_struct(primary: str, data: dict[str, Any], types: Types) -> bytes:
    enc = type_hash(primary, types)
    for f in types[primary]:
        if f["name"] not in data:
            raise TypedDataError(f"{primary}.{f['name']} is missing")
        enc += encode_value(f["type"], data[f["name"]], types)
    return keccak256(enc)


def domain_separator(doc: dict[str, Any]) -> bytes:
    return hash_struct("EIP712Domain", doc.get("domain", {}), doc["types"])


def digest(doc: dict[str, Any]) -> bytes:
    """The 32 bytes a wallet signs for ``eth_signTypedData_v4``."""
    types: Types = doc.get("types", {})
    if "EIP712Domain" not in types:
        raise TypedDataError("types.EIP712Domain is missing")
    primary = doc.get("primaryType")
    if not isinstance(primary, str):
        raise TypedDataError("primaryType is missing")
    msg = doc.get("message")
    if not isinstance(msg, dict):
        raise TypedDataError("message is missing")
    return keccak256(b"\x19\x01" + domain_separator(doc) + hash_struct(primary, msg, types))
