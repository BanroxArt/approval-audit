"""Findings and the spender lists they are checked against."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .abi import is_address

Severity = Literal["high", "medium", "low", "info"]
RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    message: str


def worst(findings: list[Finding] | tuple[Finding, ...]) -> Severity:
    best: Severity = "info"
    for f in findings:
        if RANK[f.severity] > RANK[best]:
            best = f.severity
    return best


@dataclass
class SpenderLists:
    """Your own allowlist of spenders you have reviewed, and a list of flagged ones.

    Nothing is bundled. A flagged list should come from a source you can cite
    (an OFAC SDN digital currency address, a published incident postmortem, your
    own investigations) and each entry keeps that source so a report can show it.
    """

    allow: dict[str, str] = field(default_factory=dict)
    flagged: dict[str, tuple[str, str]] = field(default_factory=dict)

    @property
    def has_allowlist(self) -> bool:
        return bool(self.allow)

    def label(self, addr: str) -> str:
        a = addr.lower()
        if a in self.allow:
            return self.allow[a]
        if a in self.flagged:
            return self.flagged[a][0]
        return ""


def _add(lists: SpenderLists, kind: str, addr: str, label: str, source: str) -> None:
    if not is_address(addr):
        raise ValueError(f"bad address in list: {addr!r}")
    if kind == "allow":
        lists.allow[addr.lower()] = label
    elif kind == "flagged":
        lists.flagged[addr.lower()] = (label, source)
    else:
        raise ValueError(f"list must be allow or flagged, not {kind!r}")


def load_lists(path: str | Path | None) -> SpenderLists:
    """JSON ``{"allow": [{address, label}], "flagged": [{address, label, source}]}``
    or CSV with columns ``list,address,label,source``."""
    lists = SpenderLists()
    if path is None:
        return lists
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                _add(lists, row["list"], row["address"], row.get("label", ""), row.get("source", ""))
        return lists
    doc = json.loads(p.read_text(encoding="utf-8"))
    for kind in ("allow", "flagged"):
        for e in doc.get(kind, []):
            _add(lists, kind, e["address"], e.get("label", ""), e.get("source", ""))
    return lists


def spender_findings(spender: str, lists: SpenderLists) -> list[Finding]:
    s = spender.lower()
    if s in lists.flagged:
        label, source = lists.flagged[s]
        return [Finding("AA-SPENDER-FLAGGED", "high", f"spender {spender} is flagged: {label} ({source})")]
    if lists.has_allowlist and s not in lists.allow:
        return [Finding("AA-SPENDER-UNKNOWN", "medium", f"spender {spender} is not on your allowlist")]
    return []
