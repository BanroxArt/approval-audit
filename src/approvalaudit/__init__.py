"""approval-audit: find risky token approvals and read permit requests before signing."""

from .eip712 import TypedDataError, digest
from .findings import Finding, SpenderLists, load_lists
from .permits import Request, decode_call, decode_typed
from .rpc import FixtureTransport, HttpTransport, RecordingTransport, Rpc, RpcError
from .scan import Allowance, scan

__all__ = [
    "Allowance",
    "Finding",
    "FixtureTransport",
    "HttpTransport",
    "RecordingTransport",
    "Request",
    "Rpc",
    "RpcError",
    "SpenderLists",
    "TypedDataError",
    "decode_call",
    "decode_typed",
    "digest",
    "load_lists",
    "scan",
]
__version__ = "0.1.0"
