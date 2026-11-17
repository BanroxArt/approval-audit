from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from chain import OWNER
from make_fixture import NOW

from approvalaudit import abi
from approvalaudit.__main__ import main

HERE = Path(__file__).parent
EX = HERE.parents[0] / "examples"
AT = dt.datetime.fromtimestamp(NOW, dt.UTC).isoformat()


def test_scan_from_fixture(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "scan",
            OWNER,
            "--fixture",
            str(HERE / "fixtures" / "scan.json"),
            "--now",
            AT,
            "--lists",
            str(EX / "lists.json"),
            "--stale-days",
            "90",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 3
    assert "AA-SPENDER-FLAGGED" in out and "AA-APPROVAL-FOR-ALL" in out and "AA-STALE" in out
    assert "revoke: to" in out
    assert main(["scan", OWNER, "--fixture", str(HERE / "fixtures" / "scan.json"), "--now", AT, "--json"]) == 3
    rows = json.loads(capsys.readouterr().out)
    assert {r["standard"] for r in rows} == {"erc20", "permit2", "erc721-all"}


def test_typed_and_call(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            [
                "typed",
                str(EX / "permit2-batch.json"),
                "--lists",
                str(EX / "lists.json"),
                "--now",
                "2026-11-16T00:00:00+00:00",
            ]
        )
        == 2
    )
    out = capsys.readouterr().out
    assert "EIP-712 digest 0x" in out and "AA-MULTI-TOKEN" in out
    assert (
        main(["typed", str(EX / "permit2-single-unlimited.json"), "--json", "--now", "2026-11-16T00:00:00+00:00"]) == 3
    )
    assert json.loads(capsys.readouterr().out)["severity"] == "high"
    data = abi.call_data("setApprovalForAll", "0x" + "e1" * 20, True)
    assert main(["call", "--to", "0x" + "c2" * 20, "--data", data]) == 3


def test_bad_input_exit_1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["scan", "0x1234", "--fixture", str(HERE / "fixtures" / "scan.json")]) == 1
    assert main(["call", "--to", "0x" + "c2" * 20, "--data", "0x095ea7b3" + "00" * 63]) == 1
    missing = tmp_path / "empty.json"
    missing.write_text("{}")
    assert main(["scan", OWNER, "--fixture", str(missing)]) == 1
    assert "error:" in capsys.readouterr().err
