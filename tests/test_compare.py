"""Comparing two scans: reading exports back, and matching findings up."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from preflight.core.compare import CompareError, Snapshot, load
from preflight.core.report import SCHEMA_VERSION

ACCOUNT_ID = "123456789012"
EARLIER = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
LATER = EARLIER + timedelta(days=14)


def item(
    check: str = "unattached-ebs-volumes",
    resource: str = "vol-0a1b2c3d4e5f60001",
    *,
    module: str = "cost",
    region: str = "us-east-1",
    monthly: float | None = 40.0,
    severity: str = "medium",
) -> dict:
    return {
        "id": f"{module}/{check}/{region}/{resource}",
        "check": check,
        "module": module,
        "title": f"{check} on {resource}",
        "severity": severity,
        "confidence": "high",
        "resource": {"id": resource, "kind": "ec2:volume", "region": region},
        "evidence": [],
        "recommendation": "Delete it.",
        "estimated_monthly_savings_usd": monthly,
        "estimated_annual_savings_usd": monthly * 12 if monthly is not None else None,
        "estimate_basis": "500 GB x $0.08/GB-month" if monthly is not None else None,
    }


def export(
    findings: list[dict] | None = None,
    *,
    when: datetime = EARLIER,
    account: str = ACCOUNT_ID,
    regions: tuple[str, ...] = ("us-east-1", "eu-west-1"),
    modules: tuple[str, ...] = ("cost", "observability", "security"),
    checks: dict[str, str] | None = None,
    redacted: bool = False,
) -> dict:
    findings = findings or []
    statuses = checks or {f["check"]: "ran" for f in findings} or {"unattached-ebs-volumes": "ran"}
    return {
        "schema_version": SCHEMA_VERSION,
        "preflight": {"version": "0.3.0", "command": "preflight scan"},
        "scan": {
            "started_at": when.isoformat(),
            "finished_at": when.isoformat(),
            "regions": list(regions),
            "redacted": redacted,
            "demo": False,
        },
        "account": {"id": account},
        "modules": [{"key": key, "name": key} for key in modules],
        "checks": [{"key": key, "status": status} for key, status in statuses.items()],
        "findings": copy.deepcopy(findings),
    }


# --- reading an export back -------------------------------------------------


def test_reads_what_a_scan_writes(tmp_path):
    from preflight import demo

    path = tmp_path / "scan.json"
    path.write_text(demo.build().to_json(), encoding="utf-8")
    snapshot = load(path)
    assert snapshot.account_id == demo.ACCOUNT_ID
    assert snapshot.demo
    assert snapshot.modules == ("cost", "observability", "security")
    assert snapshot.checks["unattached-ebs-volumes"] == "ran"
    assert all(key.count("/") >= 3 for key in snapshot.findings)


def test_a_file_that_isnt_json_says_so(tmp_path):
    path = tmp_path / "report.pdf"
    path.write_text("%PDF-1.7", encoding="utf-8")
    with pytest.raises(CompareError, match="isn't valid JSON"):
        load(path)


def test_a_missing_file_says_so(tmp_path):
    with pytest.raises(CompareError, match="Couldn't read"):
        load(tmp_path / "nope.json")


def test_json_that_isnt_an_export_says_so():
    with pytest.raises(CompareError, match="isn't a Preflight export"):
        Snapshot.from_dict({"hello": "world"})


def test_a_newer_schema_is_refused_rather_than_misread():
    data = export()
    data["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(CompareError, match="newer Preflight") as raised:
        Snapshot.from_dict(data)
    assert "Upgrade" in (raised.value.hint or "")


def test_a_truncated_export_names_what_is_missing():
    data = export()
    del data["scan"]
    with pytest.raises(CompareError, match="missing part"):
        Snapshot.from_dict(json.loads(json.dumps(data)))
