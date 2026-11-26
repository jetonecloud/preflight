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
    assert snapshot.modules == (
        "cost",
        "observability",
        "security",
        "reliability",
        "delivery",
    )
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


# --- matching findings up ----------------------------------------------------


def snap(findings: list[dict] | None = None, **kwargs) -> Snapshot:
    return Snapshot.from_dict(export(findings, **kwargs))


def test_gone_is_fixed_and_arrived_is_new():
    from preflight.core.compare import compare

    kept, gone, arrived = item(resource="vol-1"), item(resource="vol-2"), item(resource="vol-3")
    result = compare(snap([kept, gone]), snap([kept, arrived], when=LATER))
    assert [f["id"] for f in result.fixed] == [gone["id"]]
    assert [f["id"] for f in result.new] == [arrived["id"]]
    assert [c.id for c in result.still_open] == [kept["id"]]
    assert not result.changed


def test_money_adds_up_on_both_sides():
    from preflight.core.compare import compare

    before = [item(resource="vol-1", monthly=100.0), item(resource="vol-2", monthly=40.0)]
    after = [item(resource="vol-1", monthly=100.0), item(resource="vol-3", monthly=12.5)]
    result = compare(snap(before), snap(after, when=LATER))
    assert result.fixed_monthly == 40.0
    assert result.new_monthly == 12.5
    assert result.monthly_before == 140.0
    assert result.monthly_after == 112.5
    assert result.priced


def test_an_unpriced_comparison_says_so():
    from preflight.core.compare import compare

    alarm = item("alarms-notify-nobody", "web-5xx", module="observability", monthly=None)
    result = compare(snap([alarm]), snap([], when=LATER))
    assert not result.priced
    assert result.fixed_monthly == 0.0


def test_a_finding_that_got_worse_is_changed():
    from preflight.core.compare import compare

    before = item(monthly=40.0, severity="medium")
    after = item(monthly=120.0, severity="high")
    (change,) = compare(snap([before]), snap([after], when=LATER)).changed
    assert change.severity_changed
    assert change.monthly_delta == 80.0


def test_rounding_isnt_a_change():
    from preflight.core.compare import compare

    result = compare(snap([item(monthly=40.0)]), snap([item(monthly=40.004)], when=LATER))
    assert not result.changed
    assert result.unchanged


def test_biggest_saving_comes_first():
    from preflight.core.compare import compare

    small, big = item(resource="vol-1", monthly=5.0), item(resource="vol-2", monthly=90.0)
    unpriced = item("public-buckets", "exports", module="security", monthly=None)
    checks = {"unattached-ebs-volumes": "ran", "public-buckets": "ran"}
    result = compare(snap([small, big, unpriced]), snap([], when=LATER, checks=checks))
    assert [f["id"] for f in result.fixed] == [big["id"], small["id"], unpriced["id"]]


# --- not calling it fixed when nobody looked ----------------------------------


def _gone_because(after: Snapshot, finding: dict | None = None) -> str:
    from preflight.core.compare import compare

    finding = finding or item()
    result = compare(snap([finding]), after)
    assert not result.fixed, "nobody looked, so nothing was fixed"
    (unseen,) = result.unverified
    assert unseen.id == finding["id"]
    assert not result.like_for_like
    return unseen.reason


def test_a_skipped_check_fixed_nothing():
    after = snap(when=LATER, checks={"unattached-ebs-volumes": "skipped"})
    assert _gone_because(after) == "unattached-ebs-volumes was skipped"


def test_a_failed_check_fixed_nothing():
    after = snap(when=LATER, checks={"unattached-ebs-volumes": "failed"})
    assert _gone_because(after) == "unattached-ebs-volumes failed"


def test_a_check_left_out_with_only_fixed_nothing():
    after = snap(when=LATER, checks={"idle-nat-gateways": "ran"})
    assert _gone_because(after) == "unattached-ebs-volumes wasn't run"


def test_a_module_left_out_fixed_nothing():
    after = snap(when=LATER, modules=("observability",), checks={"alarms-notify-nobody": "ran"})
    assert _gone_because(after) == "the cost module wasn't run"


def test_a_region_left_out_fixed_nothing():
    after = snap(when=LATER, regions=("us-east-1",))
    finding = item(region="eu-west-1")
    assert _gone_because(after, finding) == "eu-west-1 wasn't scanned"


def test_a_global_resource_isnt_lost_to_a_region_filter():
    from preflight.core.compare import compare

    root = item("root-user-unguarded", "root", module="security", region="global", monthly=None)
    before = snap([root], checks={"root-user-unguarded": "ran"})
    after = snap(when=LATER, regions=("us-east-1",), checks={"root-user-unguarded": "ran"})
    result = compare(before, after)
    assert [f["id"] for f in result.fixed] == [root["id"]]


def test_newly_checked_isnt_new():
    from preflight.core.compare import compare

    finding = item(region="eu-west-1")
    before = snap([], regions=("us-east-1",))
    result = compare(before, snap([finding], when=LATER))
    assert not result.new
    (unseen,) = result.first_seen
    assert unseen.reason == "eu-west-1 wasn't scanned"


# --- refusing what can't be compared -----------------------------------------


def test_two_accounts_are_refused():
    from preflight.core.compare import compare

    with pytest.raises(CompareError, match="two different accounts"):
        compare(snap(), snap(when=LATER, account="210987654321"))


def test_a_redacted_export_is_refused_with_the_reason():
    from preflight.core.compare import compare

    with pytest.raises(CompareError, match="redacted") as raised:
        compare(snap(), snap(when=LATER, redacted=True))
    assert "without --redact" in (raised.value.hint or "")


def test_the_same_file_twice_is_refused(tmp_path):
    from preflight.core.compare import compare

    path = tmp_path / "scan.json"
    path.write_text(json.dumps(export()), encoding="utf-8")
    with pytest.raises(CompareError, match="same export twice"):
        compare(load(path), load(path))


def test_newest_first_is_put_the_right_way_round():
    from preflight.core.compare import compare

    old, new = item(resource="vol-1"), item(resource="vol-2")
    result = compare(snap([new], when=LATER), snap([old]))
    assert result.swapped
    assert result.before.finished_at == EARLIER
    assert [f["id"] for f in result.fixed] == [old["id"]]
    assert [f["id"] for f in result.new] == [new["id"]]
