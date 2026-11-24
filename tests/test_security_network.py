"""Security groups that let the internet in."""

from __future__ import annotations

from conftest import denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.security.network import OPEN_SECURITY_GROUPS

GROUP = "sg-0123456789abcdef0"


def rule(port=5432, to=None, protocol="tcp", cidr="0.0.0.0/0", v6=None):
    data = {
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": cidr}] if cidr else [],
        "Ipv6Ranges": [{"CidrIpv6": v6}] if v6 else [],
    }
    if protocol != "-1":
        data["FromPort"] = port
        data["ToPort"] = port if to is None else to
    return data


def group(*rules, group_id=GROUP, name="db-access", group_tags=None):
    return {
        "GroupId": group_id,
        "GroupName": name,
        "IpPermissions": list(rules),
        "Tags": group_tags or [],
    }


def account(*groups, attached=(GROUP,)):
    return {
        "describe_security_groups": {"SecurityGroups": list(groups)},
        "describe_network_interfaces": {
            "NetworkInterfaces": [{"Groups": [{"GroupId": g}]} for g in attached]
        },
    }


def test_flags_a_database_port_open_to_everyone():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(5432))))
    assert len(found) == 1
    finding = found[0]
    assert finding.title == "Security group open to the internet on admin or database ports"
    assert finding.resource.id == GROUP
    assert finding.resource.kind == "ec2:security-group"
    assert finding.resource.name == "db-access"
    assert finding.level is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert "port 5432 (PostgreSQL)" in finding.evidence[0]
    assert "1 network interface is using it" in finding.evidence[1]


def test_https_open_to_everyone_is_a_web_server_doing_its_job():
    outcome = run(OPEN_SECURITY_GROUPS, account(group(rule(443), rule(80))))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_a_narrow_source_is_fine():
    assert findings(OPEN_SECURITY_GROUPS, account(group(rule(22, cidr="10.0.0.0/8")))) == ()


def test_ssh_alone_is_medium():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(22))))
    assert found[0].title == "SSH open to the internet"
    assert found[0].level is Severity.MEDIUM


def test_all_traffic_is_called_out():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(protocol="-1"))))
    assert found[0].title == "Security group open to the internet on every port"
    assert found[0].level is Severity.HIGH


def test_ipv6_anywhere_counts_too():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(3389, cidr=None, v6="::/0"))))
    assert "port 3389 (RDP)" in found[0].evidence[0]


def test_a_range_covering_a_sensitive_port_is_caught():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(6000, to=6500))))
    assert "port 6379 (Redis)" in found[0].evidence[0]


def test_a_huge_range_is_everything_in_all_but_name():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(1024, to=65535))))
    assert "ports 1024-65535 (tcp)" in found[0].evidence[0]


def test_a_group_nothing_uses_is_not_exposed():
    assert findings(OPEN_SECURITY_GROUPS, account(group(rule(5432)), attached=())) == ()


def test_the_default_group_is_named_as_such():
    found = findings(OPEN_SECURITY_GROUPS, account(group(rule(protocol="-1"), name="default")))
    assert any("default group" in line for line in found[0].evidence)


def test_respects_the_ignore_tag():
    tagged = group(rule(22), group_tags=tags(**{"preflight:ignore": "bastion"}))
    assert findings(OPEN_SECURITY_GROUPS, account(tagged)) == ()


def test_missing_interfaces_permission_skips_rather_than_guesses():
    responses = account(group(rule(5432)))
    responses["describe_network_interfaces"] = denied("DescribeNetworkInterfaces")
    outcome = run(OPEN_SECURITY_GROUPS, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ec2:DescribeNetworkInterfaces"
