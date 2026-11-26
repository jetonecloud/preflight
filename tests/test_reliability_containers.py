"""ECS services one task from down."""

from __future__ import annotations

from conftest import days_ago, denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.reliability.containers import ECS_SERVICES_AT_RISK as CHECK

ACCOUNT = "123456789012"
CLUSTER = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/main"


def service(name="api", desired=2, running=None, subnets=("subnet-a", "subnet-b"), **extra):
    return {
        "serviceName": name,
        "serviceArn": f"arn:aws:ecs:us-east-1:{ACCOUNT}:service/main/{name}",
        "status": "ACTIVE",
        "desiredCount": desired,
        "runningCount": desired if running is None else running,
        "schedulingStrategy": "REPLICA",
        "createdAt": days_ago(60),
        "deployments": [{"status": "PRIMARY", "rolloutState": "COMPLETED"}],
        "networkConfiguration": {"awsvpcConfiguration": {"subnets": list(subnets)}},
        "tags": [],
        **extra,
    }


def account(*services):
    described = list(services)
    return {
        "list_clusters": {"clusterArns": [CLUSTER]},
        "list_services": {"serviceArns": [s["serviceArn"] for s in described]},
        "describe_services": lambda **params: {
            "services": [s for s in described if s["serviceArn"] in params["services"]]
        },
    }


def test_two_tasks_in_two_subnets_are_fine():
    outcome = run(CHECK, account(service()))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_a_service_with_nothing_running():
    (found,) = findings(CHECK, account(service(running=0)))
    assert found.title == "ECS service with no tasks running"
    assert found.level is Severity.HIGH
    assert found.confidence is Confidence.HIGH
    assert found.resource.id == "main/api"
    assert found.resource.kind == "ecs:service"


def test_flags_a_single_task_service():
    (found,) = findings(CHECK, account(service(desired=1)))
    assert found.title == "ECS service running a single task"
    assert found.level is Severity.MEDIUM


def test_daemon_services_run_one_per_host_by_design():
    assert findings(CHECK, account(service(desired=1, schedulingStrategy="DAEMON"))) == ()


def test_flags_a_service_confined_to_one_subnet():
    (found,) = findings(CHECK, account(service(subnets=("subnet-a",))))
    assert found.title == "ECS service confined to one subnet"
    assert "two Availability Zones" in found.recommendation


def test_several_problems_make_one_finding():
    (found,) = findings(CHECK, account(service(desired=1, subnets=("subnet-a",))))
    assert found.title == "ECS service running a single task"
    assert found.recommendation == (
        "Run at least two tasks; give it subnets in at least two Availability Zones."
    )


def test_a_service_mid_deploy_is_left_alone():
    deploying = service(running=0, deployments=[{"rolloutState": "IN_PROGRESS"}])
    assert findings(CHECK, account(deploying)) == ()


def test_scaled_to_zero_new_and_dev_services_are_left_alone():
    parked = service("parked", desired=0, running=0)
    new = service("new", desired=1, createdAt=days_ago(1))
    dev = service("dev", desired=1, tags=[{"key": "env", "value": "dev"}])
    quiet = service("quiet", desired=1, tags=[{"key": "preflight:ignore", "value": "true"}])
    assert findings(CHECK, account(parked, new, dev, quiet)) == ()


def test_describes_services_ten_at_a_time():
    many = [service(f"s{index}") for index in range(23)]
    responses = account(*many)
    answer = responses["describe_services"]
    batches: list[int] = []

    def describe(**params):
        batches.append(len(params["services"]))
        return answer(**params)

    responses["describe_services"] = describe
    assert run(CHECK, responses).examined == 23
    assert batches == [10, 10, 3]


def test_no_clusters_means_no_further_reads():
    outcome = run(CHECK, {"list_clusters": {"clusterArns": []}})
    assert outcome.status == "ran"
    assert outcome.examined == 0


def test_skipped_without_permission():
    responses = account(service())
    responses["describe_services"] = denied("DescribeServices")
    outcome = run(CHECK, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ecs:DescribeServices"
