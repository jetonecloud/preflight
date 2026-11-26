"""Services that deploy a moving image tag."""

from __future__ import annotations

import pytest
from conftest import days_ago, denied, findings, run

from preflight.core.findings import Confidence, Severity
from preflight.modules.delivery.images import SERVICES_ON_MOVING_TAGS as CHECK
from preflight.modules.delivery.images import parse_image

ACCOUNT = "123456789012"
CLUSTER = f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/main"
ECR = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com"


def service(name="api", image="nginx:1.27", **extra):
    return {
        "serviceName": name,
        "serviceArn": f"arn:aws:ecs:us-east-1:{ACCOUNT}:service/main/{name}",
        "status": "ACTIVE",
        "desiredCount": 2,
        "createdAt": days_ago(60),
        "taskDefinition": f"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/{name}:7",
        "tags": [],
        "_image": image,
        **extra,
    }


def account(*services, repositories=()):
    described = list(services)
    images = {s["taskDefinition"]: s["_image"] for s in described}
    return {
        "list_clusters": {"clusterArns": [CLUSTER]},
        "list_services": {"serviceArns": [s["serviceArn"] for s in described]},
        "describe_services": lambda **params: {
            "services": [s for s in described if s["serviceArn"] in params["services"]]
        },
        "describe_task_definition": lambda **params: {
            "taskDefinition": {
                "containerDefinitions": [{"name": "app", "image": images[params["taskDefinition"]]}]
            }
        },
        "describe_repositories": {"repositories": list(repositories)},
    }


@pytest.mark.parametrize(
    ("image", "host", "repository", "tag", "digest"),
    [
        ("nginx", None, "nginx", None, None),
        ("nginx:latest", None, "nginx", "latest", None),
        ("team/app:v1", None, "team/app", "v1", None),
        ("localhost:5000/app", "localhost:5000", "app", None, None),
        ("registry.io:5000/team/app:2", "registry.io:5000", "team/app", "2", None),
        (f"{ECR}/api:latest", ECR, "api", "latest", None),
        ("app@sha256:abc", None, "app", None, "sha256:abc"),
        ("app:latest@sha256:abc", None, "app", "latest", "sha256:abc"),
    ],
)
def test_image_references_come_apart(image, host, repository, tag, digest):
    ref = parse_image(image)
    assert (ref.host, ref.repository, ref.tag, ref.digest) == (host, repository, tag, digest)


def test_a_versioned_image_is_fine():
    outcome = run(CHECK, account(service()))
    assert outcome.findings == ()
    assert outcome.examined == 1


@pytest.mark.parametrize("image", ["nginx", "nginx:latest", f"{ECR}/api:latest"])
def test_flags_latest_and_untagged_images(image):
    (found,) = findings(CHECK, account(service(image=image)))
    assert found.title == "ECS service deploys a moving image tag"
    assert found.level is Severity.MEDIUM
    assert found.confidence is Confidence.MEDIUM
    assert found.resource.id == "main/api"
    assert f"app runs {image}" in " ".join(found.evidence)


def test_production_tag_makes_it_high_confidence():
    prod = service(image="nginx", tags=[{"key": "Environment", "value": "production"}])
    (found,) = findings(CHECK, account(prod))
    assert found.confidence is Confidence.HIGH


def test_a_digest_pins_the_image_whatever_the_tag():
    assert findings(CHECK, account(service(image="app:latest@sha256:abc"))) == ()


def test_latest_in_an_immutable_ecr_repository_cannot_move():
    immutable = {"repositoryName": "api", "imageTagMutability": "IMMUTABLE"}
    assert (
        findings(CHECK, account(service(image=f"{ECR}/api:latest"), repositories=[immutable])) == ()
    )


def test_latest_in_a_mutable_ecr_repository_can():
    mutable = {"repositoryName": "api", "imageTagMutability": "MUTABLE"}
    (found,) = findings(CHECK, account(service(image=f"{ECR}/api:latest"), repositories=[mutable]))
    assert found.title == "ECS service deploys a moving image tag"


def test_another_accounts_ecr_isnt_looked_up():
    other = "999999999999.dkr.ecr.us-east-1.amazonaws.com/api:latest"
    responses = account(service(image=other))
    responses["describe_repositories"] = denied("DescribeRepositories")
    (found,) = findings(CHECK, responses)
    assert found.resource.id == "main/api"


def test_task_definitions_are_read_once():
    shared = f"arn:aws:ecs:us-east-1:{ACCOUNT}:task-definition/worker:3"
    responses = account(
        service("a", image="worker", taskDefinition=shared),
        service("b", image="worker", taskDefinition=shared),
    )
    assert len(findings(CHECK, responses)) == 2


def test_dev_new_idle_and_ignored_services_are_left_alone():
    dev = service("dev", image="nginx", tags=[{"key": "env", "value": "dev"}])
    new = service("new", image="nginx", createdAt=days_ago(2))
    idle = service("idle", image="nginx", desiredCount=0)
    quiet = service("quiet", image="nginx", tags=[{"key": "preflight:ignore", "value": "yes"}])
    assert findings(CHECK, account(dev, new, idle, quiet)) == ()


def test_skipped_without_permission():
    responses = account(service(image="nginx"))
    responses["describe_task_definition"] = denied("DescribeTaskDefinition")
    outcome = run(CHECK, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ecs:DescribeTaskDefinition"
