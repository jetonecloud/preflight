"""Instances you couldn't launch again."""

from __future__ import annotations

from botocore.exceptions import ClientError
from conftest import days_ago, denied, findings, run, tags

from preflight.core.findings import Confidence, Severity
from preflight.modules.delivery.amis import INSTANCES_YOU_COULDNT_REBUILD as CHECK


def instance(instance_id="i-1", image="ami-1", state="running", launched=100, **tag_pairs):
    return {
        "InstanceId": instance_id,
        "ImageId": image,
        "State": {"Name": state},
        "LaunchTime": days_ago(launched),
        "Tags": tags(**tag_pairs),
    }


def image(image_id="ami-1", built=90, name="web-2026", **extra):
    return {"ImageId": image_id, "Name": name, "CreationDate": days_ago(built), **extra}


def account(*instances, images=()):
    known = {i["ImageId"]: i for i in images}
    return {
        "describe_instances": {"Reservations": [{"Instances": list(instances)}]},
        "describe_images": lambda **params: {
            "Images": [known[i] for i in params["ImageIds"] if i in known]
        },
    }


def test_an_instance_on_a_recent_image_is_fine():
    outcome = run(CHECK, account(instance(), images=[image()]))
    assert outcome.findings == ()
    assert outcome.examined == 1


def test_flags_an_image_thats_gone():
    (found,) = findings(CHECK, account(instance(Name="web"), images=[]))
    assert found.title == "Instances launched from an image that's gone"
    assert found.level is Severity.MEDIUM
    assert found.confidence is Confidence.HIGH
    assert found.resource.id == "ami-1"
    assert found.resource.kind == "ec2:image"
    assert "1 running instance launched from it: i-1 (web)." in found.evidence
    assert "deregistered" in found.evidence[1]


def test_a_disabled_image_is_as_good_as_gone():
    (found,) = findings(CHECK, account(instance(), images=[image(State="disabled")]))
    assert found.title == "Instances launched from an image that's gone"
    assert "is disabled" in found.evidence[1]


def test_flags_an_image_over_a_year_old():
    (found,) = findings(CHECK, account(instance(), images=[image(built=500)]))
    assert found.title == "Instances launched from an image over a year old"
    assert found.level is Severity.LOW
    assert found.confidence is Confidence.MEDIUM
    assert "Image ami-1 (web-2026) was built 500 days ago" in found.evidence[1]


def test_one_finding_per_image_naming_its_instances():
    fleet = [instance(f"i-{n}") for n in range(5)]
    (found,) = findings(CHECK, account(*fleet, images=[]))
    assert found.evidence[0] == ("5 running instances launched from it: i-0, i-1, i-2 and 2 more.")


def test_an_unknown_id_doesnt_hide_the_rest():
    def describe(**params):
        if len(params["ImageIds"]) > 1 or params["ImageIds"] == ["ami-bad"]:
            raise ClientError(
                {"Error": {"Code": "InvalidAMIID.NotFound", "Message": "nope"}}, "DescribeImages"
            )
        return {"Images": [image("ami-good")]}

    responses = account(instance("i-1", "ami-bad"), instance("i-2", "ami-good"))
    responses["describe_images"] = describe
    (found,) = findings(CHECK, responses)
    assert found.resource.id == "ami-bad"


def test_old_images_are_fine_outside_production_but_missing_ones_arent():
    old = findings(CHECK, account(instance(env="dev"), images=[image(built=500)]))
    gone = findings(CHECK, account(instance(env="dev"), images=[]))
    assert old == ()
    assert len(gone) == 1


def test_stopped_new_and_ignored_instances_are_left_alone():
    stopped = instance("i-1", state="stopped")
    new = instance("i-2", launched=1)
    quiet = instance("i-3", **{"preflight:ignore": "true"})
    assert findings(CHECK, account(stopped, new, quiet, images=[])) == ()


def test_skipped_without_permission():
    responses = account(instance())
    responses["describe_images"] = denied("DescribeImages", "UnauthorizedOperation")
    outcome = run(CHECK, responses)
    assert outcome.status == "skipped"
    assert outcome.missing_action == "ec2:DescribeImages"
