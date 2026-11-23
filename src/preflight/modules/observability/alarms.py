"""Alarms, and whether they reach anyone.

An alarm is only as good as where it goes. The failure this module looks for
isn't "no monitoring" so much as monitoring that was set up once and quietly
stopped working: actions switched off during an incident and never switched
back on, a topic whose only subscriber left the company, an email
subscription nobody clicked to confirm.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from preflight.core.findings import Confidence, Finding, Resource, Severity
from preflight.core.scan import ScanContext, ignored
from preflight.modules.base import Check

MODULE = "observability"

#: SNS reports these in place of an ARN for a subscription that doesn't
#: deliver anywhere yet - or any more.
UNCONFIRMED = frozenset({"PendingConfirmation", "Deleted"})

#: How many alarm names a finding about a topic lists before summarising.
NAMES_SHOWN = 5

# --- alarms that notify nobody --------------------------------------------


def alarms_that_notify_nobody(ctx: ScanContext) -> Iterator[Finding]:
    """Alarms that are switched off, go nowhere, or go to a topic nobody reads."""
    for region in ctx.regions:
        alarms = _metric_alarms(ctx, region)
        composites = ctx.collect(
            "cloudwatch:DescribeAlarms",
            "CompositeAlarms",
            region=region,
            AlarmTypes=["CompositeAlarm"],
        )
        everything = [*alarms, *composites]
        if not everything:
            continue

        # A metric alarm feeding a composite is meant to have no actions of
        # its own: the composite does the notifying.
        rules = " ".join(str(alarm.get("AlarmRule") or "") for alarm in composites)

        needs_sns = any(_topics_of(alarm) for alarm in everything)
        topics, subscribers = _topic_audience(ctx, region) if needs_sns else (set(), {})

        dead_topics: dict[str, list[str]] = {}
        for alarm in everything:
            ctx.looked_at()
            name = str(alarm.get("AlarmName"))
            arn = str(alarm.get("AlarmArn") or ctx.arn("cloudwatch", region, f"alarm:{name}"))
            if ignored(ctx.tags_for(region, arn)):
                continue

            actions = [str(action) for action in alarm.get("AlarmActions") or ()]
            if not actions:
                if f'"{name}"' in rules or f"({name})" in rules:
                    continue
                yield _alarm_finding(
                    ctx,
                    region,
                    alarm,
                    title="Alarm with nowhere to send it",
                    why=(
                        "It has no alarm actions: when it goes into ALARM, the "
                        "only place that shows is the CloudWatch console."
                    ),
                    confidence=Confidence.MEDIUM,
                    severity=Severity.LOW,
                    caveat=(
                        "Some alarms are deliberately action-free - a deployment's "
                        "rollback trigger, or one that only colours a dashboard. If "
                        "that's this one, tag it 'preflight:ignore'."
                    ),
                )
                continue

            if alarm.get("ActionsEnabled") is False:
                yield _alarm_finding(
                    ctx,
                    region,
                    alarm,
                    title="Alarm with its actions switched off",
                    why=(
                        f"It has {len(actions)} action(s) configured, but actions "
                        "are disabled, so none of them will run when it fires."
                    ),
                    confidence=Confidence.HIGH,
                    severity=Severity.MEDIUM,
                    caveat=(
                        "Actions are usually switched off to silence an alarm during "
                        "an incident, and forgotten afterwards."
                    ),
                )
                continue

            sns = _topics_of(alarm)
            if len(sns) != len(actions):
                # It also scales, recovers, or runs something. It does a job.
                continue
            if any(_reaches_someone(topic, region, topics, subscribers) for topic in sns):
                continue
            for topic in sns:
                dead_topics.setdefault(topic, []).append(name)

        for topic, names in sorted(dead_topics.items()):
            yield _topic_finding(ctx, region, topic, names, exists=topic in topics)


def _metric_alarms(ctx: ScanContext, region: str) -> list[dict[str, Any]]:
    return ctx.collect(
        "cloudwatch:DescribeAlarms",
        "MetricAlarms",
        region=region,
        AlarmTypes=["MetricAlarm"],
    )


def _topics_of(alarm: dict[str, Any]) -> list[str]:
    """The alarm's actions that publish to SNS, as opposed to doing something."""
    return [
        str(action)
        for action in alarm.get("AlarmActions") or ()
        if str(action).split(":")[2:3] == ["sns"]
    ]


def _topic_region(topic: str) -> str:
    parts = topic.split(":")
    return parts[3] if len(parts) > 3 else ""


def _reaches_someone(
    topic: str,
    region: str,
    topics: set[str],
    subscribers: dict[str, int],
) -> bool:
    if _topic_region(topic) != region:
        # Another region's topic: unknowable from here, so assume it works.
        return True
    return topic in topics and subscribers.get(topic, 0) > 0


def _topic_audience(ctx: ScanContext, region: str) -> tuple[set[str], dict[str, int]]:
    """Every topic in the region, and how many confirmed subscribers each has."""
    topics = {
        str(topic["TopicArn"])
        for topic in ctx.collect("sns:ListTopics", "Topics", region=region)
        if topic.get("TopicArn")
    }
    confirmed: dict[str, int] = {}
    for subscription in ctx.collect("sns:ListSubscriptions", "Subscriptions", region=region):
        if str(subscription.get("SubscriptionArn")) in UNCONFIRMED:
            continue
        topic = str(subscription.get("TopicArn") or "")
        confirmed[topic] = confirmed.get(topic, 0) + 1
    return topics, confirmed


def _alarm_finding(
    ctx: ScanContext,
    region: str,
    alarm: dict[str, Any],
    *,
    title: str,
    why: str,
    confidence: Confidence,
    severity: Severity,
    caveat: str,
) -> Finding:
    name = str(alarm.get("AlarmName"))
    arn = str(alarm.get("AlarmArn") or ctx.arn("cloudwatch", region, f"alarm:{name}"))
    evidence = [why]
    if alarm.get("MetricName"):
        evidence.append(f"Watches {alarm.get('Namespace')} {alarm.get('MetricName')}.")
    elif alarm.get("AlarmRule"):
        evidence.append(f"Composite alarm: {str(alarm['AlarmRule'])[:160]}")
    if alarm.get("StateValue"):
        evidence.append(f"Currently {alarm['StateValue']}.")
    evidence.append(caveat)
    return Finding(
        check="alarms-that-notify-nobody",
        module=MODULE,
        title=title,
        resource=Resource(
            id=name,
            kind="cloudwatch:alarm",
            region=region,
            arn=arn,
            tags=dict(ctx.tags_for(region, arn)),
        ),
        evidence=tuple(evidence),
        recommendation=(
            "Point it at a topic someone is subscribed to - the on-call rotation, "
            "or a team channel - and make sure its actions are enabled. If nobody "
            "would act on it, delete it rather than keep a false sense of cover."
        ),
        confidence=confidence,
        severity=severity,
    )


def _topic_finding(
    ctx: ScanContext, region: str, topic: str, alarms: list[str], *, exists: bool
) -> Finding:
    name = topic.rsplit(":", 1)[-1]
    shown = ", ".join(sorted(alarms)[:NAMES_SHOWN])
    more = len(alarms) - NAMES_SHOWN
    listed = f"{shown} and {more} more" if more > 0 else shown
    if exists:
        title = "Alarms sent to a topic nobody is subscribed to"
        why = (
            "The topic exists but has no confirmed subscriptions - an email "
            "nobody clicked to confirm counts as none."
        )
    else:
        title = "Alarms sent to a topic that doesn't exist"
        why = "The topic isn't in this account any more, so publishing to it fails."
    return Finding(
        check="alarms-that-notify-nobody",
        module=MODULE,
        title=title,
        resource=Resource(
            id=name,
            kind="sns:topic",
            region=region,
            arn=topic,
            tags=dict(ctx.tags_for(region, topic)),
        ),
        evidence=(
            why,
            f"{len(alarms)} alarm(s) notify only this topic: {listed}.",
            "When any of them fires, nobody hears about it.",
        ),
        recommendation=(
            "Subscribe whoever is on call - email, chat, or a paging tool - and "
            "confirm the subscription. One fix covers every alarm listed."
        ),
        confidence=Confidence.HIGH,
        severity=Severity.HIGH if len(alarms) > 1 else Severity.MEDIUM,
    )


ALARMS_THAT_NOTIFY_NOBODY = Check(
    key="alarms-that-notify-nobody",
    title="Alarms that notify nobody",
    looks_for=(
        "Alarms that are switched off, have nowhere to go, or send to a topic nobody reads."
    ),
    actions=("cloudwatch:DescribeAlarms", "sns:ListTopics", "sns:ListSubscriptions"),
    run=alarms_that_notify_nobody,
)
