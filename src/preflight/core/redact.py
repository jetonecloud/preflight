"""Taking the account out of a report, so it can leave the room.

A Preflight report is written to be shared — with a co-founder, a board, a
contractor, whoever is going to approve the work. Sometimes the findings are
the point and the identifiers aren't, and a report full of real instance IDs
and an account number is awkward to paste into a thread.

`--redact` replaces every identifier with a stable pseudonym: the same volume
is `vol-1` everywhere in the report, so the document still reads as a document
and the numbers still add up — you just can't tell whose account it is. The
dollar figures, severities and reasoning are untouched, because those are the
part worth reading.

Redaction is not a security boundary. It's a courtesy to the reader, and a
report is only ever as redacted as the strings the checks put in it.
"""

from __future__ import annotations

import re

#: Twelve digits in a row is an AWS account ID anywhere it appears.
ACCOUNT_ID = re.compile(r"\b\d{12}\b")

#: Resource IDs AWS hands out, which all share the `prefix-hex` shape.
RESOURCE_ID = re.compile(
    r"\b(i|vol|snap|ami|eni|nat|subnet|vpc|sg|eipalloc|igw|rtb|acl|fl)-[0-9a-f]{8,17}\b"
)

#: Dotted quads. Over-matches version numbers in theory; in practice the only
#: four-part dotted numbers in a cost report are addresses.
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ACCOUNT_PLACEHOLDER = "<account>"
IP_PLACEHOLDER = "<ip>"


class Redactor:
    """Replaces identifiers with stable pseudonyms, or does nothing.

    One instance per report. The pseudonym registry lives on it, which is what
    makes `vol-1` mean the same volume in the headline, the evidence and the
    appendix.
    """

    def __init__(self, active: bool = False, *, account_id: str | None = None) -> None:
        self.active = active
        self._account_id = account_id
        self._aliases: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    # --- the pieces of a finding -----------------------------------------

    def identifier(self, value: str, kind: str = "resource") -> str:
        """A stable pseudonym for one resource ID."""
        if not self.active or not value:
            return value
        if value not in self._aliases:
            prefix = _prefix_for(value, kind)
            self._counts[prefix] = self._counts.get(prefix, 0) + 1
            self._aliases[value] = f"{prefix}-{self._counts[prefix]}"
        return self._aliases[value]

    def name(self, value: str | None) -> str | None:
        """Resource names are free text and frequently the most revealing part."""
        return None if self.active else value

    def account(self, value: str) -> str:
        return ACCOUNT_PLACEHOLDER if self.active else value

    def text(self, value: str) -> str:
        """Scrub a sentence: IDs we've already seen, account numbers, addresses.

        Runs the alias table first so a volume mentioned in someone else's
        evidence gets the same pseudonym it has in its own finding.
        """
        if not self.active or not value:
            return value
        scrubbed = value
        for real, alias in self._aliases.items():
            scrubbed = scrubbed.replace(real, alias)
        scrubbed = RESOURCE_ID.sub(lambda match: self.identifier(match.group(0)), scrubbed)
        if self._account_id:
            scrubbed = scrubbed.replace(self._account_id, ACCOUNT_PLACEHOLDER)
        scrubbed = ACCOUNT_ID.sub(ACCOUNT_PLACEHOLDER, scrubbed)
        return IPV4.sub(IP_PLACEHOLDER, scrubbed)

    def arn(self, value: str | None) -> str | None:
        """ARNs carry the account and often a human-chosen name. Drop them."""
        return None if self.active else value


def _prefix_for(value: str, kind: str) -> str:
    """`vol-0abc…` keeps `vol`; a database called `prod-api` becomes `rds-instance`.

    Falling back to the resource kind rather than something generic keeps the
    pseudonyms readable — a redacted report where everything is `resource-7`
    is technically redacted and useless to read.
    """
    if RESOURCE_ID.fullmatch(value):
        return value.split("-", 1)[0]
    return kind.replace(":", "-") or "resource"
