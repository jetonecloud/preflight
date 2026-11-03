"""Who made this, for the report that leaves the terminal.

The PDF goes to people who never ran the tool - a founder, a client, whoever
the ticket gets assigned to - so it says where it came from. That's one
sentence and one mark, loaded the same way the CloudFormation template is:
through `importlib.resources`, so it works from a wheel and from the frozen
single-file binary.

A leaf module. The terminal already says this in its own words, and neither
has to import the other to agree on the wording.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from preflight.core.pdf import Png, read_png

NAME = "Jet1"
TAGLINE = "Accountable infrastructure operations."
SITE = "jetonecloud.com"
BOOK = "https://jetonecloud.com/book"

#: What Preflight is, in the words the README uses.
WHAT = (
    "Preflight is a free, open-source, read-only AWS audit. It finds the first "
    "things worth fixing in deploys, cost, and bus factor."
)

#: Who Jet1 is, from the organisation's own description.
WHO = (
    "Jet1 is a managed DevOps team running your pipelines, AWS, and on-call "
    "under an SLA. Everything in your repos, owned by you."
)

MARK_FILE = "jet1-mark.png"


@lru_cache(maxsize=1)
def mark() -> Png:
    """The Jet1 mark, read once and reused on every page that draws it."""
    raw = resources.files("preflight").joinpath("assets", MARK_FILE).read_bytes()
    return read_png(raw)
