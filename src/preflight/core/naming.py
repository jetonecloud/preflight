"""Names for the things Preflight generates.

A leaf module on purpose. The template builder names the role; the scanner
needs the same name to recognise when it's running as it. Keeping the
strings here means neither has to import the other, and the deployed stack,
the report and the warnings all agree on what the role is called.
"""

from __future__ import annotations

#: What `preflight scan` writes when you don't name a file.
DEFAULT_FILENAME = "preflight-role.cfn.yaml"

#: Resource names inside the generated CloudFormation template. Changing
#: either is a breaking change for anyone who already deployed the stack.
POLICY_NAME = "PreflightReadOnlyPolicy"
ROLE_NAME = "PreflightReadOnlyRole"

#: Where a scan writes its report, with the account and a timestamp filled in.
REPORT_STEM = "preflight-report"
