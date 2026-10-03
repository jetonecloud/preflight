## Summary

<!-- What does this change do, and why? -->

## What does this read from AWS?

<!-- List any new API calls. Confirm each is Get*/List*/Describe* only and has been added to iam/policy.json and the module's declared permissions. -->

- [ ] No new AWS API calls, OR
- [ ] New calls added, all read-only, and added to `iam/policy.json`
- [ ] `SECURITY.md` updated if this changes what Preflight reads

## Test plan

- [ ] Added/updated tests, including a no-finding case and a false-positive guard case
- [ ] `uv run pytest` passes
- [ ] `uv run ruff check . && uv run ruff format --check .` passes

## Checklist

- [ ] No credentials, secrets, or raw API responses are logged or transmitted
- [ ] No write/mutating AWS calls introduced
- [ ] License-compatible if logic was adapted from another project (attribution added to `NOTICE`)
