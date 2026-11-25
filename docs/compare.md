# Comparing two scans

A report tells you what's wrong today. The second scan is the one that tells
you whether the work you did made a difference. `preflight diff` reads two
JSON exports a scan already wrote and says what happened in between.

It makes no AWS calls and needs no credentials: it reads two files.

```sh
preflight diff                                      # the last two scans in this directory
preflight diff --in ./audits                        # ... in another one
preflight diff preflight-report-<acct>-<old>.json   # that scan, and the newest one since
preflight diff old.json new.json                    # exactly these two
```

With no files named, it takes the newest export in the directory and the one
before it for the same account, and says which two it picked. PDFs, files
that aren't exports, and redacted exports are passed over. Given newest
first, the two are swapped rather than refused.

## What it reports

Every finding has an ID that is the same across scans — module, check,
region and resource — so matching is exact rather than fuzzy:

| Bucket | Means |
|---|---|
| **Fixed** | In the earlier scan, gone from the later one, and the later scan looked where it was |
| **New** | Not in the earlier scan, in the later one, and the earlier scan looked where it is |
| **Changed** | Open in both, but its severity or its monthly figure moved |
| **Still open** | In both. Counted, not repeated — the later report has each in full |
| **Can't tell** | Gone or arrived, but one of the scans didn't look (below) |

When anything is priced it leads with the monthly figure fixed, and what was
open before and after. When nothing is — a security-only comparison — there's
no dollar figure, as in the report itself.

## "Fixed" means somebody looked

A finding that disappears isn't necessarily fixed. The later scan may simply
not have looked. `diff` checks, for every finding that went missing, whether
the later scan:

- ran the module it belongs to (`--modules`),
- ran its check at all (`--only`),
- ran that check successfully — not **skipped** for a missing permission, or
  **failed**,
- covered its region (`--region`).

If not, the finding goes under **Can't tell** with the reason, and isn't
counted or priced as fixed. The same test runs the other way: a region
scanned for the first time doesn't make everything in it **new**, it makes
it *seen for the first time*.

Global resources — IAM users, the root user — live in no listed region, so
narrowing `--region` on the later scan doesn't count against them.

## What it refuses

- **Two different accounts.** A comparison only means something for one
  account over time.
- **Redacted exports.** `--redact` numbers resources per report, so `vol-1`
  in one scan isn't `vol-1` in the next. Compare the unredacted exports.
- **The same file twice**, and **an export from a newer Preflight** than the
  one you're running.

Each exits with status 2 and says what to do instead.

## In a script, or CI

```sh
preflight diff --json > diff.json        # the comparison, versioned, on stdout
preflight diff --fail-on-new             # exit 1 if anything new turned up
```

The readable copy still goes to stderr, so stdout is clean JSON:

```jsonc
{
  "schema_version": 1,
  "account": { "id": "123456789012" },
  "before": { "path": "...", "finished_at": "2026-11-01T09:00:00+00:00", "regions": [...], "findings": 28 },
  "after":  { "path": "...", "finished_at": "2026-11-15T09:00:00+00:00", "regions": [...], "findings": 27 },
  "summary": { "fixed": 2, "new": 1, "still_open": 26, "changed": 1,
               "unverified": 0, "first_seen": 0, "like_for_like": true,
               "fixed_monthly_usd": 255.0, "new_monthly_usd": 45.0, ... },
  "fixed":      [ { ...the finding as the earlier export wrote it... } ],
  "new":        [ { ...the finding as the later export wrote it... } ],
  "changed":    [ { "id": "...", "severity": {"before": "medium", "after": "high"},
                    "monthly_usd": {"before": 46.0, "after": 76.0}, "finding": {...} } ],
  "still_open": [ "cost/oversized-instances/us-east-1/i-0abc", ... ],
  "unverified": [ { "finding": {...}, "reason": "eu-west-1 wasn't scanned" } ],
  "first_seen": [ ]
}
```

`--fail-on-new` counts only **New** — findings the earlier scan could have
seen and didn't — so widening a scheduled scan to another region doesn't fail
the build. `like_for_like` is `false` whenever anything landed in
*Can't tell*, if you'd rather fail on that too.
