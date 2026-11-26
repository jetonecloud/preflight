# The Security Check

Six checks about who can get into the account and what's left open. This
page is the full reference: what each one looks at, what makes it stay
quiet, and how severity is set when there's no money to set it by.

Run it on its own:

```sh
preflight scan --modules security --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole
```

Leave `--modules` off and it runs alongside the Cost, Observability,
Reliability and Delivery Checks. To see the checks and the exact permissions each one needs, without
an account:

```sh
preflight scan --modules security --list-checks
```

## The checks

| Check | Looks for | Stays quiet when |
|---|---|---|
| `root-user-unguarded` | A root user with no MFA device, or with access keys of its own | Root has MFA and no keys |
| `public-buckets` | Buckets S3 reports as public by policy; buckets with no Block Public Access at all | The bucket has no policy, or a private one, and Block Public Access is configured; the bucket is in a region the scan didn't cover |
| `open-security-groups` | Security groups that admit `0.0.0.0/0` or `::/0` to admin or database ports, to every port, or to a range of 1,000 ports or more | The open ports are web ports (80, 443 and so on); the source is narrower than the whole internet; no network interface uses the group |
| `console-users-without-mfa` | IAM users with a console password and no MFA device | The user has MFA, or has no console password; the user is less than 7 days old and hasn't signed in yet |
| `stale-access-keys` | Active access keys unused for 90 days or more, never used after 30 days, or in use but over a year old | The key is inactive; it was created this month and hasn't been used yet; it's in use and under a year old |
| `trail-coverage` | Scanned regions no logging CloudTrail trail covers; trails that exist but have stopped logging | Any multi-region, organisation, or local trail covering the region is logging |

Every threshold above is a constant at the top of the file that implements
the check, under [`src/preflight/modules/security/`](../src/preflight/modules/security/).

### Root user unguarded

Read from the account summary, one call. No MFA and access keys are one
finding rather than two, because both are fixed in the same sitting as root.
The finding is reported against `global`, since IAM isn't in a region.

### Public buckets

Preflight doesn't parse bucket policies. It asks S3 — `GetBucketPolicyStatus`
gives S3's own verdict, the one the console's "Public" badge is built on —
and reads Block Public Access next to it:

- **A public policy** is high severity and high confidence, and the finding
  says which Block Public Access settings are off. A static website or a
  public dataset is public on purpose: tag the bucket `preflight:ignore`.
- **No Block Public Access at all** is low severity and medium confidence:
  nothing on the bucket stops the next policy edit from publishing it, but
  the account-wide setting may, and reading that needs `s3:GetAccountPublicAccessBlock`,
  which Preflight doesn't ask for.

Bucket ACLs aren't read. Each bucket is reported in its own region, and only
when that region was part of the scan.

### Security groups open to the internet

A rule open to the whole internet on one of these ports is flagged: SSH (22),
Telnet (23), SMB (445), SQL Server (1433), Oracle (1521), the Docker API
(2375, 2376), MySQL (3306), RDP (3389), PostgreSQL (5432), Kibana (5601),
CouchDB (5984), Redis (6379), Elasticsearch (9200), Memcached (11211) and
MongoDB (27017). So is a rule allowing all traffic, or a TCP/UDP range of
1,000 ports or more.

Only groups a network interface is using are reported — an open rule on a
group nothing uses is untidy, not exposed — so the check also reads
`ec2:DescribeNetworkInterfaces`. It doesn't look at whether the instance
behind the interface has a public address, and says so.

SSH on its own is medium severity: key-only SSH open to the world is common
and survivable. Session Manager needs no inbound port at all.

### Console users without MFA

`GetLoginProfile` tells the check whether a user has a console password at
all; IAM answers `NoSuchEntity` when they don't, and that's read as "no
password". A user who has signed in within 90 days is high severity. A
password nobody has used in longer is medium, and the advice is to delete it
rather than protect it.

### Stale access keys

| Key | Finding | Severity |
|---|---|---|
| Unused for a year or more, or never used after a year | Unused | High |
| Unused for 90 days or more, or never used after 30 days | Unused | Medium |
| In use, but created over a year ago | Not rotated | Low |

The finding is about the key, named by its user.

### CloudTrail coverage

Every scanned region should be covered by a trail that's logging: a
multi-region trail, an organisation trail from the management account (seen
as a shadow trail), or a trail based in that region. One logging trail is
enough, whatever else is lying around switched off.

A trail that covers a region but has stopped logging is reported by name,
since that's the thing to fix. No trail anywhere is one account-wide
finding. A region nothing covers, in an account with trails elsewhere, is
medium severity: a region nobody uses is where an attacker would.

## Silencing a finding

Tag the bucket, security group, trail or IAM user `preflight:ignore`. A
user's tag covers all of their access keys. Security groups return their own
tags, IAM users are read with `iam:ListUserTags`, and buckets and trails are
looked up through `tag:GetResources`. The root user can't be tagged, so its
finding can't be silenced — fix it instead.

## Severity

None of these findings has a dollar figure, so each check sets its own:

| Finding | Severity |
|---|---|
| Root user without MFA, or with access keys | High |
| A bucket with a public policy | High |
| A security group open on a database or admin port, every port, or a wide range | High |
| A console user without MFA who signed in within 90 days | High |
| An access key unused for a year | High |
| A trail that has stopped logging; no trail at all | High |
| SSH open to the internet | Medium |
| A console password unused for 90 days, without MFA | Medium |
| An access key unused for 90 days, or never used | Medium |
| A region no trail covers | Medium |
| A bucket with no Block Public Access | Low |
| An access key in use but over a year old | Low |

## What the scan reads

| Permission | Used by |
|---|---|
| `sts:GetCallerIdentity` | Every scan, to show you which account it's about to read |
| `ec2:DescribeRegions` | Finding the regions to scan |
| `iam:GetAccountSummary` | Whether root has MFA and access keys |
| `iam:ListUsers` | Both user checks |
| `iam:GetLoginProfile` | Whether a user has a console password |
| `iam:ListMFADevices` | Whether a user has MFA |
| `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | Each key's age and when it was last used |
| `iam:ListUserTags` | `preflight:ignore` and owner names for users |
| `ec2:DescribeSecurityGroups` | The rules |
| `ec2:DescribeNetworkInterfaces` | Whether anything uses a group |
| `s3:ListAllMyBuckets`, `s3:GetBucketLocation` | The buckets, and which region each is in |
| `s3:GetBucketPolicyStatus` | S3's verdict on whether the policy is public |
| `s3:GetBucketPublicAccessBlock` | Block Public Access on each bucket |
| `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | Which trails cover which regions, and whether they're logging |
| `tag:GetResources` | `preflight:ignore` and owner names for buckets and trails |

None of them reads a password, a secret key, a policy document, an object
in a bucket or a CloudTrail event: the check sees names, settings, dates and
yes/no answers. `iam:GetLoginProfile` returns when a password was created,
never the password.

Shipping this module added `iam:GetLoginProfile`, `iam:ListUserTags` and
`ec2:DescribeNetworkInterfaces` to [`iam/policy.json`](../iam/policy.json),
and removed `iam:GetAccountPasswordPolicy` and `s3:GetEncryptionConfiguration`,
which nothing calls. A role generated for Security alone gets only the
actions above.
