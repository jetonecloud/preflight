# Running Preflight from CloudShell

[AWS CloudShell](https://console.aws.amazon.com/cloudshell) is a terminal in
the AWS console, already signed in as whoever you are in that account. It's
the fastest way to run Preflight if you don't have the AWS CLI set up
locally, or if you'd rather nothing touched your laptop at all.

## The short version

Open CloudShell from the console toolbar, then:

```sh
curl -fsSL https://jetonecloud.com/preflight | sh
export PATH="$HOME/.local/bin:$PATH"

preflight scan --current --region us-east-1
```

`--current` means "use the credentials that are already here", which in
CloudShell is your console identity. You'll see what Preflight is about to
read, the whole report is printed in the shell when it's done, and a JSON
export of it lands in the current directory.

## Getting the report out

The report is terminal output, so selecting it and copying it works — it is
plain ASCII, so it pastes into a ticket or an email unchanged.

For the JSON, CloudShell has a file download built in: **Actions → Download
file**, then give it the export's name — something like
`preflight-report-123456789012-20261022-141500.json`. `ls` will show you
exactly what was written.

## Which identity you're using

CloudShell runs as the console user or role you're signed in with, which is
usually broader than Preflight needs. It will say so:

```
! Scanning as arn:aws:sts::123456789012:assumed-role/AdminRole/you
  Preflight only reads, but it can't tell what else this identity is
  allowed to do.
```

That's a caution, not a problem — Preflight only ever makes `Get`, `List`
and `Describe` calls. If you'd rather it ran with nothing but the read
access it needs, generate the role first and assume it:

```sh
preflight scan --modules cost --save
aws cloudformation deploy --template-file preflight-role.cfn.yaml \
  --stack-name preflight-role --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn="$(aws sts get-caller-identity --query Arn --output text)"

preflight scan --role-arn "$(aws cloudformation describe-stacks \
  --stack-name preflight-role \
  --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text)"
```

The first command makes no AWS calls at all — it just writes the template,
so you can read every permission before deploying it.

## Things worth knowing

- **Scanning every region takes a while.** CloudShell is in one region, but
  Preflight scans every region the account has enabled unless you narrow it.
  `--region us-east-1,eu-west-1` keeps it quick while you're trying it out.
- **CloudShell's home directory persists; `/tmp` doesn't.** Write the JSON
  export to your home directory (the default) if you want it to survive a
  session timeout, and download it before you finish.
- **You get 1 GB of storage.** Exports are tens of kilobytes, so this only
  matters if you keep hundreds.
- **Sessions idle out after about 20 minutes.** A scan of a large account
  across every region can outlast an inattentive session; use `--region` or
  keep the tab active.
- **Nothing leaves the account.** The report is printed in the shell and the
  export is written to CloudShell's filesystem, and nowhere else.

## If you'd rather not install anything at all

CloudShell has Python 3.11, so `pipx` works too:

```sh
pip install --user pipx && pipx install preflight-cli
```

Either way, `preflight demo` prints a sample report with no credentials and
no AWS calls, if you want to see the output before running a real scan.
