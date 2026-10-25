# Installing Preflight

Preflight is a single command-line tool. It runs on your machine, reads your
AWS account over the normal SDK credential chain, and writes a report to a
local file. Pick whichever of these you'd trust.

## The installer

```sh
curl -fsSL https://jetonecloud.com/preflight | sh
```

Downloads the right binary for your platform from the latest GitHub release,
checks its SHA-256 against the published `checksums.txt`, and refuses to
install on a mismatch. It installs to `~/.local/bin` by default.

```sh
# Somewhere else
PREFLIGHT_BIN=/usr/local/bin curl -fsSL https://jetonecloud.com/preflight | sh

# A specific version
PREFLIGHT_VERSION=v0.1.0 curl -fsSL https://jetonecloud.com/preflight | sh
```

If you'd rather read the script before running it, it's published as a
release asset — download `install.sh` from the
[Releases page](https://github.com/jetonecloud/preflight/releases) and run it
from disk. [`SECURITY.md`](../SECURITY.md#verifying-releases) has the full
verification steps, including checking the signed build provenance.

## pipx

```sh
pipx install preflight-cli
preflight --version
```

Needs Python 3.11 or newer. `pipx` keeps Preflight in its own environment, so
it can't disturb anything else you have installed.

Plain `pip install preflight-cli` works too, inside a virtualenv.

## uv

```sh
uv tool install preflight-cli
```

Or run it once without installing anything:

```sh
uvx --from preflight-cli preflight demo
```

## Homebrew

```sh
brew install jetonecloud/tap/preflight
```

## Docker

Useful when you'd rather not install anything, or when you want the scan to
run somewhere with no access to the rest of your machine. Mount your AWS
config read-only and a directory for the report to land in:

```sh
docker run --rm \
  -v "$HOME/.aws:/root/.aws:ro" \
  -v "$PWD:/out" \
  -e AWS_PROFILE \
  ghcr.io/jetonecloud/preflight:latest \
  scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole \
       --out /out --yes
```

For SSO profiles, make sure you've run `aws sso login` on the host first —
the container reads the cached token out of `~/.aws`.

## From source

```sh
git clone https://github.com/jetonecloud/preflight.git
cd preflight
uv sync
uv run preflight demo
```

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the development setup.

## No local install at all

If you'd rather not put anything on your laptop, run it from AWS CloudShell —
see [`cloudshell.md`](cloudshell.md).

## Checking it worked

```sh
preflight --version
preflight demo
```

`demo` renders a sample report from made-up data. It makes no AWS calls and
needs no credentials, so it's a safe way to confirm the install and to see
what a report looks like before pointing one at your account.

## Upgrading and removing

| Installed with | Upgrade | Remove |
|---|---|---|
| installer | re-run it | `rm ~/.local/bin/preflight` |
| pipx | `pipx upgrade preflight-cli` | `pipx uninstall preflight-cli` |
| uv | `uv tool upgrade preflight-cli` | `uv tool uninstall preflight-cli` |
| Homebrew | `brew upgrade preflight` | `brew uninstall preflight` |
| Docker | `docker pull ghcr.io/jetonecloud/preflight:latest` | `docker rmi ghcr.io/jetonecloud/preflight` |

Preflight keeps no state anywhere. Removing the binary removes the tool; the
only other thing it ever wrote is the reports you asked for, wherever you
asked for them.
