# Installing Preflight

Preflight is a single command-line tool. It runs on your machine, reads your
AWS account over the normal SDK credential chain, and prints the report in
your terminal (with a JSON export saved next to you). Pick whichever of these you'd trust.

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

That taps [`jetonecloud/homebrew-tap`](https://github.com/jetonecloud/homebrew-tap)
the first time and installs the same prebuilt binary the installer downloads,
checksum and all — no Python, no compiling. macOS and Linux, Intel and ARM.

## Docker

Useful when you'd rather not install anything, or when you want the scan to
run somewhere with no access to the rest of your machine. Mount your AWS
config read-only and a directory for the report to land in:

```sh
docker run --rm \
  -v "$HOME/.aws:/home/preflight/.aws:ro" \
  -v "$PWD:/out" \
  -e AWS_PROFILE \
  ghcr.io/jetonecloud/preflight:latest \
  scan --role-arn arn:aws:iam::123456789012:role/PreflightReadOnlyRole \
       --yes
```

`preflight` is the image's entrypoint, so everything after the image name is
the usual command line: `demo`, `scan --list-checks`, `--pdf`, any of it.

Nothing in the image runs as root. It runs as the `preflight` user, uid 1000,
whose home is `/home/preflight` — that's why the AWS config goes there rather
than in `/root`. The working directory is `/out`, which is where a report is
written by default, so `-v "$PWD:/out"` puts the files in the directory you
ran the command from, owned by you.

If your own uid isn't 1000, the bind mount may be unreadable or the output
directory unwritable. Run as yourself instead, and say where home is:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$HOME/.aws:/tmp/.aws:ro" \
  -v "$PWD:/out" \
  ghcr.io/jetonecloud/preflight:latest demo --pdf
```

For SSO profiles, make sure you've run `aws sso login` on the host first —
the container reads the cached token out of `~/.aws`.

Tags: `latest`, the full version (`0.1.0`), and the minor series (`0.1`).
Pin the full version if a reproducible scan matters. Each image carries a
build provenance attestation, the same as the binaries:

```sh
gh attestation verify oci://ghcr.io/jetonecloud/preflight:latest \
  --repo jetonecloud/preflight
```

The image is built for `linux/amd64` and `linux/arm64`, from the published
wheel rather than the standalone binary — in a container there's already a
Python to run it.

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

`demo` prints a sample report from made-up data. It makes no AWS calls and
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
only other thing it ever wrote is the JSON exports you asked for, wherever
you asked for them.
