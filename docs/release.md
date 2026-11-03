# Cutting a release

## What happens

Pushing a `v*` tag runs [`.github/workflows/release.yml`](../.github/workflows/release.yml):

1. **ci** — the whole of `ci.yml` (lint, shellcheck, tests on 3.11 through 3.14, the image build and its smoke test, the IAM policy check) runs again against the tagged commit. Nothing ships if it fails.
2. **version-check** — the tag must match `preflight.__version__`. `v0.2.0` with a package that still says `0.1.0` fails here rather than shipping a binary that misreports itself.
3. **build** — PyInstaller produces one self-contained binary per platform (linux x86_64/aarch64, macOS x86_64/arm64), each smoke-tested by actually generating a role template with it.
4. **publish** — collects the binaries, writes `checksums.txt`, attaches a signed build provenance attestation, and creates the GitHub Release with `install.sh` alongside the binaries.
5. **publish-pypi** — builds the sdist and wheel and publishes them with PyPI trusted publishing, so `pipx install preflight-cli` works from the same tag.
6. **publish-docker** — builds the image for `linux/amd64` and `linux/arm64` and pushes it to `ghcr.io/jetonecloud/preflight` as the full version, the minor series, and `latest`, with a provenance attestation pushed alongside it. A prerelease tag (`v0.3.0-rc1`) publishes itself and leaves `latest` alone.
7. **publish-homebrew** — renders `Formula/preflight.rb` from [`packaging/homebrew/preflight.rb.template`](../packaging/homebrew/preflight.rb.template) and commits it to the tap, so `brew install jetonecloud/tap/preflight` picks up the new version. Skipped unless the tap is configured (below). It waits for **publish**, because a formula is a URL plus a checksum and the assets have to exist first.

`workflow_dispatch` runs steps 1 and 3 only — a dry run that builds and smoke-tests the binaries without publishing anything.

## One-time setup

Three things live outside this repo. Until each is done, the matching job either skips or fails; everything else releases regardless.

**PyPI** — a trusted publisher for this repo and `release.yml`, and a `pypi` environment on the repo.

**GHCR** — nothing to configure: the job pushes with the workflow's own token. But the first push creates the package **private**, so pull it once after the first release and, if it 404s, make it public: the package page → *Package settings* → *Change visibility*. While you're there, *Manage Actions access* → add this repository, so later releases can push without the owner's involvement.

**The Homebrew tap** — a separate public repository called `jetonecloud/homebrew-tap` (the `homebrew-` prefix is what makes `jetonecloud/tap` resolve to it). It needs no contents of its own; the release workflow creates `Formula/preflight.rb` in it. Then, on *this* repo:

| Setting | Name | Value |
|---|---|---|
| Variable | `HOMEBREW_TAP` | `jetonecloud/homebrew-tap` |
| Secret | `HOMEBREW_TAP_TOKEN` | a token with `contents: write` on the tap |

A fine-grained PAT scoped to the tap repository alone is enough, and is the smallest thing that works — the workflow's own `GITHUB_TOKEN` can't write to another repository. The job is gated on the *variable* rather than the secret, because secrets can't be read in a job-level `if`: with `HOMEBREW_TAP` unset, the release skips the tap instead of failing on it.

To fix a tap by hand — after a retag, or if the push failed — render the formula locally and commit it yourself:

```sh
gh release download v0.2.0 --pattern checksums.txt
sh packaging/homebrew/render-formula.sh 0.2.0 checksums.txt
```

## Doing it

```sh
# 1. Bump the version in both places and land it on main.
#    src/preflight/__init__.py  ->  __version__ = "0.2.0"
#    pyproject.toml             ->  version = "0.2.0"
# 2. Move everything under CHANGELOG's [Unreleased] into a [0.2.0] section.
# 3. Tag it.
git tag v0.2.0
git push origin v0.2.0
```

Then check the release page: four binaries, `checksums.txt`, `install.sh`, and a provenance badge on each asset. Then the three places the same version has to show up:

```sh
pipx run preflight-cli --version
docker run --rm ghcr.io/jetonecloud/preflight:latest --version
brew install jetonecloud/tap/preflight && preflight --version
```

## Asset naming

Release assets deliberately carry **no version** in their filenames:

```
preflight-linux-x86_64
preflight-linux-aarch64
preflight-macos-x86_64
preflight-macos-arm64
checksums.txt
install.sh
```

That's what lets `install.sh` fetch `releases/latest/download/preflight-linux-x86_64` with no GitHub API call — no rate limits, no token, no JSON parsing in shell. Renaming these breaks every installed copy of the installer — and every Homebrew formula, which names each asset with its checksum — so treat them as a public interface. `tests/test_packaging.py` holds the formula to this list.

## The jetonecloud.com/preflight endpoint

`install.sh` lives here, in this repo, and is attached to each release. The website only forwards to it, so the two can never drift.

In the website repo (static HTML on Cloudflare Pages), add one line to `_redirects` in the published output directory:

```
/preflight  https://github.com/jetonecloud/preflight/releases/latest/download/install.sh  302
```

`curl -fsSL` follows the redirect, so `curl -fsSL https://jetonecloud.com/preflight | sh` keeps working for every future release with no further changes.

If you'd rather the script be served from our own origin — no visible redirect to github.com, and control over the content type and edge caching — use a Pages Function instead. `functions/preflight.js`:

```js
export async function onRequest() {
  const upstream =
    "https://github.com/jetonecloud/preflight/releases/latest/download/install.sh";
  const res = await fetch(upstream, { redirect: "follow" });
  if (!res.ok) return new Response("installer unavailable\n", { status: 502 });
  return new Response(res.body, {
    headers: {
      "content-type": "text/x-shellscript; charset=utf-8",
      "cache-control": "public, max-age=300",
    },
  });
}
```

Use one or the other, not both — a `_redirects` entry wins over a Function on the same path.

## Verifying a release by hand

```sh
sha256sum --check --ignore-missing checksums.txt
gh attestation verify preflight-linux-x86_64 --repo jetonecloud/preflight
```
