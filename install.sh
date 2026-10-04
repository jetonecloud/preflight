#!/bin/sh
# Install Preflight, the read-only AWS audit CLI.
#
#   curl -fsSL https://jetonecloud.com/preflight | sh
#
# Downloads the binary for your platform from GitHub Releases, checks it
# against the published SHA-256, and puts it on your PATH. Nothing is sent
# anywhere; nothing runs as root.
#
# Knobs:
#   PREFLIGHT_VERSION=0.1.0   install a specific release instead of the latest
#   PREFLIGHT_BIN=/usr/local/bin   install somewhere other than ~/.local/bin
#
# Read it before you run it — that's the whole point of piping it to less
# first:  curl -fsSL https://jetonecloud.com/preflight | less

set -eu

REPO="jetonecloud/preflight"
RELEASES="https://github.com/$REPO/releases"
DEST="${PREFLIGHT_BIN:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- which binary do we want ------------------------------------------------

platform="$(uname -s)-$(uname -m)"
case "$platform" in
  Linux-x86_64 | Linux-amd64) asset="preflight-linux-x86_64" ;;
  Linux-aarch64 | Linux-arm64) asset="preflight-linux-aarch64" ;;
  Darwin-arm64) asset="preflight-macos-arm64" ;;
  Darwin-x86_64) asset="preflight-macos-x86_64" ;;
  *)
    fail "no prebuilt binary for $platform.
  Install from PyPI instead:  pipx install preflight-cli
  Or from source:             https://github.com/$REPO"
    ;;
esac

if [ -n "${PREFLIGHT_VERSION:-}" ]; then
  base="$RELEASES/download/v${PREFLIGHT_VERSION#v}"
else
  base="$RELEASES/latest/download"
fi

command -v curl > /dev/null 2>&1 || fail "curl is required."

# --- download ---------------------------------------------------------------

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset..."
curl -fsSL "$base/$asset" -o "$tmp/preflight" \
  || fail "couldn't download $base/$asset
  If this is a brand-new release, the assets may still be uploading."
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" \
  || fail "couldn't download the checksums from $base/checksums.txt"

# --- verify -----------------------------------------------------------------

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    fail "need sha256sum or shasum to verify the download, and found neither."
  fi
}

expected="$(awk -v want="$asset" '$2 == want || $2 == "*" want { print $1 }' "$tmp/checksums.txt")"
[ -n "$expected" ] || fail "$asset isn't listed in checksums.txt."

actual="$(sha256_of "$tmp/preflight")"
if [ "$expected" != "$actual" ]; then
  fail "checksum mismatch for $asset — refusing to install.
  expected $expected
  got      $actual"
fi
say "Checksum OK."

# --- install ----------------------------------------------------------------

mkdir -p "$DEST" || fail "couldn't create $DEST."
chmod +x "$tmp/preflight"
mv "$tmp/preflight" "$DEST/preflight" \
  || fail "couldn't write $DEST/preflight. Set PREFLIGHT_BIN to a directory you own."

installed="$("$DEST/preflight" --version 2> /dev/null || true)"
say "Installed ${installed:-preflight} to $DEST/preflight"

case ":$PATH:" in
  *":$DEST:"*) say "Run it:  preflight scan" ;;
  *)
    say ""
    say "$DEST isn't on your PATH. Add it:"
    say "  echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.profile && . ~/.profile"
    say ""
    say "Or run it directly:  $DEST/preflight scan"
    ;;
esac
