#!/bin/sh
# Render the Homebrew formula for a release, on stdout.
#
#   render-formula.sh 0.2.0 checksums.txt > Formula/preflight.rb
#
# Takes the version (without the leading v) and the release's checksums.txt,
# fills in the template next to this script, and refuses to produce a
# formula that would 404 or fail its checksum: every platform named in the
# template has to have a checksum in the file.
#
# The release workflow runs this and commits the result to the tap. Run it
# by hand to repair a tap after a retag, or just to read what would be
# committed.

set -eu

here="$(dirname "$0")"
template="${PREFLIGHT_FORMULA_TEMPLATE:-$here/preflight.rb.template}"

fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

version="${1:-}"
sums="${2:-}"

[ -n "$version" ] && [ -n "$sums" ] || fail "usage: $0 <version> <checksums.txt>"
[ -f "$sums" ] || fail "no such file: $sums"
[ -f "$template" ] || fail "no such template: $template"

# A leading v is the tag, not the version. Accept either and strip it, so
# "$GITHUB_REF_NAME" can be passed straight through.
version="${version#v}"

# Homebrew compares versions, so a tag that isn't one would install and then
# never upgrade cleanly.
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "'$version' doesn't look like a version (want 1.2.3)" ;;
esac

sha_for() {
  # checksums.txt is `sha256sum` output: the digest, two spaces, the filename.
  found="$(awk -v want="$1" '$2 == want { print $1 }' "$sums")"
  [ -n "$found" ] || fail "$sums has no checksum for $1"
  case "$found" in
    *[!0-9a-f]* | "") fail "checksum for $1 isn't a hex digest: $found" ;;
  esac
  [ "${#found}" -eq 64 ] || fail "checksum for $1 isn't 64 characters: $found"
  printf '%s' "$found"
}

# Every checksum first, then the substitution. A `sha_for` inside the sed
# arguments would be a subshell: its `exit 1` would end the subshell, sed
# would be handed an empty digest, and a formula nobody could install would
# be printed with a zero exit status.
macos_arm64="$(sha_for preflight-macos-arm64)"
macos_x86_64="$(sha_for preflight-macos-x86_64)"
linux_aarch64="$(sha_for preflight-linux-aarch64)"
linux_x86_64="$(sha_for preflight-linux-x86_64)"

sed \
  -e "s|@VERSION@|$version|g" \
  -e "s|@SHA_MACOS_ARM64@|$macos_arm64|g" \
  -e "s|@SHA_MACOS_X86_64@|$macos_x86_64|g" \
  -e "s|@SHA_LINUX_AARCH64@|$linux_aarch64|g" \
  -e "s|@SHA_LINUX_X86_64@|$linux_x86_64|g" \
  "$template"
