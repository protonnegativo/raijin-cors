#!/usr/bin/env bash
# Tags and releases HEAD: the next version after the latest v* tag (v0.1.0 when there is none).
# Usage: .github/release.sh [patch|minor|major] [BEFORE-SHA]
# With BEFORE-SHA (a push), it skips when every changed file is one the binary does not depend on.
set -euo pipefail

bump=${1:-patch}
before=${2:-}

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*' | tr '\n' ' ')"
  exit 0
fi

if [ -n "$before" ] && [ "$before" != 0000000000000000000000000000000000000000 ] && git cat-file -e "$before^{commit}" 2>/dev/null; then
  binary=$(git diff --name-only "$before" HEAD | grep -vE '^(bench/fixtures/|docs/|\.github/)|\.md$' || true)
  if [ -z "$binary" ]; then
    echo "only docs, fixtures or CI changed: no release"
    exit 0
  fi
fi

latest=$(git tag --list 'v*' --sort=-version:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n1 || true)
if [ -z "$latest" ]; then
  tag=v0.1.0
else
  IFS=. read -r major minor patch <<<"${latest#v}"
  case "$bump" in
    major) tag="v$((major + 1)).0.0" ;;
    minor) tag="v$major.$((minor + 1)).0" ;;
    patch) tag="v$major.$minor.$((patch + 1))" ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git -c user.name=github-actions[bot] -c user.email=41898282+github-actions[bot]@users.noreply.github.com \
  tag -a "$tag" -m "$tag"
git push origin "$tag"
gh release create "$tag" --generate-notes --verify-tag
# Events made with GITHUB_TOKEN do not start other workflows, so start the binaries build by hand.
gh workflow run goreleaser.yml -f tag="$tag"
echo "released $tag"
