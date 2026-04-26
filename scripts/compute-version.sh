#!/usr/bin/env bash
set -euo pipefail

version_file="${1:-VERSION}"

if [[ ! -f "$version_file" ]]; then
	echo "version file not found: $version_file" >&2
	exit 1
fi

raw_version="$(tr -d '[:space:]' < "$version_file")"
if [[ ! "$raw_version" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
	echo "invalid version in $version_file: $raw_version" >&2
	exit 1
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
base_patch="${BASH_REMATCH[3]}"
epoch_commit="$(git log -1 --format=%H -- "$version_file" 2>/dev/null || true)"
commits_since_epoch=0
if [[ -n "$epoch_commit" ]]; then
	commits_since_epoch="$(git rev-list --count "${epoch_commit}..HEAD")"
fi

patch="$((base_patch + commits_since_epoch))"

echo "base_version=v${major}.${minor}.${patch}"
echo "version_epoch_commit=${epoch_commit}"
echo "version_commits_since_epoch=${commits_since_epoch}"
