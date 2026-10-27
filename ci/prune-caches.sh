#!/usr/bin/env bash
# Deletes the Bazel caches of main that a newer one of the same kind
# replaced: prune-caches.sh <key prefix>... Cache entries cannot be updated,
# so every build saves a new one; keeping only the newest of each kind keeps
# the simulator and the IPA caches side by side within the 10 GB of a
# repository instead of evicting each other.
#
# Environment: GH_TOKEN with actions: write, GITHUB_REPOSITORY.
set -euo pipefail
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
if [ $# = 0 ]; then
	echo "usage: prune-caches.sh <key prefix>..." >&2
	exit 2
fi
for prefix in "$@"; do
	ids=$(gh cache list --repo "$GITHUB_REPOSITORY" --ref refs/heads/main --key "$prefix" \
		--sort created_at --order desc --limit 100 --json id --jq '.[1:][].id')
	n=0
	for id in $ids; do
		gh cache delete --repo "$GITHUB_REPOSITORY" "$id"
		n=$((n + 1))
	done
	echo "prune-caches: $prefix: $n older entries deleted"
done
