#!/usr/bin/env bash
# Fetches the upstream commit upstream.env pins: one commit, no history.
#   fetch-upstream.sh sparse  into ./upstream, only the files ci/patch.py
#                             reads and checks (ci/patch.py --paths): seconds,
#                             for the check job and the tests;
#   fetch-upstream.sh full    into $UPSTREAM_DIR (default ./upstream) with
#                             every submodule, for a build.
# The CI builds in /Users/Shared/telegram-ios, as upstream's own CI does: the
# source path ends up in the compiler command lines, so a stable one keeps
# the Bazel cache valid between runs.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
mode=${1:?usage: fetch-upstream.sh sparse|full}

# GNU timeout where there is one (Linux; macOS only with coreutils).
with_timeout() {
	local limit=$1
	shift
	if command -v timeout >/dev/null; then
		timeout "$limit" "$@"
	elif command -v gtimeout >/dev/null; then
		gtimeout "$limit" "$@"
	else
		"$@"
	fi
}

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "fetch-upstream: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

case $mode in
sparse)
	dir=upstream
	;;
full)
	dir=${UPSTREAM_DIR:-upstream}
	;;
*)
	echo "usage: fetch-upstream.sh sparse|full" >&2
	exit 2
	;;
esac

rm -rf "$dir"
git init -q "$dir"
git -C "$dir" remote add origin "$UPSTREAM_REPO"
fetch=(fetch -q --depth 1)
if [ "$mode" = sparse ]; then
	# Only the blobs of these paths are downloaded, at checkout.
	git -C "$dir" config core.sparseCheckout true
	python3 -I ci/patch.py --paths | sed 's|^|/|' >"$dir/.git/info/sparse-checkout"
	fetch+=(--filter=blob:none)
fi
retry with_timeout 10m git -C "$dir" "${fetch[@]}" origin "$UPSTREAM_REF"
retry with_timeout 10m git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C "$dir" rev-parse HEAD)" = "$UPSTREAM_REF"
if [ "$mode" = full ]; then
	retry with_timeout 30m git -C "$dir" submodule update -q --init --recursive --depth 1 --jobs 4
fi
echo "fetch-upstream: $UPSTREAM_TAG ($UPSTREAM_REF), $mode, in $dir"
