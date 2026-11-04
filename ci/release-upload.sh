#!/usr/bin/env bash
# Records the ad hoc build as the current iPhone release with the server's
# releases service (task 054 and ADR 0035 of the server repository): the
# builds installed from the site are then offered the install page for an
# update. No file goes with it: the install service serves the IPA
# (install-upload.sh). release-upload.sh, after install-upload.sh.
#
# The version is UPSTREAM_VERSION, the build BUILD_NUMBER (the run number, as
# CFBundleVersion); the notes are release/notes.en.txt and
# release/notes.ru.txt.
#
# Environment:
#   PLUMA_RELEASES_URL      the site, https://pluma.chat;
#   RELEASES_UPLOAD_TOKEN   the releases service's upload token
#                           (teamgramd/deploy/releases/put-token.sh of the
#                           server repository sets it).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
build=${BUILD_NUMBER:?BUILD_NUMBER is not set}
: "${RELEASES_UPLOAD_TOKEN:?RELEASES_UPLOAD_TOKEN is not set (the release environment)}"
if [[ ! "${PLUMA_RELEASES_URL:-}" =~ ^https://[a-z0-9.-]+$ ]]; then
	echo "release-upload: PLUMA_RELEASES_URL is not the site's https:// address" >&2
	exit 1
fi
if [[ ! "$build" =~ ^[0-9]{1,9}$ ]]; then
	echo "release-upload: BUILD_NUMBER $build is not a number" >&2
	exit 1
fi
for f in release/notes.en.txt release/notes.ru.txt; do
	[ -s "$f" ] || { echo "release-upload: $f is missing or empty" >&2; exit 1; }
done

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pluma-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
# The token goes in a header file, not on the command line.
umask 077
printf 'Authorization: Bearer %s\n' "$RELEASES_UPLOAD_TOKEN" >"$work/auth"
status=$(curl -sS --retry 3 --retry-all-errors --max-time 120 -o "$work/answer" -w '%{http_code}' \
	-H @"$work/auth" \
	-F platform=ios -F "version=$UPSTREAM_VERSION" -F "build=$build" \
	-F "notes_en=<release/notes.en.txt" -F "notes_ru=<release/notes.ru.txt" \
	"$PLUMA_RELEASES_URL/dl/upload")
case $status in
200) echo "release-upload: Pluma $UPSTREAM_VERSION ($build) is the current iPhone release" ;;
409) echo "release-upload: build $build is recorded already" ;;
*)
	echo "release-upload: HTTP $status: $(head -c 500 "$work/answer")" >&2
	exit 1
	;;
esac
