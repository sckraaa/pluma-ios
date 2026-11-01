#!/usr/bin/env bash
# Uploads the App Store IPA to App Store Connect, where it becomes a
# TestFlight build: testflight.sh <ipa>. The version and the build number
# are read from the IPA; App Store Connect accepts each build number of a
# version once, and the workflow's run number only grows.
#
# altool authenticates with the team's App Store Connect API key, which it
# looks up as AuthKey_<key ID>.p8 in $API_PRIVATE_KEYS_DIR (xcrun altool
# --help). The key is written to a private directory in $RUNNER_TEMP (or a
# temporary one) and removed on exit; it is never printed. Upstream uploads
# the IPA of the same build with altool too (build-system/Make/RemoteBuild.py).
#
# Environment (ci/preflight_sign.py --kind appstore checks them first):
#   PLUMA_ASC_KEY_ID      the ID of the API key;
#   PLUMA_ASC_ISSUER_ID   the issuer ID of the team's keys;
#   PLUMA_ASC_KEY_P8_B64  the key's .p8 file, base64;
#   PLUMA_ASC_APP_ID      the Apple ID of the app record (App Information).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./config/app.env
ipa=${1:?usage: testflight.sh <ipa>}
: "${PLUMA_ASC_KEY_ID:?PLUMA_ASC_KEY_ID is not set (README, TestFlight)}"
: "${PLUMA_ASC_ISSUER_ID:?PLUMA_ASC_ISSUER_ID is not set (README, TestFlight)}"
: "${PLUMA_ASC_KEY_P8_B64:?PLUMA_ASC_KEY_P8_B64 is not set (README, TestFlight)}"
: "${PLUMA_ASC_APP_ID:?PLUMA_ASC_APP_ID is not set (README, TestFlight)}"
if [[ ! "$PLUMA_ASC_KEY_ID" =~ ^[A-Z0-9]{10}$ ]]; then
	echo "testflight: PLUMA_ASC_KEY_ID is not an API key ID" >&2
	exit 1
fi

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pluma-testflight.XXXXXX")
trap 'rm -rf "$work"' EXIT
plist() {
	/usr/libexec/PlistBuddy -c "Print :$1" "$work/Info.plist"
}
unzip -p "$ipa" Payload/Telegram.app/Info.plist >"$work/Info.plist"
id=$(plist CFBundleIdentifier)
if [ "$id" != "$PLUMA_BUNDLE_ID" ]; then
	echo "testflight: the IPA is $id, not $PLUMA_BUNDLE_ID" >&2
	exit 1
fi
version=$(plist CFBundleShortVersionString)
build=$(plist CFBundleVersion)

(
	umask 077
	mkdir "$work/private_keys"
	tr -d '[:space:]' <<<"$PLUMA_ASC_KEY_P8_B64" | base64 -d >"$work/private_keys/AuthKey_$PLUMA_ASC_KEY_ID.p8"
)

echo "testflight: uploading $(basename "$ipa"), $id $version ($build), to the app $PLUMA_ASC_APP_ID"
API_PRIVATE_KEYS_DIR="$work/private_keys" xcrun altool --upload-package "$ipa" \
	--type ios \
	--apple-id "$PLUMA_ASC_APP_ID" \
	--bundle-id "$id" \
	--bundle-short-version-string "$version" \
	--bundle-version "$build" \
	--apiKey "$PLUMA_ASC_KEY_ID" \
	--apiIssuer "$PLUMA_ASC_ISSUER_ID"
echo "testflight: uploaded; the build shows in TestFlight once App Store Connect has processed it"
