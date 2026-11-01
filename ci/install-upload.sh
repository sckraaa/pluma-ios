#!/usr/bin/env bash
# Hands the signed ad hoc IPA to the server's install service, which
# re-signs it for every iPhone that installs Pluma from the site (server
# repository: app/ops/iosinstall, docs/ops/ios-install.md):
# install-upload.sh <ipa>. With the IPA go its version and build number and,
# for the app and each extension, the bundle ID and the entitlements it was
# signed with (codesign), which the service signs it with again.
#
# Environment:
#   PLUMA_INSTALL_URL         the site, https://pluma.chat;
#   IOSINSTALL_UPLOAD_TOKEN   the service's upload token (put-secrets.sh of
#                             the server repository sets it).
# Without the token there is no service yet: the step says so and passes.
set -euo pipefail
ipa=${1:?usage: install-upload.sh <ipa>}
if [ -z "${IOSINSTALL_UPLOAD_TOKEN:-}" ]; then
	echo "install-upload: no IOSINSTALL_UPLOAD_TOKEN, the install service is not set up; skipped"
	exit 0
fi
if [[ ! "${PLUMA_INSTALL_URL:-}" =~ ^https://[a-z0-9.-]+$ ]]; then
	echo "install-upload: PLUMA_INSTALL_URL is not the site's https:// address" >&2
	exit 1
fi

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pluma-install.XXXXXX")
trap 'rm -rf "$work"' EXIT
unzip -q "$ipa" -d "$work/unpacked"
apps=("$work"/unpacked/Payload/*.app)
if [ ${#apps[@]} != 1 ]; then
	echo "install-upload: expected one app in the IPA, found ${#apps[@]}" >&2
	exit 1
fi
app=${apps[0]}
plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Info.plist"; }
version=$(plist "$app" CFBundleShortVersionString)
number=$(plist "$app" CFBundleVersion)

# The bundles as JSON: path in the app ("" for the app), bundle ID, the
# entitlements' plist.
{
	echo "["
	sep=""
	for b in "$app" "$app"/PlugIns/*.appex; do
		[ -d "$b" ] || continue
		rel=${b#"$app"}
		rel=${rel#/}
		codesign -d --entitlements - --xml "$b" 2>/dev/null >"$work/ent.plist"
		python3 -I -c 'import json,sys; print(sys.argv[4] + json.dumps({"path": sys.argv[1], "bundle_id": sys.argv[2], "entitlements": open(sys.argv[3]).read()}))' \
			"$rel" "$(plist "$b" CFBundleIdentifier)" "$work/ent.plist" "$sep"
		sep=","
	done
	echo "]"
} >"$work/bundles.json"
python3 -I -c 'import json,sys; b=json.load(open(sys.argv[1])); assert all("<plist" in x["entitlements"] for x in b), "a bundle without entitlements"; print("install-upload: %d bundles" % len(b))' "$work/bundles.json"

# The token goes in a header file, not on the command line.
umask 077
printf 'Authorization: Bearer %s\n' "$IOSINSTALL_UPLOAD_TOKEN" >"$work/auth"
status=$(curl -sS --retry 3 --retry-all-errors --max-time 900 -o "$work/answer" -w '%{http_code}' \
	-H @"$work/auth" \
	-F "version=$version" -F "number=$number" -F "bundles=<$work/bundles.json" -F "ipa=@$ipa;type=application/octet-stream" \
	"$PLUMA_INSTALL_URL/ios/adhoc/upload")
if [ "$status" != 204 ]; then
	echo "install-upload: HTTP $status: $(head -c 500 "$work/answer")" >&2
	exit 1
fi
echo "install-upload: $version ($number) handed to $PLUMA_INSTALL_URL"
