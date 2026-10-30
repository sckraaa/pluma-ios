#!/usr/bin/env bash
# Builds the Telegram-iOS release upstream.env pins as Telegram publishes it,
# without the Pluma patch, for the simulator: the reference Pluma is compared
# with. The App Store app runs on devices only, and Telegram publishes no
# simulator build. It uses Telegram's own configuration from the checkout
# (build-system/appstore-configuration.json) and talks to Telegram's servers.
#
#   out/telegram-ios-<version>-<build>-simulator.zip, Telegram.app, with its
#   SHA-256.
#
# Like ci/build.sh sim, without code signing: Xcode-managed signing with no
# provisioning profiles. Make.py's build command has no option for the
# latter, and upstream's files stay as they are, so the flag goes into the
# user's bazelrc; run it on a CI runner, not on a machine of one's own.
# Environment: UPSTREAM_DIR (default ./upstream), PLUMA_BAZEL_DIR (default
# ~/pluma-bazel-reference), BUILD_NUMBER (default 1).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
root=$PWD
dir=$(cd "${UPSTREAM_DIR:-upstream}" && pwd)
cache=${PLUMA_BAZEL_DIR:-$HOME/pluma-bazel-reference}
build_number=${BUILD_NUMBER:-1}
if [ -z "${CI:-}" ]; then
	echo "build-reference: writes ~/.bazelrc; run it in CI" >&2
	exit 1
fi
if [ -f "$dir/build-system/pluma-configuration.json" ]; then
	echo "build-reference: $dir is patched; fetch it afresh (ci/fetch-upstream.sh full)" >&2
	exit 1
fi
configuration=$dir/build-system/appstore-configuration.json
if [ ! -f "$configuration" ]; then
	echo "build-reference: $configuration is missing; upstream changed" >&2
	exit 1
fi
mkdir -p "$cache/disk" "$cache/repo" out
cat >>"$HOME/.bazelrc" <<EOF
# Written by ci/build-reference.sh of pluma-ios.
common --repository_cache=$cache/repo
common --color=no --curses=no --show_progress_rate_limit=60
build --//Telegram:disableProvisioningProfiles
EOF
cd "$dir"
echo "build-reference: $PLUMA_SIM_CONFIGURATION, build $build_number"
python3 -u build-system/Make/Make.py \
	--bazelUserRoot="${PLUMA_BAZEL_USER_ROOT:-/private/var/tmp/_bazel_containerhost}" \
	--cacheDir="$cache/disk" \
	build \
	--configurationPath="$configuration" \
	--xcodeManagedCodesigning \
	--configuration="$PLUMA_SIM_CONFIGURATION" \
	--buildNumber="$build_number" \
	--continueOnError
shopt -s nullglob
ipas=(bazel-bin/Telegram/Telegram.ipa)
if [ ! -f "${ipas[0]}" ]; then
	ipas=(bazel-out/applebin_ios-ios_*-ST-*/bin/Telegram/Telegram.ipa)
fi
if [ ${#ipas[@]} != 1 ]; then
	echo "build-reference: expected one Telegram.ipa, found ${#ipas[@]}: ${ipas[*]}" >&2
	exit 1
fi
ipa="$dir/${ipas[0]}"
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ditto -x -k "$ipa" "$work"
app="$work/Payload/Telegram.app"
plist() {
	/usr/libexec/PlistBuddy -c "Print :$1" "$2"
}
id=$(plist CFBundleIdentifier "$app/Info.plist")
version=$(plist CFBundleShortVersionString "$app/Info.plist")
if [ "$version" != "$UPSTREAM_VERSION" ]; then
	echo "build-reference: the app is version $version, upstream.env says $UPSTREAM_VERSION" >&2
	exit 1
fi
name="telegram-ios-$version-$build_number-simulator"
ditto -c -k --keepParent "$app" "out/$name.zip"
(cd out && shasum -a 256 "$name.zip" >"$name.zip.sha256")
echo "build-reference: $id $version: out/$name.zip"
