#!/usr/bin/env bash
# Builds the patched $UPSTREAM_DIR (default ./upstream) with Telegram-iOS's
# Make.py into ./out:
#   build.sh sim  the simulator app, in the Make.py configuration
#                 PLUMA_SIM_CONFIGURATION of config/app.env, without code
#                 signing (Xcode-managed signing with no profiles is what
#                 Make.py offers for that; the app is signed ad hoc):
#                 out/pluma-ios-<version>-<build>-simulator.zip, Pluma.app;
#   build.sh ipa  the ad hoc IPA (release_arm64), signed inside the build with
#                 the profiles in $PLUMA_CODESIGNING_DIR/profiles and the
#                 identity in the keychain (ci/keychain.sh):
#                 out/pluma-ios-<version>-<build>.ipa.
# Each file comes with its SHA-256.
#
# The Bazel disk and repository caches live in $PLUMA_BAZEL_DIR (default
# ~/pluma-bazel); the workflow keeps it in the GitHub Actions cache.
# Environment: BUILD_NUMBER (default 1).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
target=${1:?usage: build.sh sim|ipa}
root=$PWD
dir=$(cd "${UPSTREAM_DIR:-upstream}" && pwd)
cache=${PLUMA_BAZEL_DIR:-$HOME/pluma-bazel}
build_number=${BUILD_NUMBER:-1}
mkdir -p "$cache/disk" "$cache/repo" out

if [ ! -f "$dir/build-system/pluma-configuration.json" ]; then
	echo "build: $dir is not patched (ci/configure.sh)" >&2
	exit 1
fi

# The flags Make.py has no option for; the patch makes the upstream
# .bazelrc import this file.
{
	echo "# Written by ci/build.sh of pluma-ios."
	echo "common --repository_cache=$cache/repo"
	if [ -n "${CI:-}" ]; then
		echo "common --color=no --curses=no --show_progress_rate_limit=60"
	fi
	if [ "$target" = sim ]; then
		# No provisioning profile for any target: the simulator needs none.
		echo "build --//Telegram:disableProvisioningProfiles"
	fi
} >"$dir/pluma.bazelrc"

case $target in
sim)
	configuration=$PLUMA_SIM_CONFIGURATION
	signing=(--xcodeManagedCodesigning)
	;;
ipa)
	configuration=release_arm64
	: "${PLUMA_CODESIGNING_DIR:?PLUMA_CODESIGNING_DIR is not set (ci/preflight_sign.py --out-dir)}"
	signing=(--codesigningInformationPath="$PLUMA_CODESIGNING_DIR")
	;;
*)
	echo "usage: build.sh sim|ipa" >&2
	exit 2
	;;
esac

cd "$dir"
echo "build: $target, $configuration, build $build_number"
# The canonical Bazel output root of upstream's CI: with the stable source
# path it keeps the cache entries valid from run to run.
python3 -u build-system/Make/Make.py \
	--bazelUserRoot="${PLUMA_BAZEL_USER_ROOT:-/private/var/tmp/_bazel_containerhost}" \
	--cacheDir="$cache/disk" \
	build \
	--configurationPath=build-system/pluma-configuration.json \
	"${signing[@]}" \
	--configuration="$configuration" \
	--buildNumber="$build_number" \
	--continueOnError

# rules_apple writes the bundle as an IPA, under the configuration of the
# app's platform.
shopt -s nullglob
ipas=(bazel-bin/Telegram/Telegram.ipa)
if [ ! -f "${ipas[0]}" ]; then
	ipas=(bazel-out/applebin_ios-ios_*-ST-*/bin/Telegram/Telegram.ipa)
fi
if [ ${#ipas[@]} != 1 ]; then
	echo "build: expected one Telegram.ipa, found ${#ipas[@]}: ${ipas[*]}" >&2
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
if [ "$id" != "$PLUMA_BUNDLE_ID" ]; then
	echo "build: the app is $id, not $PLUMA_BUNDLE_ID" >&2
	exit 1
fi
version=$(plist CFBundleShortVersionString "$app/Info.plist")
if [ "$version" != "$UPSTREAM_VERSION" ]; then
	echo "build: the app is version $version, upstream.env says $UPSTREAM_VERSION" >&2
	exit 1
fi
for appex in "$app"/PlugIns/*.appex; do
	echo "build: extension $(plist CFBundleIdentifier "$appex/Info.plist")"
done

case $target in
sim)
	name="pluma-ios-$version-$build_number-simulator"
	mv "$app" "$work/Pluma.app"
	ditto -c -k --keepParent "$work/Pluma.app" "out/$name.zip"
	file=$name.zip
	;;
ipa)
	# Every bundle carries its profile and a valid signature.
	for bundle in "$app" "$app"/PlugIns/*.appex; do
		if [ ! -f "$bundle/embedded.mobileprovision" ]; then
			echo "build: $(basename "$bundle") has no provisioning profile" >&2
			exit 1
		fi
	done
	codesign --verify --deep --strict "$app"
	codesign -dvv "$app" 2>&1 | grep -E '^(Authority|TeamIdentifier)=' | head -n 2
	name="pluma-ios-$version-$build_number"
	cp "$ipa" "out/$name.ipa"
	file=$name.ipa
	;;
esac
(cd out && shasum -a 256 "$file" >"$file.sha256")
echo "build: out/$file ($(du -h "out/$file" | awk '{print $1}'))"
echo "file=$file" >>"${GITHUB_OUTPUT:-/dev/null}"
