#!/usr/bin/env bash
# Prepares a macOS runner:
#   setup.sh build  selects the Xcode of upstream.env (Make.py refuses any
#                   other), makes room on the disk (PLUMA_MIN_FREE_GB, default
#                   60) and installs the Metal toolchain, which Xcode 26
#                   downloads separately;
#   setup.sh age    the age tool, to encrypt the IPA for the owner.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
mode=${1:?usage: setup.sh build|age}

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "setup: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

free_gb() {
	df -g "$HOME" | awk 'NR == 2 {print $4}'
}

case $mode in
build)
	xcode="/Applications/Xcode_$XCODE_VERSION.app"
	if [ ! -d "$xcode" ]; then
		echo "setup: no $xcode on this runner image (README, Updating the upstream)" >&2
		ls -d /Applications/Xcode*.app >&2 || true
		exit 1
	fi
	sudo xcode-select -s "$xcode/Contents/Developer"
	version=$(xcodebuild -version | awk '/^Xcode / {print $2}')
	if [ "$version" != "$XCODE_VERSION" ]; then
		echo "setup: $xcode is Xcode $version, upstream.env says $XCODE_VERSION" >&2
		exit 1
	fi
	echo "setup: Xcode $version ($(xcodebuild -version | awk '/^Build version/ {print $3}')), iOS SDK $(xcrun --sdk iphoneos --show-sdk-version)"

	# A cold build fills tens of GB (the Bazel output base, the sources with
	# their submodules, the disk cache). The other Xcode versions of the
	# image go first, then the simulator runtimes; neither is used.
	need=${PLUMA_MIN_FREE_GB:-60}
	echo "setup: $(free_gb) GB free, $need needed"
	if [ "$(free_gb)" -lt "$need" ]; then
		keep=$(cd "$xcode" && pwd -P)
		for x in /Applications/Xcode*.app; do
			if [ ! -L "$x" ] && [ "$(cd "$x" && pwd -P)" != "$keep" ]; then
				sudo rm -rf "$x" &
			fi
		done
		wait
		echo "setup: $(free_gb) GB free without the other Xcode versions"
	fi
	if [ "$(free_gb)" -lt "$need" ]; then
		xcrun simctl runtime delete all >/dev/null 2>&1 || true
		echo "setup: $(free_gb) GB free without the simulator runtimes"
	fi
	if [ "$(free_gb)" -lt "$need" ]; then
		echo "setup: only $(free_gb) GB free, $need needed" >&2
		df -h "$HOME" >&2
		exit 1
	fi

	if ! xcrun metal --version >/dev/null 2>&1; then
		retry xcodebuild -downloadComponent MetalToolchain
	fi
	echo "setup: $(xcrun metal --version | head -n 1)"
	;;
age)
	if ! command -v age >/dev/null; then
		HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 retry brew install --quiet age
	fi
	echo "setup: age $(age --version)"
	;;
*)
	echo "usage: setup.sh build|age" >&2
	exit 2
	;;
esac
