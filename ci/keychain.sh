#!/usr/bin/env bash
# The keychain that holds the distribution identity during the IPA build:
#   keychain.sh create <identity.p12>  a new keychain in $RUNNER_TEMP (or
#                                      /tmp) with the identity, first in the
#                                      search list, where codesign finds it;
#   keychain.sh delete                 removes it again.
#
# Environment: PLUMA_DIST_P12_PASSWORD, the password of the .p12.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:?usage: keychain.sh create <identity.p12> | delete}
keychain="${RUNNER_TEMP:-/tmp}/pluma-signing.keychain-db"

case $mode in
create)
	p12=${2:?usage: keychain.sh create <identity.p12>}
	: "${PLUMA_DIST_P12_PASSWORD?PLUMA_DIST_P12_PASSWORD is not set}"
	password=$(openssl rand -hex 24)
	security delete-keychain "$keychain" 2>/dev/null || true
	security create-keychain -p "$password" "$keychain"
	security set-keychain-settings -lut 21600 "$keychain"
	security unlock-keychain -p "$password" "$keychain"
	security import "$p12" -k "$keychain" -f pkcs12 -P "$PLUMA_DIST_P12_PASSWORD" \
		-T /usr/bin/codesign -T /usr/bin/security >/dev/null
	# The intermediate that issues distribution certificates, as upstream's
	# ImportCertificates.py adds it; the runner image may have it already.
	wwdr="${UPSTREAM_DIR:-upstream}/build-system/AppleWWDRCAG3.cer"
	if [ -f "$wwdr" ]; then
		security import "$wwdr" -k "$keychain" >/dev/null 2>&1 || true
	fi
	security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
	# shellcheck disable=SC2046 # the search list is a list of paths
	security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
	identities=$(security find-identity -v -p codesigning "$keychain")
	echo "$identities"
	if ! grep -q '1 valid identities found' <<<"$identities"; then
		echo "keychain: expected one valid signing identity in the .p12" >&2
		exit 1
	fi
	;;
delete)
	security delete-keychain "$keychain" 2>/dev/null || true
	;;
*)
	echo "usage: keychain.sh create <identity.p12> | delete" >&2
	exit 2
	;;
esac
