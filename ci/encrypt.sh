#!/usr/bin/env bash
# Encrypts the IPAs in a directory for the owner: encrypt.sh <dir>. Each
# <name>.ipa becomes <name>.ipa.age (with its .sha256 kept next to it) and
# the plain IPA is removed: workflow artifacts of a public repository are
# readable by anyone (ADR 0010 of the server repository).
#
# Environment: PLUMA_AGE_RECIPIENT, an age public key (age1...).
set -euo pipefail
dir=${1:?usage: encrypt.sh dir}
if [[ ! "${PLUMA_AGE_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]; then
	echo "encrypt: PLUMA_AGE_RECIPIENT is not an age public key (README, Signing)" >&2
	exit 1
fi
shopt -s nullglob
ipas=("$dir"/*.ipa)
if [ ${#ipas[@]} = 0 ]; then
	echo "encrypt: no IPA in $dir" >&2
	exit 1
fi
for ipa in "${ipas[@]}"; do
	age --encrypt --recipient "$PLUMA_AGE_RECIPIENT" --output "$ipa.age" "$ipa"
	rm -f "$ipa"
	echo "encrypt: $ipa.age"
done
