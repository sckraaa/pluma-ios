#!/usr/bin/env bash
# Patches $UPSTREAM_DIR (default ./upstream) with ci/patch.py:
#   configure.sh dev     for the development server of config/dev, without a
#                        team (the simulator build); its HTTPS CDN takes plain
#                        HTTP to that server as well (the stand's fake CDN);
#   configure.sh server  for the server the repository variables name, signed
#                        by the team of PLUMA_TEAM_ID (the ad hoc IPA).
#
# Environment for server: SERVER_IPV4, SERVER_PORT, SERVER_IPV6 (optional),
# RSA_PUBLIC_KEY (PKCS#1 PEM), TEAM_ID, EDGE_WS_URLS (optional, the edges of
# task 109). A development build takes its edges from PLUMA_EDGE_WS_URLS
# (none in config/dev; set it to try a stand with an edge).
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?usage: configure.sh dev|server}
dir=${UPSTREAM_DIR:-upstream}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case $target in
dev)
	. config/dev/server.env
	SERVER_IPV4=$PLUMA_SERVER_IPV4
	SERVER_PORT=$PLUMA_SERVER_PORT
	SERVER_IPV6=
	TEAM_ID=$PLUMA_TEAM_ID
	DEV_CDN_HTTP=$PLUMA_SERVER_IPV4
	edge_urls=${PLUMA_EDGE_WS_URLS:-}
	cp config/dev/server_public.pem "$tmp/key.pem"
	;;
server)
	# Half a configuration would build a client that cannot sign in.
	for v in SERVER_IPV4 SERVER_PORT RSA_PUBLIC_KEY TEAM_ID; do
		if [ -z "${!v:-}" ]; then
			echo "configure: PLUMA_$v is not set (README, Configuration)" >&2
			exit 1
		fi
	done
	printf '%s\n' "$RSA_PUBLIC_KEY" >"$tmp/key.pem"
	edge_urls=${EDGE_WS_URLS:-}
	;;
*)
	echo "usage: configure.sh dev|server" >&2
	exit 2
	;;
esac

python3 -I ci/patch.py --source "$dir" --upstream upstream.env --app config/app.env \
	--server-ipv4 "$SERVER_IPV4" --server-port "$SERVER_PORT" --server-ipv6 "${SERVER_IPV6:-}" \
	--rsa-public-key "$tmp/key.pem" --team-id "$TEAM_ID" --dev-cdn-http "${DEV_CDN_HTTP:-}" \
	--edge-ws-urls "$edge_urls"
echo "configure: $target build"
