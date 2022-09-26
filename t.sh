#!/usr/bin/env bash

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob

BATS_URL="https://github.com/bats-core/bats-core/archive/c0d2ca193ab8e5a671692a1f4390ff508792442a.tar.gz"

main() {
	if [ ! -d ".bats" ]; then
		mkdir ".bats"
		wget -q -O - "$BATS_URL" \
			| tar -C ".bats" --strip-components 1 -zxf -
	fi
	./.bats/bin/bats "$@" --print-output-on-failure t
}

main "$@"
