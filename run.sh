#!/usr/bin/env bash
# Runs from the repository: builds the release binary if it is missing or older than the sources.
set -euo pipefail
cd "$(dirname "$0")"

BIN=target/release/sockettrail
NEWEST_SRC=$(find src ui Cargo.toml -type f -newer "$BIN" -print -quit 2>/dev/null || true)

if [[ ! -x $BIN || -n ${NEWEST_SRC:-} ]]; then
  echo "Building..."
  cargo build --release
fi

exec "$BIN" "$@"
