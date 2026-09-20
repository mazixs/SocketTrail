#!/usr/bin/env bash
# Запуск из репозитория: собирает релизный бинарь, если его нет или исходники новее.
set -euo pipefail
cd "$(dirname "$0")"

BIN=target/release/sockettrail
NEWEST_SRC=$(find src ui Cargo.toml -type f -newer "$BIN" -print -quit 2>/dev/null || true)

if [[ ! -x $BIN || -n ${NEWEST_SRC:-} ]]; then
  echo "Сборка..."
  cargo build --release
fi

exec "$BIN" "$@"
