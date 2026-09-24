#!/usr/bin/env bash
# Portable build: target/windows/SocketTrail-<version>-windows-x64.zip
# Locally with mingw (x86_64-pc-windows-gnu), in CI on Windows with TARGET=x86_64-pc-windows-msvc.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARGET=${TARGET:-x86_64-pc-windows-gnu}
PYTHON=${PYTHON:-python3}
OUT=target/windows
DIR=$OUT/SocketTrail
ZIP=$OUT/SocketTrail-$VERSION-windows-x64.zip

cargo build --release --target "$TARGET"

rm -rf "$OUT" && mkdir -p "$DIR"
cp "target/$TARGET/release/sockettrail.exe" "$DIR/"
cp packaging/README-windows.txt "$DIR/README.txt"
cp LICENSE "$DIR/LICENSE.txt"
(cd "$OUT" && "$PYTHON" -m zipfile -c "$(basename "$ZIP")" SocketTrail)
echo "$ZIP"
