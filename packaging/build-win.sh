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

# Reject console-subsystem builds: the portable application must not open CMD.
"$PYTHON" - "target/$TARGET/release/sockettrail.exe" <<'PY_CHECK'
import pathlib
import struct
import sys

binary = pathlib.Path(sys.argv[1]).read_bytes()
pe = struct.unpack_from("<I", binary, 0x3C)[0]
if binary[pe:pe + 4] != b"PE\0\0":
    raise SystemExit("Not a Windows PE executable")
subsystem = struct.unpack_from("<H", binary, pe + 24 + 68)[0]
if subsystem != 2:  # IMAGE_SUBSYSTEM_WINDOWS_GUI
    raise SystemExit(f"Expected Windows GUI subsystem, got {subsystem}")
PY_CHECK

rm -rf "$OUT" && mkdir -p "$DIR"
cp "target/$TARGET/release/sockettrail.exe" "$DIR/"
cp packaging/README-windows.txt "$DIR/README.txt"
cp LICENSE "$DIR/LICENSE.txt"
(cd "$OUT" && "$PYTHON" -m zipfile -c "$(basename "$ZIP")" SocketTrail)
echo "$ZIP"
