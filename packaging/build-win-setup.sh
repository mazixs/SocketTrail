#!/usr/bin/env bash
# Windows installer: target/windows/SocketTrail-<version>-windows-x64-setup.exe
# Packs the folder staged by packaging/build-win.sh, run that first (make win-setup does both).
# Needs Inno Setup 6: ISCC.exe on Windows or under Wine on Linux. ISCC=<path> overrides the lookup.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
SETUP=target/windows/SocketTrail-$VERSION-windows-x64-setup.exe

[ -f target/windows/SocketTrail/sockettrail.exe ] || {
  echo "target/windows/SocketTrail is missing, run packaging/build-win.sh first"
  exit 1
}

iscc=()
if [ -n "${ISCC:-}" ]; then
  iscc=("$ISCC")
elif command -v iscc >/dev/null 2>&1; then
  iscc=(iscc)
else
  local_programs=
  if [ -n "${LOCALAPPDATA:-}" ] && command -v cygpath >/dev/null 2>&1; then
    local_programs="$(cygpath -u "$LOCALAPPDATA")/Programs"
  fi
  for p in "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" \
           "/c/Program Files/Inno Setup 6/ISCC.exe" \
           "$local_programs/Inno Setup 6/ISCC.exe" \
           "$HOME/.wine/drive_c/Program Files (x86)/Inno Setup 6/ISCC.exe"; do
    [ -f "$p" ] || continue
    case "$p" in
      "$HOME/.wine/"*) iscc=(wine "$p") ;;
      *) iscc=("$p") ;;
    esac
    break
  done
fi
[ ${#iscc[@]} -gt 0 ] || { echo "Inno Setup 6 (ISCC.exe) not found, set ISCC=<path>"; exit 1; }

rm -f "$SETUP"
# Git Bash would turn ISCC options into paths, the dash form and the exclusion keep them intact.
MSYS2_ARG_CONV_EXCL='*' "${iscc[@]}" -Q "-DAppVersion=$VERSION" packaging/sockettrail.iss
[ -f "$SETUP" ] || { echo "ISCC finished without $SETUP"; exit 1; }
echo "$SETUP"
