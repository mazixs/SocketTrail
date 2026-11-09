#!/usr/bin/env bash
# Installer smoke on Windows (Git Bash): silent per-user install into a temporary folder,
# the API smoke test of the installed exe, silent uninstall.
# Usage: packaging/setup-smoke.sh target/windows/SocketTrail-<version>-windows-x64-setup.exe
set -euo pipefail
SETUP=$(realpath "$1")
cd "$(dirname "$0")/.."
export MSYS2_ARG_CONV_EXCL='*'

# The test uninstalls what it installed: an existing installation would lose its registration.
KEY='Software\Microsoft\Windows\CurrentVersion\Uninstall\{98C6C04C-CD89-4B2A-B466-675B482351EE}_is1'
for root in HKCU HKLM; do
  if reg query "$root\\$KEY" >/dev/null 2>&1; then
    echo "SocketTrail is already installed ($root), uninstall it before this test"
    exit 1
  fi
done

DIR=$(mktemp -d)
LOG=$DIR.log
LNK="$(cygpath -u "$APPDATA")/Microsoft/Windows/Start Menu/Programs/SocketTrail.lnk"
fail() { echo "$1"; [ -f "$LOG" ] && tail -n 40 "$LOG"; exit 1; }

"$SETUP" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER \
  "/DIR=$(cygpath -w "$DIR")" "/LOG=$(cygpath -w "$LOG")" || fail "setup exited with $?"
for f in sockettrail.exe README.txt LICENSE.txt unins000.exe; do
  [ -f "$DIR/$f" ] || fail "not installed: $f"
done
[ -f "$LNK" ] || fail "no Start menu shortcut: $LNK"
reg query "HKCU\\$KEY" >/dev/null 2>&1 || fail "no uninstall entry"

packaging/smoke.sh "$DIR/sockettrail.exe"

# The uninstaller restarts itself from a temporary copy and returns at once, so wait for it.
"$DIR/unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
for _ in $(seq 1 60); do
  [ -e "$DIR/sockettrail.exe" ] || [ -e "$LNK" ] || break
  sleep 1
done
[ -e "$DIR/sockettrail.exe" ] && fail "uninstall left sockettrail.exe"
[ -e "$LNK" ] && fail "uninstall left the Start menu shortcut"
for _ in $(seq 1 10); do
  reg query "HKCU\\$KEY" >/dev/null 2>&1 || break
  sleep 1
done
reg query "HKCU\\$KEY" >/dev/null 2>&1 && fail "uninstall left the uninstall entry"
rm -rf "$DIR" "$LOG"
echo "setup smoke ok"
