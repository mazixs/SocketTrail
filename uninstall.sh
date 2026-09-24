#!/usr/bin/env bash
# Removes what install.sh installed. Recorded dumps in ~/SocketTrail are left alone.
set -euo pipefail

# Inside a snap sandbox (e.g. the VS Code terminal) XDG_DATA_HOME points into the
# snap's own directory, where the shortcut never reaches the application menu.
# Fall back to the standard ~/.local/share then.
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
case "$DATA_HOME" in
  */snap/*) DATA_HOME="$HOME/.local/share" ;;
esac

BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
case "$BIN_DIR" in
  */snap/*) BIN_DIR="$HOME/.local/bin" ;;
esac
APP_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/scalable/apps"

rm -fv "$BIN_DIR/sockettrail" "$APP_DIR/sockettrail.desktop" "$APP_DIR"/sockettrail-*.desktop "$ICON_DIR/sockettrail.svg"
command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
echo "Removed. Dumps in ~/SocketTrail were kept."
