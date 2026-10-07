#!/usr/bin/env bash
# Removes what install.sh installed, the window profile and the name cache.
# Recorded dumps in ~/SocketTrail are left alone.
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
CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
case "$CONFIG_HOME" in
  */snap/*) CONFIG_HOME="$HOME/.config" ;;
esac
# Same rule as paths::cache_dir in the program.
CACHE_HOME="${XDG_CACHE_HOME:-}"
case "$CACHE_HOME" in
  ""|*/snap/*) CACHE_HOME="$HOME/.cache" ;;
esac
APP_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/scalable/apps"
UNIT="$CONFIG_HOME/systemd/user/sockettrail.service"

if [[ -f $UNIT ]] && command -v systemctl >/dev/null; then
  systemctl --user disable --now sockettrail 2>/dev/null || true
fi
rm -fv "$BIN_DIR/sockettrail" "$APP_DIR/sockettrail.desktop" "$APP_DIR"/sockettrail-*.desktop \
  "$ICON_DIR/sockettrail.svg" "$UNIT"
rm -rf "$CACHE_HOME/sockettrail"
command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null || true
echo "Removed. Dumps in ~/SocketTrail were kept."
