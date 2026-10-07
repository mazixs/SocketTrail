#!/usr/bin/env bash
# Installs into the home directory: binary into ~/.local/bin, shortcut into the
# application menu. No root required.
set -euo pipefail
cd "$(dirname "$0")"

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
APP_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/scalable/apps"
UNIT_DIR="$CONFIG_HOME/systemd/user"

echo "== Build"
cargo build --release

echo "== Install"
mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"
install -m 755 target/release/sockettrail "$BIN_DIR/sockettrail"
install -m 644 assets/sockettrail.svg "$ICON_DIR/sockettrail.svg"

packaging/desktop.sh "$APP_DIR" "$BIN_DIR/sockettrail"

# Background collection unit, disabled as in the .deb. systemd has no specifier for
# XDG_BIN_HOME, so the copy gets the real path; systemd rejects " and \ in it.
if [[ $BIN_DIR == *[\"\\]* ]]; then
  UNIT_NOTE="not installed: systemd does not accept \" or \\ in $BIN_DIR"
else
  mkdir -p "$UNIT_DIR"
  unit=$(<assets/sockettrail.service)
  printf '%s\n' "${unit//'%h/.local/bin/sockettrail'/"\"${BIN_DIR//%/%%}/sockettrail\""}" \
    > "$UNIT_DIR/sockettrail.service"
  command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null || true
  UNIT_NOTE="$UNIT_DIR/sockettrail.service (off: systemctl --user enable --now sockettrail)"
fi

command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
# No icon cache in the home directory: without it GTK scans the directory itself,
# while a stale cache hides icons added later and keeps removed ones.

echo "   binary:    $BIN_DIR/sockettrail"
echo "   shortcut:  $APP_DIR/sockettrail.desktop"
echo "   service:   $UNIT_NOTE"

echo
echo "== Environment check"
ok=1

if ! command -v dumpcap >/dev/null; then
  echo "  [no]  dumpcap is not installed"
  echo "        sudo apt install wireshark-common"
  ok=0
elif dumpcap -D >/dev/null 2>&1; then
  echo "  [ok]  packet capture works without root"
else
  echo "  [no]  dumpcap is installed, but has no capture rights"
  echo "        sudo dpkg-reconfigure wireshark-common   # answer \"yes\""
  echo "        sudo usermod -aG wireshark \"$USER\"       # then log out and back in"
  ok=0
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) echo "  [ok]  $BIN_DIR is in PATH" ;;
  *) echo "  [no]  $BIN_DIR is not in PATH"
     echo "        echo 'export PATH=\"\$PATH:$BIN_DIR\"' >> ~/.bashrc && source ~/.bashrc"
     ok=0 ;;
esac

echo
if [[ $ok -eq 1 ]]; then
  echo "Done. Run: sockettrail, or SocketTrail in the application menu."
else
  echo "Installed, but some checks failed - see the hints above."
  echo "Without capture rights the tool works, but shows no domains and no short connections."
fi
