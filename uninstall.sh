#!/usr/bin/env bash
# Удаление того, что поставил install.sh. Собранные дампы в ~/SocketTrail не трогаются.
set -euo pipefail

# XDG_DATA_HOME внутри snap-песочницы (терминал VS Code, например) указывает в
# каталог самого snap, откуда ярлык в меню приложений не попадет. В таком случае
# берем штатный ~/.local/share.
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

rm -fv "$BIN_DIR/sockettrail" "$APP_DIR/sockettrail.desktop" "$ICON_DIR/sockettrail.svg"
command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
echo "Удалено. Дампы в ~/SocketTrail остались на месте."
