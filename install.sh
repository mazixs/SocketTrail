#!/usr/bin/env bash
# Установка в домашний каталог: бинарь в ~/.local/bin, ярлык в меню приложений.
# Права root не требуются.
set -euo pipefail
cd "$(dirname "$0")"

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

echo "== Сборка"
cargo build --release

echo "== Установка"
mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"
install -m 755 target/release/sockettrail "$BIN_DIR/sockettrail"
install -m 644 assets/sockettrail.svg "$ICON_DIR/sockettrail.svg"

packaging/desktop.sh "$APP_DIR" "$BIN_DIR/sockettrail"

command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
# Кеш иконок в домашнем каталоге не создаем: без него GTK сканирует каталог сам,
# а устаревший кеш прячет иконки, добавленные позже, и держит удаленные.

echo "   бинарь:  $BIN_DIR/sockettrail"
echo "   ярлык:   $APP_DIR/sockettrail.desktop"

echo
echo "== Проверка окружения"
ok=1

if ! command -v dumpcap >/dev/null; then
  echo "  [нет] dumpcap не установлен"
  echo "        sudo apt install wireshark-common"
  ok=0
elif dumpcap -D >/dev/null 2>&1; then
  echo "  [ок]  захват пакетов доступен без root"
else
  echo "  [нет] dumpcap есть, но прав на захват нет"
  echo "        sudo dpkg-reconfigure wireshark-common   # ответить \"да\""
  echo "        sudo usermod -aG wireshark \"$USER\"       # затем перелогиниться"
  ok=0
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) echo "  [ок]  $BIN_DIR есть в PATH" ;;
  *) echo "  [нет] $BIN_DIR не в PATH"
     echo "        echo 'export PATH=\"\$PATH:$BIN_DIR\"' >> ~/.bashrc && source ~/.bashrc"
     ok=0 ;;
esac

echo
if [[ $ok -eq 1 ]]; then
  echo "Готово. Запуск: sockettrail, либо SocketTrail в меню приложений."
else
  echo "Установлено, но часть проверок не прошла - см. подсказки выше."
  echo "Без прав на захват утилита работает, но доменов и коротких соединений не покажет."
fi
