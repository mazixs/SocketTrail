#!/usr/bin/env bash
# Ярлыки SocketTrail: основной и скрытые псевдонимы для дока.
# Использование: packaging/desktop.sh <каталог applications> <команда запуска>
set -euo pipefail
APP_DIR=$1
EXEC=$2
mkdir -p "$APP_DIR"

cat > "$APP_DIR/sockettrail.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=SocketTrail
GenericName=Монитор сетевых соединений
Comment=Сетевые соединения по процессам, включая приложения под Proton
Exec=$EXEC
Icon=sockettrail
Terminal=false
Categories=Network;Monitor;
Keywords=network;traffic;capture;proton;wine;pcap;
StartupNotify=true
StartupWMClass=chrome-127.0.0.1__sockettrail-Default
DESKTOP

# Док сопоставляет окно с ярлыком по app_id (Wayland) или WM_CLASS (X11), а они
# зависят от браузера. Скрытые ярлыки-псевдонимы дают иконку SocketTrail для каждого.
for wm in chromium-127.0.0.1__sockettrail-Default msedge-127.0.0.1__sockettrail-Default \
          brave-127.0.0.1__sockettrail-Default vivaldi-127.0.0.1__sockettrail-Default SocketTrail; do
  cat > "$APP_DIR/sockettrail-$wm.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=SocketTrail
Exec=$EXEC
Icon=sockettrail
NoDisplay=true
StartupWMClass=$wm
DESKTOP
done
chmod 644 "$APP_DIR"/sockettrail*.desktop
