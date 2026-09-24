#!/usr/bin/env bash
# SocketTrail shortcuts: the main one and hidden aliases for the dock.
# Usage: packaging/desktop.sh <applications dir> <launch command>
set -euo pipefail
APP_DIR=$1
EXEC=$2
mkdir -p "$APP_DIR"

cat > "$APP_DIR/sockettrail.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=SocketTrail
GenericName=Network Connection Monitor
GenericName[ru]=Монитор сетевых соединений
Comment=Network connections by process, including applications under Proton
Comment[ru]=Сетевые соединения по процессам, включая приложения под Proton
Exec=$EXEC
Icon=sockettrail
Terminal=false
Categories=Network;Monitor;
Keywords=network;traffic;capture;proton;wine;pcap;
StartupNotify=true
StartupWMClass=chrome-127.0.0.1__sockettrail-Default
DESKTOP

# The dock matches a window to a shortcut by app_id (Wayland) or WM_CLASS (X11),
# which depend on the browser. Hidden alias shortcuts give each one the SocketTrail icon.
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
