#!/usr/bin/env bash
# Сборка .deb: target/debian/sockettrail_<версия>_<арх>.deb
set -euo pipefail
cd "$(dirname "$0")/.."
umask 022

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ARCH=$(dpkg --print-architecture)
OUT=target/debian
ROOT=$OUT/sockettrail_${VERSION}_$ARCH
rm -rf "$ROOT"

cargo build --release

install -Dm755 target/release/sockettrail "$ROOT/usr/bin/sockettrail"
strip "$ROOT/usr/bin/sockettrail"
install -Dm644 assets/sockettrail.svg "$ROOT/usr/share/icons/hicolor/scalable/apps/sockettrail.svg"
packaging/desktop.sh "$ROOT/usr/share/applications" sockettrail
# user-юнит для фонового сбора, по умолчанию выключен: systemctl --user enable --now sockettrail
install -d "$ROOT/usr/lib/systemd/user"
sed 's#%h/.local/bin/sockettrail#/usr/bin/sockettrail#' assets/sockettrail.service \
  > "$ROOT/usr/lib/systemd/user/sockettrail.service"
install -Dm644 README.md "$ROOT/usr/share/doc/sockettrail/README.md"
install -Dm644 LICENSE "$ROOT/usr/share/doc/sockettrail/copyright"
gzip -9nc CHANGELOG.md > "$ROOT/usr/share/doc/sockettrail/changelog.gz"

# Зависимости от системных библиотек считает dpkg-shlibdeps, ему нужен debian/control.
TMP=$(mktemp -d -p "$OUT")
mkdir -p "$TMP/debian" && touch "$TMP/debian/control"
DEPS=$(cd "$TMP" && dpkg-shlibdeps -O -e "$OLDPWD/$ROOT/usr/bin/sockettrail" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
rm -rf "$TMP"

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
MAINT="$(git config user.name 2>/dev/null || echo mazixs) <$(git config user.email 2>/dev/null || echo mazixs@users.noreply.github.com)>"
install -d "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: sockettrail
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINT
Installed-Size: $SIZE
Depends: $DEPS
Recommends: wireshark-common, google-chrome-stable | chromium | chromium-browser | microsoft-edge-stable | brave-browser
Section: net
Priority: optional
Homepage: https://github.com/mazixs/SocketTrail
Description: монитор сетевых соединений с привязкой к процессу
 Показывает домен, IP, порт, протокол, владельца сети и объем трафика по
 каждому соединению процесса, в том числе приложений под Proton и Wine.
 Ведет историю соединений и пишет трафик выбранного процесса в .pcapng.
 .
 Для доменов и коротких соединений нужен dumpcap с правами на захват:
 sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark \$USER
CONTROL

fakeroot dpkg-deb --build --root-owner-group -Zxz "$ROOT" "$OUT/" >/dev/null
echo "$OUT/sockettrail_${VERSION}_$ARCH.deb"
