#!/usr/bin/env bash
# Builds the .deb: target/debian/sockettrail_<version>_<arch>.deb
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
# user unit for background collection, disabled by default: systemctl --user enable --now sockettrail
install -d "$ROOT/usr/lib/systemd/user"
sed 's#%h/.local/bin/sockettrail#/usr/bin/sockettrail#' assets/sockettrail.service \
  > "$ROOT/usr/lib/systemd/user/sockettrail.service"
install -Dm644 README.md "$ROOT/usr/share/doc/sockettrail/README.md"
install -Dm644 README.ru.md "$ROOT/usr/share/doc/sockettrail/README.ru.md"
install -Dm644 LICENSE "$ROOT/usr/share/doc/sockettrail/copyright"
gzip -9nc CHANGELOG.md > "$ROOT/usr/share/doc/sockettrail/changelog.gz"

# dpkg-shlibdeps computes the system library dependencies and needs debian/control.
TMP=$(mktemp -d -p "$OUT")
mkdir -p "$TMP/debian" && touch "$TMP/debian/control"
DEPS=$(cd "$TMP" && dpkg-shlibdeps -O -e "$OLDPWD/$ROOT/usr/bin/sockettrail" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
rm -rf "$TMP"

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
MAINT="mazixs <mazixs@users.noreply.github.com>"
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
Description: network connection monitor tied to processes
 Shows the domain, IP, port, protocol, network owner and traffic volume for
 every connection of a process, including applications under Proton and Wine.
 Keeps a connection history and records the traffic of the selected process
 into .pcapng.
 .
 Domains and short connections require dumpcap with capture rights:
 sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark \$USER
CONTROL

fakeroot dpkg-deb --build --root-owner-group -Zxz "$ROOT" "$OUT/" >/dev/null
echo "$OUT/sockettrail_${VERSION}_$ARCH.deb"
