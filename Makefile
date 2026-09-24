.PHONY: run build install uninstall deb win check clean

run: ## build if needed and run
	@./run.sh

build: ## build only
	cargo build --release

install: ## install into ~/.local/bin and add a menu shortcut
	@./install.sh

uninstall: ## remove the binary and the shortcut
	@./uninstall.sh

deb: ## build target/debian/sockettrail_<version>_amd64.deb
	@packaging/build-deb.sh

win: ## portable Windows zip: target/windows/SocketTrail-<version>-windows-x64.zip
	@packaging/build-win.sh

check: ## check packet capture rights
	@dumpcap -D >/dev/null 2>&1 && echo "packet capture works without root" || \
	  echo "no capture rights: sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark $$USER"

clean:
	cargo clean
