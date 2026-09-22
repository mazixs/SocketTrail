.PHONY: run build install uninstall deb win check clean

run: ## собрать при необходимости и запустить
	@./run.sh

build: ## только сборка
	cargo build --release

install: ## поставить в ~/.local/bin и добавить ярлык в меню
	@./install.sh

uninstall: ## убрать бинарь и ярлык
	@./uninstall.sh

deb: ## собрать пакет target/debian/sockettrail_<версия>_amd64.deb
	@packaging/build-deb.sh

win: ## портативный zip для Windows: target/windows/SocketTrail-<версия>-windows-x64.zip
	@packaging/build-win.sh

check: ## проверить права на захват
	@dumpcap -D >/dev/null 2>&1 && echo "захват доступен без root" || \
	  echo "прав на захват нет: sudo dpkg-reconfigure wireshark-common && sudo usermod -aG wireshark $$USER"

clean:
	cargo clean
