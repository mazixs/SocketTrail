# Разработка

[English](../development.md) | **Русский** · [К README](../../README.ru.md)

## Что нужно

- Rust stable 1.88 или новее (edition 2024).
- `dumpcap` с правами на захват, чтобы при проверке видеть домены и пакеты, см.
  [README](../../README.ru.md#linux).
- Для сборки под Windows на Linux: `gcc-mingw-w64-x86-64`, `binutils-mingw-w64-x86-64`,
  а для тестов Wine 10 или новее.

## Сборка и запуск

| Команда | Что делает |
|---|---|
| `./run.sh` | собирает релизный бинарь, если исходники новее, и запускает его |
| `make run` | то же самое |
| `make build` | `cargo build --release` |
| `make install` / `make uninstall` | ставит в `~/.local/bin` с ярлыком в меню или удаляет |
| `make check` | проверяет, работает ли захват пакетов без root |
| `make deb` | `target/debian/sockettrail_<версия>_amd64.deb` |
| `make win` | портативный `target/windows/SocketTrail-<версия>-windows-x64.zip` |

Аргументы после `./run.sh` передаются программе: `./run.sh --lang ru --port 8790`.

## Проверки

То же, что запускает CI:

```sh
cargo fmt --check
cargo clippy --all-targets
cargo clippy --all-targets --target x86_64-pc-windows-gnu
cargo test
packaging/smoke.sh target/release/sockettrail   # запускает бинарь и проверяет API
```

## Windows

Кросс-сборка идет через mingw-w64, а `.cargo/config.toml` назначает Wine запускающей
средой, поэтому тесты Windows-кода идут прямо на Linux:

```sh
cargo build --release --target x86_64-pc-windows-gnu
cargo test --target x86_64-pc-windows-gnu
packaging/smoke.sh wine target/x86_64-pc-windows-gnu/release/sockettrail.exe
make win
```

Wine 9 из репозиториев Ubuntu не отдает PID владельца в таблице сокетов: нужен
WineHQ 10 или новее. На настоящей Windows запускайте `cargo test -- --include-ignored`:
так добавляется тест живого DNS-запроса, который падает под Wine.

Релизный zip собирается на `windows-2025` под `x86_64-pc-windows-msvc` со статическим
CRT (`+crt-static`), поэтому exe не нужен Visual C++ runtime. Иконку, сведения о
версии и манифест встраивает `build.rs`.

## Пакеты

`make deb` собирает пакет с бинарем в `/usr/bin`, ярлыком в меню, иконкой и
выключенным пользовательским unit systemd. Он зависит от `wireshark-common`.
Минимальная версия glibc - та, что на машине сборки: релиз собирается на Ubuntu 24.04,
то есть glibc 2.39.

## CI и релизы

`.github/workflows/ci.yml` запускается на каждый push в `main` и на pull request: fmt и
clippy для обеих целей, тесты на Linux, под WineHQ и на Windows, Smoke тест каждой
сборки.

Релиз выпускается по тегу:

1. Поднимите `version` в `Cargo.toml`.
2. Превратите `## Unreleased` в `CHANGELOG.md` в `## vX.Y.Z - ГГГГ-ММ-ДД`.
3. Закоммитьте, сделайте push, затем `git tag vX.Y.Z && git push origin vX.Y.Z`.

`.github/workflows/release.yml` проверяет, что тег совпадает с `Cargo.toml`, собирает
`.deb` и zip, пишет `SHA256SUMS`, создает аттестации сборки и публикует релиз с
разделом CHANGELOG в описании.

## Переводы

Исходный язык - английский, русский - перевод.

- Rust: `t!("English", "Русский")` дает `String`, `text!` дает `Text`, который
  переводится при показе, `i18n::tr` работает с `&'static str`. Модуль `i18n` объявлен
  в `main.rs` первым, чтобы его макросы были видны везде.
- Интерфейс: английский остается в разметке `ui/index.html`, русский лежит в словаре
  `RU` в том же файле. Статичные элементы помечены `data-t`, динамический текст идет
  через `t('English {name}', {name})`, а множественное число - через `plural()`.

Новой строке нужны оба языка.

## Скриншоты

Картинки в `docs/images` сняты с настоящей сессии в 1600x900 с масштабом 2, в темной и
светлой теме, и сжаты `pngquant`. На них не должно быть личных данных: своего трафика,
хостов, IP-адресов и списка процессов.
