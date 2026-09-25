# Development

**English** | [Русский](ru/development.md) · [Back to README](../README.md)

## Requirements

- Rust stable 1.89 or newer (edition 2024).
- `dumpcap` with capture rights to see domains and packets while testing, see the
  [README](../README.md#linux).
- For the Windows build on Linux: `gcc-mingw-w64-x86-64`, `binutils-mingw-w64-x86-64`
  and, for tests, Wine 10 or newer.

## Build and run

| Command | What it does |
|---|---|
| `./run.sh` | builds the release binary if the sources are newer, then runs it |
| `make run` | the same |
| `make build` | `cargo build --release` |
| `make install` / `make uninstall` | install into `~/.local/bin` with a menu shortcut, or remove |
| `make check` | tells whether packet capture works without root |
| `make deb` | `target/debian/sockettrail_<version>_amd64.deb` |
| `make win` | portable `target/windows/SocketTrail-<version>-windows-x64.zip` |

Arguments after `./run.sh` go to the program: `./run.sh --lang ru --port 8790`.

## Checks

The same as CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets
cargo clippy --all-targets --target x86_64-pc-windows-gnu
cargo test
packaging/smoke.sh target/release/sockettrail   # starts the binary and checks the API
```

## Windows

Cross-compiling uses mingw-w64, and `.cargo/config.toml` sets Wine as the runner, so
tests of the Windows code run on Linux:

```sh
cargo build --release --target x86_64-pc-windows-gnu
cargo test --target x86_64-pc-windows-gnu
packaging/smoke.sh wine target/x86_64-pc-windows-gnu/release/sockettrail.exe
make win
```

Wine 9 from the Ubuntu repositories does not report the owner PID in the socket table:
use WineHQ 10 or newer. On real Windows run `cargo test -- --include-ignored`: it adds a
live DNS lookup test that fails under Wine.

The release zip is built on `windows-2025` for `x86_64-pc-windows-msvc` with a static
CRT (`+crt-static`), so the exe needs no Visual C++ runtime. Icon, version info and
manifest are embedded by `build.rs`.

## Packages

`make deb` builds a package with the binary in `/usr/bin`, the menu shortcut, the icon
and a disabled systemd user unit. It recommends `wireshark-common`. The minimum glibc is
the one of the build machine: the release is built on Ubuntu 24.04, which means glibc
2.39.

## CI and releases

`.github/workflows/ci.yml` runs on every push to `main` and on pull requests: fmt and
clippy for both targets, tests on Ubuntu 24.04 and 26.04, under WineHQ and on Windows,
and a smoke test of every build.

A release is made by a tag:

1. Bump `version` in `Cargo.toml`.
2. Turn `## Unreleased` in `CHANGELOG.md` into `## vX.Y.Z - YYYY-MM-DD`.
3. Commit, push, then `git tag vX.Y.Z && git push origin vX.Y.Z`.

`.github/workflows/release.yml` checks that the tag matches `Cargo.toml`, builds the
`.deb` and the zip, writes `SHA256SUMS`, creates build attestations and publishes the
release with the CHANGELOG section as its notes.

## Translations

English is the source language, Russian is the translation.

- Rust: `t!("English", "Русский")` gives a `String`, `text!` gives a `Text` that is
  translated when shown, `i18n::tr` works with `&'static str`. The `i18n` module is
  declared first in `main.rs` so that its macros are visible everywhere.
- Interface: English stays in the markup of `ui/index.html`, Russian lives in the `RU`
  dictionary in the same file. Static elements are marked with `data-t`, dynamic text
  goes through `t('English {name}', {name})`, and plurals through `plural()`.

A new string needs both languages.

## Screenshots

The images in `docs/images` are taken from a real session at 1600x900 with a device
scale factor of 2, in the dark and the light theme, and compressed with `pngquant`.
They must not show personal data: your own traffic, hosts, IP addresses or process
list.
