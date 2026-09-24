# SocketTrail

English | [Русский](README.ru.md)

A network connection monitor tied to processes, including applications running
under Proton and Wine. For every connection it shows the domain, IP, port,
protocol, network owner and traffic volume, keeps a history (closed connections
stay in the list) and records all traffic of the selected process into a single
.pcapng file with one button.

```
 ● SocketTrail [x] process only [Record dump]  [Dumps][Copy][Report][JSON] EN|RU
┌───────────────────────────┬──────────────────────────────────────────────────┐
│ [With traffic|Proton|All] │ [Process|Whole host] [List|By address]           │
├───────────────────────────┼──────────────────────────────────────────────────┤
│ ● steam          PROTON   │ Time   State        Domain / name    Port    Out │
│   └ srt-bwrap             │ 21:04  ESTABLISHED  api.example.com   443  12 KB │
│     └ pv-adverb           │ 21:04  ESTABLISHED  cdn.example.net   443 3.1 MB │
│       └ game.exe    ●     │ 21:03  TIME_WAIT    192.0.2.10      27015  840 B │
│ ● chrome  x12             │ 21:03  ESTABLISHED  www.example.org   443  56 KB │
│   firefox                 │ ...                                              │
└───────────────────────────┴──────────────────────────────────────────────────┘
```

On the left is an auto-refreshing process tree, on the right is the connection
history with domain, address, port, network owner and traffic volume. The
"By address" mode collapses the history into one row per target with a session
count.

## Why existing tools were not enough

- `ss -tunp` in a loop misses connections shorter than the polling interval, and
  those are often the interesting ones (crash report uploads, API calls at startup).
- `nethogs` and `iftop` show traffic volume, but not addresses or domains.
- Wireshark sees packets, but does not know which process they belong to.
- Under Proton there is more than one process: Steam, `pressure-vessel`,
  `wineserver` and the `.exe` itself, and the sockets belong to child processes.
  Picking a single PID loses half of the picture.

SocketTrail combines both sources: fast polling of the socket tables gives the
owner, and parsing the packet stream gives domains (DNS and SNI) and the
connections that polling did not catch.

## Requirements

Linux (for Windows see the [Windows](#windows) section) and `dumpcap` from
Wireshark. Root is not needed if the standard Wireshark setup is in place:
`dumpcap` has capabilities and the user is in the `wireshark` group:

```sh
sudo dpkg-reconfigure wireshark-common   # answer "yes"
sudo usermod -aG wireshark "$USER"       # then log out and back in
getcap /usr/bin/dumpcap                  # cap_net_admin,cap_net_raw=eip
```

Without `dumpcap` the tool still works, but only socket polling is left: there
are no domains and no short connections, and the indicator in the header says so.

## Installation

```sh
./install.sh
```

Puts the binary into `~/.local/bin`, a shortcut into the application menu and
checks the environment: whether `dumpcap` is installed, whether it has capture
rights, whether `~/.local/bin` is in `PATH`. Root is not needed. To undo, run
`./uninstall.sh`.

Or as a package for Debian and Ubuntu (requires glibc 2.39+, i.e. Ubuntu 24.04 or
Debian 13 and newer):

```sh
make deb                                            # target/debian/sockettrail_<version>_amd64.deb
sudo apt install ./target/debian/sockettrail_*.deb  # pulls in wireshark-common
```

The package installs the binary into `/usr/bin`, the shortcut and the icon, and a
disabled user unit for background collection
(`systemctl --user enable --now sockettrail`).

## Running

| How | Command |
|---|---|
| From the application menu | **SocketTrail** icon (Network category) |
| From a terminal after installation | `sockettrail` |
| From the repository, without installing | `./run.sh` - rebuilds if the sources are newer than the binary |
| With make | `make run`, `make install`, `make check` |
| Manually | `cargo build --release && ./target/release/sockettrail` |

A separate window opens: Chrome, Chromium, Edge or Brave in app mode with its own
profile in `~/.cache/sockettrail/ui-profile`. The window does not mix with your
regular browser and has its own taskbar icon. **Closing the window exits the
program**: an unfinished dump is finalized and gets its `.json` map, and the name
cache is saved. Ctrl+C and SIGTERM do the same. Without a Chromium-based browser a
regular tab opens, and the program then runs until Ctrl+C.

The server listens on `127.0.0.1` only and rejects requests with a foreign `Host`
(DNS rebinding) and POST requests from other sites (CSRF). Running it again does
not start a second copy: if SocketTrail is already running, its window opens; if
the port is taken by another program, the next one is used.

Options: `-i <interface>` (default `any`), `--port <port>` (default 8787),
`--no-open` - server only, no window, `--lang en|ru` - language, `--help` - help.

### Language

The interface is available in English and Russian, English by default. The
EN | RU switch in the window header changes the language of the window, the HTML
report and the console messages. The choice is saved in the `lang` file in the
cache directory: `~/.cache/sockettrail/lang`, on Windows
`%LOCALAPPDATA%\SocketTrail\lang`. The `--lang en|ru` option sets the language at
startup.

### Background collection, optional

To have the history build up before the window is opened, for example from login
until the game starts:

```sh
mkdir -p ~/.config/systemd/user
cp assets/sockettrail.service ~/.config/systemd/user/
systemctl --user enable --now sockettrail
```

Note that in this mode `dumpcap` runs all the time and parses all host traffic.

## Usage

1. Pick a process on the left. The list refreshes by itself; a green dot means
   active connections, the PROTON badge means the process runs under Proton or
   Wine. Selecting a process automatically includes all its child processes.
2. The table shows the connection history. Rows tagged "packets only" are
   connections caught by packet parsing that never showed up in the socket table.
3. "Record dump" writes `~/SocketTrail/<process>-<date>.pcapng`. This is the
   SocketTrail folder in your home directory, not the repository directory of the
   same name. The "Dumps" button in the header shows the full path and the list of
   recorded files, and opens the folder in the file manager. With "process only"
   checked, the file keeps the traffic of the selected process and its children,
   including connections opened after the recording started. Such a recording
   stops by itself 15 seconds after the process exits: you can start a dump, play
   and not watch it. Without the checkbox all traffic of the computer is recorded.
   On stop every packet is labeled with its process and domain, for example
   `cs2.exe [1234] -> api.steampowered.com`. In Wireshark the label is in the
   `frame.comment` field: show it as a column or filter with
   `frame.comment contains "cs2.exe"`. A `.json` file with the map of connections,
   domains and PIDs is saved next to the dump, so that a week later it is still
   clear what was recorded.
4. "Report" exports a self-contained HTML file that opens without internet access.

### Small things that save time

- The process tree expands: a parent shows all its descendants, and a dozen
  leaves with the same name (browser tabs, workers) collapse into one row like
  `chrome x12`.
- Column borders can be dragged; a double click on a border fits the column to
  the longest value, so long domains are readable in full. Widths are
  remembered, as is the width of the left panel.
- The copy icon in a row puts the domain or address into the clipboard; "Copy"
  in the header copies the whole visible table as TSV, ready for spreadsheets.
- "By address" collapses the history by address and port: instead of three
  hundred TIME_WAIT rows to one host you see one row with the session count and
  traffic.
- The "local addresses" and "SocketTrail connections" checkboxes show what is
  hidden by default: requests to 127.0.0.53, mDNS, SSDP and the program's own
  service traffic.

### About ports and names

The port is always real. For live connections it is read from
`/proc/net/{tcp,tcp6,udp,udp6}`, for connections caught by packet parsing from the
TCP or UDP header. There are no defaults, no guesses by service type and no other
substitutions in the code: if the port is unknown, there is no row at all.

The host name comes from four sources in order of reliability: SNI from the TLS
ClientHello, DNS responses, the PTR record, then a label for special addresses
(`127.0.0.53` is the system resolver itself and never has a domain). Found names
are stored in `~/.cache/sockettrail/names.json` and survive a restart: a DNS
response is seen only once, and without the cache a connection opened before
SocketTrail started would stay nameless.

## Architecture

| Module | Purpose |
|---|---|
| `src/procs/` | process inventory: /proc on Linux (plus Proton detection), Toolhelp32 on Windows; descendant tree |
| `src/sockets/` | socket snapshot: /proc/net/* and inode -> PID on Linux, `GetExtendedTcpTable`/`GetExtendedUdpTable` on Windows |
| `src/pcap.rs` | pcapng stream parsing, SNI from the TLS ClientHello and addresses from DNS responses |
| `src/capture.rs` | dumpcap control: live stream and dump recording |
| `src/resolve.rs` | PTR and ASN via resolvectl (fallback - dig), via `DnsQuery_W` on Windows, and Team Cymru; both are shown because they often differ |
| `src/cache.rs` | on-disk cache of found names, so they are not lost between runs |
| `src/state.rs` | connection history, counters, name merging |
| `src/report.rs` | self-contained HTML report |
| `src/i18n.rs` | English and Russian texts, language selection |
| `src/window.rs` | window in a Chromium-based browser with its own profile, opening folders |
| `src/paths.rs` | cache and dump directories |
| `src/alive.rs` | SSE channel `/api/alive`: closing the window exits the program |
| `src/annotate.rs` | dump post-processing on stop: packet labels, process traffic selection |
| `src/etw.rs` | Windows: capture via PktMon and ETW, `.pcapng` recording |
| `src/dnscache.rs` | Windows: names from the system DNS cache |
| `src/elevate.rs` | Windows: privilege check and restart as administrator |
| `ui/index.html` | user interface, embedded into the binary |

## Windows

Portable zip: `sockettrail.exe`, `README.txt`, `LICENSE.txt`. No installation
needed; the exe is built with a static CRT and depends only on system DLLs.
Windows 10 and 11, x64.

- The process and connection list works right away and without administrator
  rights. In this mode domains come from the Windows DNS cache
  (`DnsGetCacheDataTable`, like `ipconfig /displaydns`): this covers games, Steam,
  system services and most programs, but not Chrome and Edge, which have their own
  DNS client. Domains appear gradually: the cache is polled every 3 seconds, and
  the name of a connection opened before SocketTrail started is found only while
  its record is still in the cache.
- With administrator rights (the "Restart as administrator" button in the window)
  SocketTrail runs its own packet capture: the PktMon driver built into Windows
  (Windows 10 2004+ and 11) is started with the standard `pktmon` tool, and frames
  are read from a dedicated ETW session. This gives domains from DNS responses and
  SNI (browsers included), traffic volume and `.pcapng` dumps. Neither Wireshark
  nor Npcap is needed.
- If Wireshark with Npcap is installed and there are no administrator rights,
  SocketTrail uses its `dumpcap.exe` as a fallback.
- The window opens in Edge (or Chrome) in app mode. Closing the window or the
  console exits the program, and the dump is finalized.
- The exe is not signed yet, so SmartScreen shows a warning: "More info" ->
  "Run anyway". Checksums and attestation are on the release page.
- Dumps: `%USERPROFILE%\SocketTrail`, cache and window profile:
  `%LOCALAPPDATA%\SocketTrail`.

Differences from Linux: the Windows UDP table has no remote address, so UDP
targets come only from packet parsing, and the owner is matched by local port.
PktMon captures from all network adapters; the `-i` option applies only to the
dumpcap fallback. While SocketTrail runs, `pktmon` is in use by it: starting
another pktmon capture stops ours. Proton detection is not needed.

Build:

```sh
make win                                 # mingw-w64, target/windows/SocketTrail-<version>-windows-x64.zip
cargo test --target x86_64-pc-windows-gnu  # tests under Wine (runner in .cargo/config.toml)
```

The release zip is built by CI on `windows-2025` (`x86_64-pc-windows-msvc`,
`+crt-static`), see `.github/workflows/release.yml`.

## License

MIT, see [LICENSE](LICENSE).
