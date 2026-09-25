# Changelog

## v0.2.1 - 2026-09-25

- Linux: with Chrome 154 the program exited 15 seconds after start while the window
  stayed open with "Connection to SocketTrail lost". Chrome now joins its command line
  with spaces, and the browser process of the window was no longer found. It is now
  found through the `SingletonLock` link in the profile, and if it cannot be found, the
  window is tracked by the page connection only.
- .deb: the package description no longer contains the commands for capture rights,
  the window shows them when needed. The build fails if `DEBIAN/control` has non-ASCII
  characters: PackageKit on Ubuntu shows them as `?` in App Center.

## v0.2.0 - 2026-09-25

- Windows 10/11: portable zip (`make win`). Sockets via IP Helper with the owner PID,
  processes via Toolhelp32, PTR and ASN via `DnsQuery_W`. Icon, version info and
  manifest in the exe.
- Windows without Wireshark and Npcap: domains from the system DNS cache without
  administrator rights, and with them our own packet capture via the built-in PktMon
  and ETW (domains from DNS and SNI, traffic, .pcapng dumps). A "Restart as
  administrator" button right in the window, which stays open. dumpcap remains the
  fallback.
- Domains of QUIC (HTTP/3) connections: SNI is read from Initial packets of QUIC
  versions 1 and 2 (RFC 9001, RFC 9369). A ClientHello split across several packets,
  as Chrome sends it, is put together by offset. Previously browser connections over
  UDP 443 were shown with only an IP unless a DNS response was seen.
- Dump: every packet is labeled with its process and domain (`frame.comment` in
  Wireshark), and the file header says what was recorded. "Process only" selects
  traffic by connection owner at stop time instead of a BPF filter by addresses at
  start: servers the game connects to later are no longer lost. Such a recording
  stops by itself 15 seconds after the process exits. The `.json` map keeps the
  process even if it exited before the recording was stopped.
- English interface by default, Russian as the second language. The EN | RU switch
  in the window header changes the window, the HTML report and console messages;
  the choice is saved in the `lang` file in the cache directory. The `--lang en|ru`
  option sets the language at startup. README in English and Russian.
- Linux: sockets of programs under Wine are attributed to the `.exe` itself. Wine
  keeps a copy of every socket in `wineserver`, and connections of a game could go to
  `wineserver` when its PID was higher.
- A name from DNS replaces a previously shown PTR name if it arrives later.
- Window closing is tracked via the SSE channel `/api/alive` on all OSes.
- `-i` accepts several comma-separated interfaces.
- TIME_WAIT sockets without history are no longer listed: tens of thousands of
  local TIME_WAIT sockets pushed out live connections, and most of them lost the PID.
- CI: fmt, clippy, tests on Ubuntu 24.04 and 26.04, under Wine and on Windows; a
  release by tag builds deb and zip, SHA256SUMS and attestation. Building from source
  needs Rust 1.89 or newer.
- Window in a Chromium-based browser with its own profile and window class: it does
  not mix with regular Chrome and has its own taskbar icon. Chrome, Chromium, Edge,
  Brave and Vivaldi are detected, including snap builds.
- Closing the window, Ctrl+C and SIGTERM exit cleanly: the dump is finalized and gets
  its `.json` map, the name cache is saved, dumpcap is stopped.
- Local API protection: `Host` check (DNS rebinding) and `Origin` check for POST
  (CSRF). Previously any page open in the browser could clear the history or start
  a dump.
- Live parsing and dumps without a process filter no longer capture loopback, except
  DNS. With heavy local traffic this cuts the load several times (measured: 34% + 32%
  CPU for dumpcap -> 3% + 0%) and keeps the dump from growing to gigabytes.
- Dock icon on Wayland: the window opens at `/sockettrail`, its app_id is set in the
  shortcut, plus hidden shortcuts for other Chromium-based browsers.
- .deb package: `make deb`.
- The window is tracked by the main browser process with the SocketTrail profile:
  Chrome started from the GNOME menu moves into its own systemd scope, and the
  original PID exits after 2 seconds, which the program used to take for a closed
  window.
- Directories moved to `src/paths.rs`, window launch to `src/window.rs`, with
  groundwork for Windows.
- README rewritten with screenshots of a real session; details moved to `docs/`
  (usage, Windows, how it works, development) in English and Russian.

## v0.1.0 - 2026-09-20

First release. Linux.

- Auto-refreshing process tree, Proton and Wine detection, selecting a process
  together with all its descendants.
- Per-process connection history: domain, IP, port, protocol, state, network owner
  (ASN), traffic volume. Closed connections stay in the list.
- Two data sources: polling `/proc/net/{tcp,tcp6,udp,udp6}` every 200 ms and parsing
  the pcapng stream from `dumpcap`. The second one catches connections shorter than
  the polling interval and gives domains from DNS responses and SNI.
- Real ports only: from the socket table or from the packet header, no substitutions
  by service type.
- Address names from four sources (SNI, DNS, PTR via resolvectl, labels for special
  addresses) with an on-disk cache `~/.cache/sockettrail/names.json`.
- Dump recording to `~/SocketTrail/<process>-<date>.pcapng` with a connection map in
  `.json` next to it, optionally with a BPF filter by the process addresses.
- Self-contained HTML report, summary by address, copying a row or the table,
  resizable columns, dark and light themes.
- Installation without root: `./install.sh` puts the binary into `~/.local/bin` and a
  shortcut into the application menu; background collection via a systemd user unit.
