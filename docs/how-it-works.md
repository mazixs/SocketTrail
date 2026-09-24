# How it works

**English** | [Русский](ru/how-it-works.md) · [Back to README](../README.md)

## Why existing tools were not enough

- `ss -tunp` in a loop misses connections shorter than the polling interval, and those
  are often the interesting ones: crash report uploads, telemetry, API calls at
  startup.
- `nethogs` and `iftop` show traffic volume, but not addresses or domains.
- Wireshark sees packets, but does not know which process they belong to.
- Under Proton there is more than one process: Steam, `pressure-vessel`, `wineserver`
  and the `.exe` itself, and the sockets belong to child processes. Picking a single
  PID loses half of the picture.

SocketTrail combines two sources. Fast polling of the socket tables gives the owner of
each connection. Parsing the packet stream gives domains and the connections that
polling did not catch.

```
dumpcap -w - ── pcapng ──> own parser ──> DNS, SNI, bytes ───┐
                                                             ├──> history ──> UI
socket tables ── 250 ms ──> sockets ──> owner PID ───────────┘       │
                                                              PTR, ASN, cache
```

A packet is matched to a process by its tuple: protocol, local address and port,
remote address and port. A connection that closed between two polls stays in the
history as a row from packets only, without a guessed owner.

## Sockets and processes

**Linux.** Sockets are read from `/proc/net/{tcp,tcp6,udp,udp6}` without spawning `ss`.
The owner is found through the socket inode in `/proc/<pid>/fd`. Walking the file
descriptors of every process is expensive, so the selected group is scanned on every
poll and the full map of the computer about every 2 seconds.

Wine keeps a copy of every socket of a Windows program in `wineserver`. Such a socket
is attributed to the `.exe`, otherwise the connections of a game would go to
`wineserver`.

A process gets the PROTON badge if its command line mentions Proton, Wine or
pressure-vessel, or its name starts with `wine` or ends with `.exe`. Such a process is
shown by the `.exe` name from its command line: the kernel name of a Wine process is
cut to 15 characters and is often just a thread name like `GameThread`.

Selecting a process takes its whole subtree, and the group is recalculated on every
full scan, because Proton starts new descendants while the game runs.

**Windows.** Sockets come from `GetExtendedTcpTable` and `GetExtendedUdpTable` with the
owner PID, processes from Toolhelp32.

## Packets

On Linux `dumpcap` from Wireshark writes a pcapng stream to stdout, and SocketTrail
parses it with its own parser, without libpcap. `dumpcap` needs capture capabilities,
not root. Loopback traffic is not captured, except DNS: heavy local traffic would load
the parser for nothing.

On Windows as administrator the PktMon driver built into Windows is started with the
standard `pktmon` tool, and frames are read from a dedicated ETW session. Without
administrator rights, domains come from the system DNS cache
(`DnsGetCacheDataTable`). See [Windows](windows.md).

From the packets SocketTrail takes:

- DNS responses: names, addresses and CNAME chains;
- SNI from the TLS ClientHello;
- SNI from QUIC Initial packets (HTTP/3);
- bytes and packets per connection;
- connections that the socket table never showed.

QUIC encrypts even the first packets, but the Initial keys are derived from the
connection ID sent in the clear (RFC 9001), so the ClientHello can be read without
the session keys. Versions 1 and 2 are supported. Chrome splits the ClientHello across
several packets and shuffles the frames, so the pieces are put together by offset for
each connection. With Encrypted Client Hello (ECH), in TLS and QUIC alike, only the
outer SNI is visible: the provider's public name, for example `cloudflare-ech.com`.

## Names and network owners

Names come from SNI, DNS responses, PTR and labels for special addresses, in this order
of reliability. PTR is requested through `resolvectl` with `dig` as a fallback, on
Windows through `DnsQuery_W`. Found names are saved to `names.json` in the cache
directory: a DNS response is seen only once, and without the cache a connection opened
before SocketTrail started would stay nameless after a restart.

The network owner is the ASN from [Team Cymru](https://www.team-cymru.com/ip-asn-mapping),
requested as a DNS TXT record from `origin.asn.cymru.com`. PTR and ASN often disagree,
for example a PTR of a hosting company on a Cloudflare network, so both are kept.
Addresses are looked up in the background a few at a time, with a cache.

## Dumps

A dump is a second `dumpcap` (or the PktMon stream on Windows) writing full packets to
a file. When the recording stops, SocketTrail rewrites the file once:

1. With **process only**, packets of connections owned by the selected group are kept.
   The owner is decided at this moment, from the whole history of the recording, so
   connections opened after the start are included. Unmatched packets to addresses the
   process talked to are kept too.
2. Every packet gets a pcapng comment `process [pid] -> domain`, and the section header
   says what was recorded.
3. A `.json` map is saved next to the file: the period, the process, its PIDs and every
   connection with names, owners and traffic.

A process-only recording stops by itself 15 seconds after the process exits.

## Local interface

The interface is one HTML file embedded into the binary and served by a built-in HTTP
server on `127.0.0.1`. Requests with a `Host` other than `127.0.0.1:<port>` or
`localhost:<port>` are rejected, which blocks DNS rebinding. POST requests with a
foreign `Origin` are rejected, which blocks CSRF from other pages open in the browser.

The window keeps an SSE channel `/api/alive` open. When the window closes and the
channel stays silent for 10 seconds, the program finalizes the dump and exits.

## Code layout

| Module | Purpose |
|---|---|
| `src/main.rs` | startup, HTTP API, polling loop, dump control |
| `src/procs/` | process inventory: `/proc` on Linux with Proton detection, Toolhelp32 on Windows; descendant tree |
| `src/sockets/` | socket snapshot: `/proc/net/*` and inode -> PID on Linux, IP Helper tables on Windows |
| `src/pcap.rs` | pcapng stream parsing, SNI from the TLS ClientHello, DNS responses |
| `src/quic.rs` | SNI from QUIC Initial: keys, decryption, reassembly of the ClientHello |
| `src/capture.rs` | `dumpcap` control: live stream and dump recording |
| `src/etw.rs` | Windows: capture through PktMon and ETW, `.pcapng` writing |
| `src/dnscache.rs` | Windows: names from the system DNS cache |
| `src/annotate.rs` | dump post-processing: packet labels, process traffic selection |
| `src/resolve.rs` | PTR and ASN lookups |
| `src/cache.rs` | on-disk name cache |
| `src/state.rs` | connection history, counters, name merging |
| `src/report.rs` | self-contained HTML report |
| `src/i18n.rs` | English and Russian texts, language selection |
| `src/window.rs` | window in a Chromium-based browser with its own profile, opening folders |
| `src/alive.rs` | SSE channel that tells when the window is closed |
| `src/elevate.rs` | Windows: privilege check and restart as administrator |
| `src/paths.rs` | cache and dump directories |
| `ui/index.html` | the whole interface, embedded into the binary |
