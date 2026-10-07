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

UDP ownership uses the local address, port and IP family, and the remote endpoint
when the socket is connected. Wildcard binds (`0.0.0.0`, `::`) match only addresses
of this computer, read from the network interfaces. A shared or unresolved endpoint
is not assigned to an arbitrary process. Linux socket inodes and Windows UDP
creation timestamps distinguish reused sockets; Windows falls back to PID tables
when creation timestamps are unavailable.

A new socket cannot claim packets from before its observed lifetime. If one
connection tuple contains packets from different socket lifetimes, it remains
unattributed rather than relabeling its whole history. Socket polling still cannot
reliably identify sockets created and closed entirely between polls.

For TCP, a changed inode or PID, or reopening an observed closed tuple, disputes
the combined history. Counters remain, but the process identity and previous SNI
are cleared. Such a tuple is excluded from process-scoped views and dumps.

Process identity includes the start time, not just the PID. A reused PID cannot
join an existing recording group or keep its old selection. The selected and
recorded processes are checked on each poll. When multiple Linux processes hold
one inode, its owner stays ambiguous, including after a partial scan; the Wine
copy in `wineserver` remains a special case.

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

TLS ClientHello is assembled across TCP segments and TLS records, with reordered
segments, retransmissions and sequence-number wrap supported. Each direction has
at most 32 KiB of stream data and a 16 KiB handshake; at most 256 streams are kept,
with a 10-second idle lifetime. QUIC reconstructs truncated packet numbers before
decryption. Ethernet VLAN/QinQ and IPv6 hop-by-hop, routing, destination, AH and
initial fragment headers are parsed. IP fragments are not reassembled.

The live capture keeps full frames. Packet accounting has a queue of 8192 decoded
packets. On Windows an ETW callback only copies into a 256-event queue; a worker
parses and writes frames, and recording controls use the same queue. PktMon startup
no longer stops another program's capture; an occupied capture is a startup error.
Overload losses appear in API statistics and the capture indicator's tooltip.

Noninitial IPv4 fragments are not parsed as TCP/UDP because they have no transport
header. IP fragments are not reassembled, so counters for fragmented traffic can
be incomplete. A whole-host dump retains all frames; a process dump excludes
fragments whose ownership cannot be confirmed.

## Names and network owners

Names come from SNI, DNS responses, PTR and labels for special addresses, in this order
of reliability. An address behind a CNAME chain gets the name that was queried, not
the CDN node at the end of the chain. PTR is requested through `resolvectl` with `dig`
as a fallback, on Windows through `DnsQuery_W`. Found names are saved to `names.json` in the cache
directory: a DNS response is seen only once, and without the cache a connection opened
before SocketTrail started would stay nameless after a restart.

DNS names expire according to their record TTL (capped at one day). Up to eight
names per IP are kept; simultaneous names or overflow make a new connection's DNS
name ambiguous. An existing connection keeps its first DNS name until SNI replaces
it. The disk cache retains expiration and ambiguity; legacy DNS entries without TTL
are not restored. DNS still suggests a name for an IP and does not prove the name
of a particular connection or process.

The network owner is the ASN from [Team Cymru](https://www.team-cymru.com/ip-asn-mapping),
requested as a DNS TXT record from `origin.asn.cymru.com`. PTR and ASN often disagree,
for example a PTR of a hosting company on a Cloudflare network, so both are kept.
Addresses are looked up in the background a few at a time, with a cache. Only public
addresses are looked up: for private, link-local, CGNAT (`100.64.0.0/10`, Tailscale
among others) and reserved addresses the request would reveal your own network to an
outside resolver. A delegated reverse zone (RFC 2317) is not taken for a PTR name, and
when Team Cymru lists several origin ASNs, the first one is shown.

## Dumps

A dump is a second `dumpcap` (or the PktMon stream on Windows) writing full packets to
a file. When the recording stops, SocketTrail rewrites the file once:

1. With **process only**, packets of connections owned by the selected group are kept.
   Confirmed ownership is retained during recording even when the live history
   evicts an old connection. Connections opened after the start are included.
   Unknown or disputed ownership is excluded: sharing an IP or CDN domain is not
   evidence of belonging to the same process.
2. Every packet gets a pcapng comment `process [pid] -> domain`, and the section header
   says what was recorded.
3. A `.json` map is saved next to the file: the period, the process, its PIDs and every
   connection with names, owners and traffic.

A process-only recording stops by itself 15 seconds after the process exits.

Startup, recording and finalization are separate states. Repeat starts and operations
during startup or finalization are rejected without changing the recording. On Linux,
capture startup is confirmed by the pcapng stream or file header, and dumpcap exit
and diagnostics are monitored. Windows checks ETW health and file write errors.
File names remain unique even when recordings start in quick succession.

Stop, processing and sidecar errors return `ok: false` and appear in the UI. If process
filtering fails, the original capture is retained and explicitly reported as unfiltered.
The JSON map distinguishes `requested_only_process` from the actual `only_process`;
`processing` includes the processing status and whether capture ended cleanly
(`capture_complete`).

Recording metadata is limited to 40,000 connection tuples and 4096 process
instances. Reaching a limit stops recording with an error. Finalization waits up
to two seconds for already accepted packets to be accounted for. Tracking losses
or incomplete ownership preserve a process dump as unfiltered, with an error and
`capture_complete: false`; truncated blocks and mismatched pcapng lengths leave
the original file intact.

History still combines repeated lifetimes of one tuple conservatively, and its
timestamps reflect observation rather than wire capture time. Separating these
lifetimes and correlating by capture timestamps remain future engine work. When
both endpoints belong to this host, packets count as outgoing on the sending
endpoint; receive counters of the other local endpoint are not mirrored.

## Local interface

The interface is one HTML file embedded into the binary and served by a built-in HTTP
server on `127.0.0.1`. Requests with a `Host` other than `127.0.0.1:<port>` or
`localhost:<port>` are rejected, which blocks DNS rebinding. POST requests with a
foreign `Origin` are rejected, which blocks CSRF from other pages open in the browser.

The window keeps an SSE channel `/api/alive` open. When the window closes and the
channel stays silent for 10 seconds, the program finalizes the dump and exits. On Linux
it also watches the browser process of its own profile through the `SingletonLock` link
in the profile and exits right after that process ends. If the process cannot be found,
only the channel is used.

## Code layout

| Module | Purpose |
|---|---|
| `src/main.rs` | startup, HTTP API, polling loop, dump control |
| `src/procs/` | process inventory: `/proc` on Linux with Proton detection, Toolhelp32 on Windows; descendant tree |
| `src/sockets/` | socket snapshot: `/proc/net/*` and inode -> PID on Linux, IP Helper tables on Windows |
| `src/pcap.rs` | pcapng stream parsing, SNI from the TLS ClientHello, DNS responses |
| `src/tls.rs` | bounded TCP/TLS ClientHello reassembly |
| `src/quic.rs` | SNI from QUIC Initial: keys, decryption, reassembly of the ClientHello |
| `src/capture/` | platform capture: dumpcap on Linux, own PktMon/ETW engine on Windows |
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
| `src/win_startup.rs` | Windows: windowed startup and file log |
| `src/paths.rs` | cache and dump directories |
| `ui/index.html` | the whole interface, embedded into the binary |
