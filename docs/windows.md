# Windows

**English** | [Русский](ru/windows.md) · [Back to README](../README.md)

SocketTrail for Windows comes in two builds with the same `sockettrail.exe`:

| Build | File |
|---|---|
| Installer | `SocketTrail-<version>-windows-x64-setup.exe` |
| Portable | `SocketTrail-<version>-windows-x64-portable.zip` |

The exe is built with a static CRT and depends only on system DLLs. Windows 10 and 11, x64.

## Installation

The installer puts the program into `C:\Program Files\SocketTrail` for all users or,
when **Install for me only** is chosen, into `%LOCALAPPDATA%\Programs\SocketTrail`
without administrator rights. It adds a Start menu shortcut, an optional desktop
shortcut and an entry in **Settings** -> **Apps** -> **Installed apps**. A new version
is installed over the previous one; a running SocketTrail is closed first.
Uninstalling removes the program and keeps dumps, cache and settings, see
[Where data is stored](#where-data-is-stored).

Silent installation: `SocketTrail-<version>-windows-x64-setup.exe /VERYSILENT`, add
`/CURRENTUSER` for a per-user install.

The portable zip needs no installation: extract it to any folder.

## Running

1. Start **SocketTrail** from the Start menu or run `sockettrail.exe` from the
   extracted folder.
2. A Microsoft Edge or Chrome window with the interface opens. No CMD/PowerShell console opens.
   Closing the application window exits the program and finalizes an unfinished dump.
3. The exe is not signed yet, so SmartScreen may show "Windows protected your PC":
   **More info** -> **Run anyway**. Checksums and build attestation are on the
   release page, see [Verifying a download](#verifying-a-download).

## Two modes

| | Without administrator rights | As administrator |
|---|---|---|
| Processes and connections | yes | yes |
| Domains | from the system DNS cache | from DNS responses and SNI of TLS and QUIC, browsers included |
| Traffic per connection | no | yes |
| UDP targets | no | yes |
| Connections shorter than 250 ms | no | yes |
| Dumps `.pcapng` | no | yes, through PktMon |
| Extra software | none | none |

**Without administrator rights** domains come from the Windows DNS cache, the same
one `ipconfig /displaydns` shows. This covers games, Steam, system services and most
programs, but not Chrome and Edge: browsers have their own DNS client. The cache is
polled every 3 seconds, so domains appear within a few seconds. A connection opened
before SocketTrail started gets its name only while its record is still in the cache.

**As administrator** SocketTrail runs its own packet capture. The PktMon driver built
into Windows (Windows 10 version 2004 and newer, Windows 11) is started with the
standard `pktmon` tool, and frames are read from a dedicated ETW session. Neither
Wireshark nor Npcap is needed. Use the **Restart as administrator** button in the
window or start the exe with **Run as administrator**.

SocketTrail uses only its own PktMon/ETW capture engine. Wireshark, Npcap and
`dumpcap.exe` are never started, even when installed. Packet capture and dump
recording are unavailable without administrator rights.

The badge in the window header shows the mode: **Full mode** or **Basic mode**. Run as
administrator for analysis and dumps, because that is the complete picture. The mode
without rights suits a quick look at which programs hold connections.

## Differences from Linux

- The Windows UDP table has no remote address, so UDP targets come only from packet
  parsing. Ownership is matched by local address, port and IP family; socket
  creation timestamps prevent a reused port from claiming older traffic.
- PktMon captures from all network adapters. The `-i` option has no effect on Windows.
- While SocketTrail runs, `pktmon` is busy with it: starting another pktmon capture
  stops ours.
- On some systems the state field of the TCP table is shifted relative to its rows:
  `netstat -ano` shows `LISTENING` with a remote address, and the states of many rows
  change at once, while addresses and PIDs stay correct. SocketTrail recognizes this by
  impossible rows, keeps the last reliable state of a connection and shows `OPEN` until
  one has been read. Connection ownership is not affected.
- Proton detection is not needed. The PROTON badge and the **Proton** tab are not shown.

## VPN and TUN adapters

With a TUN adapter the same traffic is visible twice: inside the tunnel, where programs
talk to their servers from the tunnel address, and outside, where the computer talks
to the VPN server from the physical adapter. PktMon captures both. Only the inner
connections belong to a program, so a process dump keeps them and leaves the outer
tunnel out. In a whole-host dump the outer tunnel is one large flow to the VPN server,
and splitting puts it into a part of its own.

## Where data is stored

| Data | Path |
|---|---|
| Dumps | `%USERPROFILE%\SocketTrail` |
| Name cache, language, window profile | `%LOCALAPPDATA%\SocketTrail` |

Log: `%LOCALAPPDATA%\SocketTrail\sockettrail.log`.
Normal launches and administrator restarts create no console.
An explicit `--no-open` launch from a terminal writes to that existing terminal;
`--help` prints there too, or shows a dialog when no terminal is available.

## Verifying a download

Every release has a `SHA256SUMS` file and a GitHub build attestation that ties each
file to the workflow run that built it:

```powershell
$file = Get-Item .\SocketTrail-*-windows-x64-setup.exe   # or -portable.zip
Get-FileHash $file -Algorithm SHA256
gh attestation verify $file --repo mazixs/SocketTrail
```

Compare the hash with the line in `SHA256SUMS`. The last command needs the
[GitHub CLI](https://cli.github.com/). The `.deb` is verified the same way with
`sha256sum` and `gh attestation verify`.

## Building

See [Development](development.md#windows).
