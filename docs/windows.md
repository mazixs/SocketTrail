# Windows

**English** | [Русский](ru/windows.md) · [Back to README](../README.md)

SocketTrail for Windows is a portable zip: `sockettrail.exe`, `README.txt` and
`LICENSE.txt`. Nothing to install. The exe is built with a static CRT and depends
only on system DLLs. Windows 10 and 11, x64.

## Running

1. Extract the archive to any folder and run `sockettrail.exe`.
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

## Differences from Linux

- The Windows UDP table has no remote address, so UDP targets come only from packet
  parsing, and the owner is matched by local port.
- PktMon captures from all network adapters. The `-i` option has no effect on Windows.
- While SocketTrail runs, `pktmon` is busy with it: starting another pktmon capture
  stops ours.
- Proton detection is not needed. The PROTON badge is not shown.

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

Every release has a `SHA256SUMS` file and a GitHub build attestation that ties the zip
to the workflow run that built it:

```powershell
$zip = Get-Item .\SocketTrail-*-windows-x64.zip
Get-FileHash $zip -Algorithm SHA256
gh attestation verify $zip --repo mazixs/SocketTrail
```

Compare the hash with the line in `SHA256SUMS`. The last command needs the
[GitHub CLI](https://cli.github.com/). The `.deb` is verified the same way with
`sha256sum` and `gh attestation verify`.

## Building

See [Development](development.md#windows).
