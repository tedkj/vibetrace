# VibeTrace

Every router between you and a host, measured live, and a log of outages your ISP can act on.

Type a host and VibeTrace shows every router on the way, with its loss, latency and network (AS),
and a verdict in plain words that tells real loss from a router that only answers pings slowly.
The ISP log keeps a trace running for hours or days (in the tray when the window is minimised),
records each outage and where it broke, checks DNS, and writes a report for your ISP's support
desk. Path MTU finds the largest packet each hop lets through, and where the size drops. It needs
no admin rights and no raw sockets: it uses Windows' own ping API. It is written in Rust with a
native Slint interface, with no browser engine inside: one small exe.

`VibeTrace.exe <host>` starts tracing that host at once.

## What it keeps on your PC

- Settings in `%APPDATA%\com.tedkj.vibetrace`, and the ISP log, up to 7 days of it, in
  `%LOCALAPPDATA%\com.tedkj.vibetrace`.
- Reports and exports only where you save them.
- The installer adds a Start menu shortcut and an entry in Installed apps. Uninstalling removes the
  app and leaves your settings and log where they are.

## What it connects to

- The host you trace, and every router on the way: pings at normal traceroute rates.
- Your DNS servers: the host's address, each router's name, and its network number through Team
  Cymru's public DNS service (the router's address is in the question). The ISP log's DNS check
  asks your DNS servers too.
- getvibeware.com, only when you press About's "Check this install": it fetches VibeTrace's signed
  release list to compare your install with it.

## Download

Get the installer from [Releases](https://github.com/tedkj/vibetrace/releases) or from
[getvibeware.com](https://getvibeware.com). It installs for your user only, without admin rights.
The installer, VibeTrace.exe and its uninstaller are code signed by "Open Source Developer Ted
Kenneth Johansen" (right-click the file, Properties, Digital Signatures). The certificate is new, so
Windows SmartScreen may still warn before it runs. Compare the installer's SHA-256 with the one in
`SHA256SUMS.txt` on the release page:

```powershell
Get-FileHash .\VibeTrace_0.1.0-preview_x64-setup.exe
```

## Building from source

You need a current stable Rust toolchain on Windows (the MSVC target).

```sh
cargo build --release --locked
```

The app is then at `target\release\vibetrace.exe`. `vendor/` holds Slint's `i-slint-core` 1.18.1
with one small repaint fix; `vendor/README.md` says what changed and why.

### Building the installer

`installer\build.ps1` builds the app and its installer,
`target\release\bundle\VibeTrace_<version>_x64-setup.exe`. It needs the official NSIS 3.13:
download `nsis-3.13.zip` from SourceForge (SHA-256
`ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`) and unpack it to
`_tools\nsis-3.13` in the folder that holds this repository. The script checks that whole folder
against a pinned hash before it runs anything from it. `installer\notices.ps1` writes
`THIRD-PARTY-NOTICES.txt` for each build (every crate the app links, with its licence text), and
the installer puts it and `LICENSE` next to the app.

## License

[AGPL-3.0](LICENSE). Use it, change it, share it. If you hand out a changed version, or run one as
a service for other people, you share your changes under the same license. Slint is used under
its GPLv3 option.

Made in Norway by Ted K. Johansen.
