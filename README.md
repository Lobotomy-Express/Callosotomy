<p align="center">
  <img src="assets/icon-256.png" width="112" alt="Callosotomy logo: two brain hemispheres pulled apart">
</p>

<h1 align="center">Callosotomy</h1>

<p align="center"><b>Sever the connection before it spreads.</b><br>
An open-source network kill switch for Windows.</p>

---

A **corpus callosotomy** is brain surgery that cuts the bridge between the two hemispheres so a seizure can't spread from one side to the other. Callosotomy does the same for a computer under attack: one click cuts it off from the internet, the local network, or everything, so ransomware can't spread and an attacker loses their connection.

## Features

- **Three modes**
  - **Internet**: blocks everything outside your network, *including DNS to your router*, which closes the classic DNS-tunnelling escape route. Local devices stay reachable.
  - **Local network**: blocks other machines on your LAN so an infection can't spread sideways. Your gateway, DNS and DHCP stay reachable, so the internet keeps working.
  - **Everything**: blocks every remote address in both directions.
- **Enforced by a SYSTEM service.** Closing the app, killing the tray process or signing out does not lift a block. Blocks survive reboots and are re-applied at startup.
- **Kills existing connections.** Severing drops established TCP sessions, not just new ones.
- **Tamper detection and self-healing.** Every 3 seconds the service checks its firewall rules and Windows Firewall itself. If something deletes, disables or weakens them, they are restored and the event is logged. A periodic test connection (no data sent) confirms the block really holds; if it gets through, the app turns amber and says **Bypassed**.
- **Frosted-glass interface.** A tray icon (a green joined brain when connected, a glowing red split brain when severed) opens a Windows 11 acrylic pane. There is an optional floating panic button.
- **Instant hotkey.** <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>K</kbd> severs everything from anywhere.
- **Built for IT.** It installs from an MSI, is configured through Group Policy (ADMX included), writes stable Event Log IDs for your SIEM, and has a scriptable command line for remote response.

## Install

Download the MSI from [Releases](../../releases) and run it, or deploy it silently:

```powershell
msiexec /i Callosotomy-0.1.2-x64.msi /qn
```

The installer:
- puts the files in `C:\Program Files\Callosotomy`, which only administrators can change;
- registers the **Callosotomy Protection** service to run as SYSTEM and restart automatically if it fails;
- starts the tray app for every user when they sign in.

Requires Windows 10 1809 or later. The acrylic pane needs Windows 11 22H2 or later; older versions get a solid dark pane.

## Use

| Action | How |
|---|---|
| Open the pane | Click the brain icon in the system tray |
| Sever everything | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>K</kbd>, or right-click the tray icon |
| Restore | Pane → **Restore all connections** |
| Floating button | Pane → **Floating button** |

### Command line

```powershell
Callosotomy.exe --status
Callosotomy.exe --sever internet   # or: local, all
Callosotomy.exe --restore
```

Exit codes: `0` ok, `1` usage, `2` denied or bypassed, `3` service unreachable. This works over any remote-execution tool your EDR or RMM provides.

## Group Policy

Copy `policy\Callosotomy.admx` and `policy\en-US\Callosotomy.adml` into your PolicyDefinitions folder. The settings appear under **Computer Configuration → Administrative Templates → Callosotomy**.

| Policy | Default | Notes |
|---|---|---|
| Allow standard users to sever connections | On | |
| Allow standard users to restore connections | On | **Turn off on managed fleets**, so malware running as the user can't lift a block |
| Allow Internet / Local / Everything mode | On | Turn off any modes you don't want offered |
| Repair tampering automatically | On | |
| Drop established connections | On | |
| Bypass detection probe | On, `1.1.1.1:443` | Must be an IP address and port |
| Floating panic button | User's choice | Force it on or off |

## Event log

Source **Callosotomy** in the **Application** log:

| ID | Level | Meaning |
|---|---|---|
| 1000 | Info | Service started |
| 1100 | Warning | Mode changed (includes who changed it) |
| 1101 | Info | Established connections dropped |
| 1200 | Error | Tampering detected |
| 1201 | Warning | Tampering repaired |
| 1300 | Critical | **Block bypassed: disconnect the machine physically** |
| 1400 | Warning | Request denied |
| 1401 | Critical | Control pipe hijack attempt |

## What it can't do

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). In short: **a software kill switch can't beat malware that already has administrator or kernel access on the same machine.** Callosotomy makes that much harder and loudly tells you when it happens. The only kill that can't be bypassed is pulling the network cable, or isolating the machine at the switch or router. Use Callosotomy as a fast first response, not your last line of defence.

## Build

Use Windows with the .NET 8 SDK:

```powershell
.\build.ps1          # tests, self-contained publish, MSI in .\artifacts
```

The core logic (address maths, firewall plans, protocol) is plain .NET 8, so you can test it on any OS with `dotnet test`.

```
src/Callosotomy.Core      Pure logic: modes, IP-range maths, firewall rule plans, control protocol
src/Callosotomy.Service   SYSTEM service: firewall enforcement, tamper checks, secured named pipe
src/Callosotomy.Tray      WPF tray app: acrylic pane, frosted floating button, hotkey, command line
installer/                WiX MSI
policy/                   Group Policy templates
```

The only dependencies are .NET and Microsoft's own hosting package. There are no third-party libraries.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0](LICENSE). You're free to use it anywhere, including inside companies. If you distribute a modified version, you must share its source under the same licence.
