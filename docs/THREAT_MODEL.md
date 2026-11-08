# Threat model

This is an honest account of what Callosotomy defends against, what it doesn't, and why the design looks the way it does.

## Goal

Let an everyday Windows user decide, simply and reliably, who their PC may talk to: nothing on the internet, nothing on the local network, or nothing at all. That control should protect their privacy and limit their exposure to attacks day to day, and also work as an emergency stop if something has already gone wrong. Every block must be applied **immediately, reliably and verifiably**, and kept until someone with the right permission lifts it.

## Assets

1. **The block itself**: the firewall rules that cut traffic.
2. **The truth about the block**: what the UI and event log report.
3. **The machine's integrity**: Callosotomy must not give attackers a new way in.

## Attackers and outcomes

| Attacker | Can they lift the block? | What Callosotomy does |
|---|---|---|
| Remote attacker on the network | No | Only the local channel controls the service. The control pipe explicitly denies network logons, and the service opens no network ports. |
| Malware running as the signed-in **standard user** | Only if policy allows users to restore (the default for home use) | Set **Allow standard users to restore connections = Disabled** on managed machines. Then only an administrator can lift a block. |
| Malware that kills or edits the tray app | No | The tray app has no power of its own. It only asks the SYSTEM service, and the block stays in place without it. |
| Malware that creates a fake control pipe | No | The service only ever creates the pipe as its *first* instance and always keeps one of its own instances open, so it can never end up joining a pipe someone else created. The tray app checks with the Service Control Manager that the process on the other end is the one running the registered service, and refuses anything else. |
| Malware that floods the control channel to jam the kill switch | Harder | Up to 16 connections at a time, at most 2 per process, each dropped after 2 seconds of silence. The <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>K</kbd> hotkey and the panel both keep working unless many separate processes cooperate. |
| Malware with **administrator** rights | **Yes, eventually** | Admins can stop services, edit firewall rules or uninstall. Callosotomy restores tampered rules within about 3 seconds, logs events 1200, 1201 and 1300, and shows **Bypassed** if a test connection gets out. This raises the cost and makes the attack noisy, but can't prevent it. |
| Kernel-mode malware or a malicious network driver | **Yes** | Out of scope for any user-mode tool. The probe may still catch it. |

**The bottom line:** a software kill switch on a fully compromised machine is a speed bump, not a wall. The only kill that can't be bypassed is physical: pull the cable, disable the switch port, or quarantine the machine at the router. The README says so too.

## Design decisions

- **Block rules, not allow rules.** In Windows Firewall a block rule always beats an allow rule, so nothing another program allows can punch through.
- **Fail closed.** Stopping or crashing the service never removes rules. The saved mode is re-applied at startup, so a reboot doesn't lift a block either. Rules are only removed by an explicit restore, or by a full uninstall run by an administrator.
- **No gap when switching modes.** New rules are added before old ones are removed.
- **No gap at boot.** The service starts after the Base Filtering Engine and Windows Firewall. If the saved block still can't be applied, it retries every few seconds until it can, rather than giving up.
- **DNS closed in Internet mode.** Otherwise malware could tunnel data out through the router's DNS forwarder.
- **All of IPv6 counted as internet** except loopback, link-local, unique-local and multicast. That covers translation prefixes such as NAT64 (`64:ff9b::/96`), which lead back to the IPv4 internet on IPv6-only networks.
- **Existing connections are cut.** IPv4 TCP sessions to blocked addresses are torn down immediately. Windows has no equivalent API for IPv6 or UDP flows; those hit the new rules on their next packet.
- **A small attack surface:**
  - The service opens no network ports and makes no web requests. The only outbound traffic is the optional bypass probe, a bare TCP connect with no payload, sent only while the internet is supposed to be blocked.
  - The whole control protocol is 5 fixed ASCII commands of at most 128 bytes. Anything else is rejected and logged. Slow clients are dropped after 2 seconds.
  - The caller's identity comes from the Windows kernel (pipe client token), never from the message. Callers with a network logon are refused unless they are administrators, even though the pipe's access list already denies the network.
  - No secrets or credentials are stored.
  - There is no auto-updater, which is a common way attackers hijack software.
  - Apart from .NET, the only dependencies are two Microsoft packages (the service host and `TraceEvent`). There are no third-party libraries.
  - Binaries live in `Program Files`, settings in `HKLM`; both can only be changed by administrators.
- **Supply chain.** CI runs CodeQL with the extended security queries, and Dependabot watches the NuGet packages and GitHub Actions. Release MSIs are signed when signing secrets are configured.

## App rules and the network monitor (v0.3)

- **Rules only remove access.** The rule engine works out which traffic each app's rules block and writes *only block rules*, so an app rule can never open something Windows Firewall or the kill switch blocks. The compiler is checked in CI against the same evaluator the monitor uses, on thousands of random connections.
- **The service builds every rule itself.** The tray app sends a small JSON policy (≤ 64 KB, depth ≤ 16). The service validates every field (absolute `.exe` paths only, service names and package SIDs by strict pattern, ports, domains, addresses, at most 64 rules per app and 500 apps) and writes firewall rules through the COM API. Nothing reaches a shell, so there's no command injection.
- **Protected apps.** Callosotomy, Microsoft Defender, Windows Update, core networking services and system processes such as `svchost.exe` can't be given rules, so malware running as the user can't use app rules to blind the PC.
- **Tighten freely, loosen with permission.** On managed PCs ("Allow standard users to restore connections" off), standard users can block but not unblock. The service checks this exactly, by evaluating the old and new rules over every combination of address, port and protocol.
- **Privacy between users.** Standard users see only their own session's apps plus Windows services in the monitor. The service never tells a user whether a file exists.
- **Tamper-checked.** App rules are verified with the kill-switch rules and restored if edited or deleted.
- **Low overhead.** The connection table and the kernel network event stream (ETW) are only used while the monitor is open; the event session stops itself 30 seconds after the monitor closes, and its flow table is capped at 10,000 entries (new flows are dropped, never memory growth). Only addresses, ports, process IDs and byte counts are kept, for two minutes; packet contents are never seen. Domain names come from Windows' DNS cache using cache-only lookups (no network traffic). Instead of re-reading every rule every few seconds, the full rule check runs when Windows reports a firewall registry change, with a 30-second backstop.

## Known limitations

- **Local mode leaves some things reachable.** ICMP stays allowed, so IPv6 neighbour discovery to the gateway still works. Infrastructure IPs (gateways, DNS and DHCP servers) also stay reachable. A compromised router is therefore still reachable in Local mode. Use **Everything** if you suspect the router.
- **Internet mode blocks DNS to every address, including local DNS servers.** Local name resolution through the router stops working; mDNS and LLMNR still work.
- **What the tamper check covers.** Every 3 seconds it confirms that each rule exists, is enabled, blocks, and keeps its direction, protocol, profiles, ports and **exact address coverage**. It also confirms that Windows Firewall is on, that no network adapter has been excluded from it, and that Group Policy hasn't told it to ignore local rules. The bypass probe is the final backstop for anything below the firewall.
- **Domain rules trust DNS.** A domain rule applies to the addresses Windows resolved that name to. If an app connects before Callosotomy notices a new address (it checks every 5 seconds while domain rules exist), the first attempt may be decided by the app's default. A malicious DNS server could also point an allowed domain at another address, though only the app that rule belongs to would benefit.
- **Program rules match the file path.** Apps that install each update into a new folder (some Electron apps) need their rules re-created after updating. Matching by publisher signature needs the v0.4 filtering engine.
- **Service rules need a service SID.** Windows applies per-service firewall rules only to services that have a service SID; nearly all built-in services do.
- **Monitor coverage.** With the event stream running the monitor sees every TCP and UDP flow. If the stream can't start (event 1122), it falls back to the connection table, which misses UDP destinations and sub-second connections. Blocking is unaffected either way. UDP traffic from Windows services is attributed to the service through the UDP socket table; if that lookup fails it shows as `svchost.exe`.
- **The domain list uses an undocumented Windows function** (`DnsGetCacheDataTable`). If a future Windows removes it, names stop appearing in the monitor; rules by address keep working.
