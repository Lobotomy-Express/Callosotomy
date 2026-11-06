# Threat model

This is an honest account of what Callosotomy defends against, what it doesn't, and why the design looks the way it does.

## Goal

When a person or an administrator decides a Windows machine might be compromised, cut its network access **immediately, reliably and verifiably**, and keep it cut until someone with the right permission restores it.

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
| Malware that creates a fake control pipe | No | The service claims the pipe name first. The tray app checks that the process on the other end is the registered service executable and refuses anything else. |
| Malware with **administrator** rights | **Yes, eventually** | Admins can stop services, edit firewall rules or uninstall. Callosotomy restores tampered rules within about 3 seconds, logs events 1200, 1201 and 1300, and shows **Bypassed** if a test connection gets out. This raises the cost and makes the attack noisy, but can't prevent it. |
| Kernel-mode malware or a malicious network driver | **Yes** | Out of scope for any user-mode tool. The probe may still catch it. |

**The bottom line:** a software kill switch on a fully compromised machine is a speed bump, not a wall. The only kill that can't be bypassed is physical: pull the cable, disable the switch port, or quarantine the machine at the router. The README says so too.

## Design decisions

- **Block rules, not allow rules.** In Windows Firewall a block rule always beats an allow rule, so nothing another program allows can punch through.
- **Fail closed.** Stopping or crashing the service never removes rules. The saved mode is re-applied at startup, so a reboot doesn't lift a block either. Rules are only removed by an explicit restore, or by a full uninstall run by an administrator.
- **No gap when switching modes.** New rules are added before old ones are removed.
- **DNS closed in Internet mode.** Otherwise malware could tunnel data out through the router's DNS forwarder.
- **Existing connections are cut.** IPv4 TCP sessions to blocked addresses are torn down immediately. Windows has no equivalent API for IPv6 or UDP flows; those hit the new rules on their next packet.
- **A small attack surface:**
  - The service opens no network ports and makes no web requests. The only outbound traffic is the optional bypass probe, a bare TCP connect with no payload, sent only while the internet is supposed to be blocked.
  - The whole control protocol is 5 fixed ASCII commands of at most 128 bytes. Anything else is rejected and logged. Slow clients are dropped after 3 seconds.
  - The caller's identity comes from the Windows kernel (pipe client token), never from the message.
  - No secrets or credentials are stored.
  - There is no auto-updater, which is a common way attackers hijack software.
  - Apart from .NET, the only dependency is Microsoft's own hosting package. There are no third-party libraries.
  - Binaries live in `Program Files`, settings in `HKLM`; both can only be changed by administrators.
- **Supply chain.** CI runs CodeQL with the extended security queries, and Dependabot watches the NuGet packages and GitHub Actions. Release MSIs are signed when signing secrets are configured.

## Known limitations

- **Local mode leaves some things reachable.** ICMP stays allowed, so IPv6 neighbour discovery to the gateway still works. Infrastructure IPs (gateways, DNS and DHCP servers) also stay reachable. A compromised router is therefore still reachable in Local mode. Use **Everything** if you suspect the router.
- **Internet mode blocks DNS to every address, including local DNS servers.** Local name resolution through the router stops working; mDNS and LLMNR still work.
- **The rule check has blind spots.** It confirms each rule exists, is enabled, blocks, and keeps its direction, protocol and profiles. It does not compare long address lists byte for byte. The bypass probe is the backstop for subtler edits.
- **Group Policy can override local rules.** If a domain GPO tells Windows Firewall to ignore local rules ("Apply local firewall rules: No"), Callosotomy's rules won't apply. The probe will detect it and report **Bypassed**.
