# Security policy

Callosotomy is security software, so we treat vulnerabilities in it as high priority.

## Reporting a vulnerability

**Please don't open a public issue.** Use GitHub's private reporting instead: on this repository, go to **Security → Report a vulnerability**.

Include:
- the version and the Windows build;
- what you did, what you expected and what happened;
- whether it needs admin rights, a local user account or network access.

We aim to acknowledge reports within **3 days** and to ship a fix for confirmed high-severity issues within **30 days**. We're happy to credit you in the release notes.

## In scope

- Lifting or weakening a block without the permissions that policy requires.
- Making the app or service report "protected" or "OK" when traffic is flowing.
- Privilege escalation through the service, the named pipe or the installer.
- Impersonating the control channel, or tricking the tray app into trusting a fake service.
- Crashing the service in a way that opens the network. (A crash should leave the block in place.)

## Out of scope

These are documented limits, not vulnerabilities. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- An attacker who already has **administrator, SYSTEM or kernel** access on the machine can disable any software on it, including this one. We detect and report this where we can.
- Traffic sent through an interface or driver that sits below Windows Filtering Platform.

## Supported versions

Only the latest release gets security fixes.
