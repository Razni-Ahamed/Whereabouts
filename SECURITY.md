# Security policy

Whereabouts sees metadata about every network connection on a computer, so we take security reports seriously.

## Reporting a vulnerability

**Please do not report security problems in public issues, discussions or pull requests.**

Report them privately through GitHub:
**[Report a vulnerability](https://github.com/Razni-Ahamed/Whereabouts/security/advisories/new)**

Please include:

- what the problem is and what an attacker could do with it
- steps to reproduce, or a proof of concept
- the Whereabouts version (or commit) and Windows version

We aim to acknowledge reports within 7 days and will keep you updated until the problem is fixed. With your permission, we will credit you in the release notes.

## What we consider a vulnerability

- Any way for another user, a non-admin process or a remote party to **read Whereabouts' data**
- Any way to make Whereabouts **send data off the device** that [PRIVACY.md](PRIVACY.md) says it does not
- Any way to **tamper with block rules, list updates or app updates**
- Memory-safety bugs, injection bugs or privilege escalation in the service
- Any case where Whereabouts **reads or stores traffic contents**

## Known limitations (not vulnerabilities)

These are documented in the [threat model](docs/design-spec.md#8-threat-model):

- Malware that already has administrator rights can stop or bypass Whereabouts.
- Code injected into a trusted process is attributed to that process.
- Without BitLocker, someone with physical access to the disk may be able to recover the database key.

## Supported versions

Whereabouts has not had a release yet. Once it does, security fixes will go into the latest release.
