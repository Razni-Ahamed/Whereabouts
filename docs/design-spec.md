# Whereabouts: Design Specification (Windows)

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Date** | 2026-11-11 |
| **Name** | Whereabouts |
| **Platform** | Windows first; Android later |
| **Language** | Rust |
| **License** | GPL-3.0-or-later |

---

## 1. Summary

**Whereabouts** is an open-source Windows app that shows **which app on your computer connects to which server, owned by which company, in which country, and how much data it sends** — and warns you when an app starts doing something new or unusual.

It does this **without ever reading the contents of your traffic**, and **without sending anything about you to anyone**. All processing happens on your own computer.

Example of what a user sees:

> **TikTok** uploaded 150 MB in the background at 03:12 to `x7fk2q.example` (unknown company, new country).
> This is unusual because: upload is 70× higher than normal · first time this app contacted this country · app was not in use.
> [Block this domain] [Block TikTok] [This is fine]

---

## 2. Goals and non-goals

### Goals
1. **Visibility** — For every app, show the domains, companies, and countries it talks to, when, and how much data it sends and receives.
2. **Detection** — Warn the user when an app contacts a known tracker or malicious server, or behaves differently from its own normal pattern.
3. **Control** — Let the user block an app from the internet, or block specific domains for an app.
4. **Explainability** — Every alert says *why* it fired, in plain language.
5. **Trust** — Users (and independent reviewers) can verify every claim in this document by reading the code.

### Non-goals
- **Reading, decrypting, or storing traffic contents.** The app never does TLS interception (“man-in-the-middle”) and never installs a root certificate.
- **Cloud service, accounts, or telemetry.** There is no backend.
- **Being an antivirus.** The app can highlight suspicious network behaviour, but it is not a malware scanner and does not claim to stop malware that already has administrator rights.
- **iOS support.** iOS does not allow third-party apps to attribute traffic to other apps.

---

## 3. Privacy principles (our contract with users)

These are rules, not goals. A change that breaks one of them must not be merged.

| # | Principle | How it is enforced |
|---|---|---|
| P1 | **Never read content.** | Capture sources give connection metadata only (§5.2). The optional SNI reader (§5.4) parses only the hostname field of the TLS ClientHello and discards everything else. |
| P2 | **Nothing leaves the device.** | No backend exists. The only outbound requests the app makes are listed in §7, and each can be turned off. |
| P3 | **No telemetry, no accounts, no crash uploads.** | No analytics SDKs. Crash reports are saved locally; the user may choose to attach one to a GitHub issue manually. |
| P4 | **Encrypted at rest.** | The local database is encrypted (SQLCipher). The key is protected by Windows DPAPI (§5.7). |
| P5 | **Data expires.** | Default retention: raw events 30 days, hourly summaries 180 days. User-configurable. One-click “Delete everything”. |
| P6 | **Offline enrichment.** | Company, tracker, and country lookups use databases bundled with the app. We never send a user's IPs or domains to a lookup service. |
| P7 | **Learning stays local.** | Behaviour profiles and ML models are trained and stored only on the device. No federated learning. |
| P8 | **Least privilege.** | Only the background service runs with elevated rights. The UI runs as the normal user. |
| P9 | **Verifiable.** | Open source, signed releases, documented build process, with reproducible builds as a goal. |

---

## 4. What the app sees and never sees

| Data | Seen? | Stored? | Notes |
|---|---|---|---|
| Which app (path, publisher signature) | ✅ | ✅ | |
| Remote IP address and port | ✅ | ✅ | |
| Domain name (from DNS lookup) | ✅ | ✅ | See browser note below |
| Domain name (from TLS SNI) | Optional | ✅ | Off by default in v0.1 (§5.4) |
| Bytes sent / received, timestamps | ✅ | ✅ | |
| Protocol (TCP / UDP) | ✅ | ✅ | |
| URL path, query string, headers | ❌ | ❌ | Encrypted; we never decrypt |
| Request/response bodies, messages, files | ❌ | ❌ | Encrypted; we never decrypt |
| Passwords, cookies, tokens | ❌ | ❌ | |

**Browser note:** for web browsers, the domain list is effectively the user's browsing history, which is very sensitive. By default, browser traffic is stored at the **registrable-domain level** (e.g. `example.com`, not `mail.example.com`), and the user can exclude browsers entirely. (See open decision D5.)

---

## 5. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                   Windows Service (LocalSystem, Rust)                │
│                                                                      │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────┐ │
│  │ win-capture  │──▶│  attribution  │──▶│ core                     │ │
│  │ ETW: network │   │ PID → app     │   │  • enrich (PSL, trackers,│ │
│  │ ETW: DNS     │   │ identity      │   │    geo/ASN – offline)    │ │
│  │ WFP events   │   └───────────────┘   │  • L1 lists              │ │
│  └──────────────┘                       │  • L2 profiles           │ │
│                                         │  • L3 anomaly model      │ │
│  ┌──────────────┐                       │  • alert scoring         │ │
│  │ win-firewall │◀── block rules ───────┤                          │ │
│  │ WFP filters  │                       └────────────┬─────────────┘ │
│  └──────────────┘                                    │               │
│                                         ┌────────────▼─────────────┐ │
│                                         │ store (SQLCipher)        │ │
│                                         └────────────┬─────────────┘ │
└──────────────────────────────────────────────────────┼───────────────┘
                                                       │ named pipe (ACL: SYSTEM + owning user)
┌──────────────────────────────────────────────────────▼───────────────┐
│                 Desktop UI (Tauri, runs as normal user)              │
│      Dashboard · Per-app view · Alerts · Rules · Settings · Privacy  │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.1 Components

| Component | Responsibility | Runs as |
|---|---|---|
| `service` | Hosts capture, analysis, storage, firewall. Starts at boot. | LocalSystem |
| `win-capture` | Reads connection and DNS events from ETW and WFP. | (in service) |
| `win-firewall` | Creates/removes WFP block filters. | (in service) |
| `core` | Platform-independent logic: enrichment, detection, scoring. **No `unsafe` code.** Reused later for Android. | (in service) |
| `store` | Encrypted persistence, retention, export, delete. | (in service) |
| `ui` | Tauri desktop app. Read-only view of data + sends user commands. | Logged-in user |

### 5.2 Capture: connection events

Sources (all metadata, no payload):

1. **ETW – kernel network provider** (`Microsoft-Windows-Kernel-Network`): TCP/UDP connect, send, receive events with process ID, addresses, ports, and byte counts.
2. **ETW – DNS client provider** (`Microsoft-Windows-DNS-Client`): DNS queries and answers with the process ID that asked.
3. **WFP network events** (`FwpmNetEventSubscribe`): allowed/blocked connection events with the app identity. Used to confirm blocks and to catch connections the ETW stream missed.

Rust libraries: `ferrisetw` for ETW consumption; the official `windows` crate for WFP and other Win32 APIs. `ferrisetw` is wrapped inside the `win-capture` crate so it can be replaced without touching the rest of the code.

Facts about the kernel network provider, verified against real events on Windows 11 (2026-11-11):

| Fact | Consequence |
|---|---|
| The event header's process ID is usually 4 (System). | The owning process comes from the `PID` field in the event payload. |
| Ports are stored in network byte order. | Ports are converted with `u16::from_be`. |
| TCP events and UDP *send* events store the remote end in `daddr`/`dport`; UDP *receive* events store it in `saddr`/`sport`. | Direction is decoded per event type. |
| Events 18/34 ("protocol copied data on behalf of user") repeat data already counted by receive events. | They are not captured, to avoid double counting. |
| DNS lookups are sent by the DNS Client service (`svchost.exe`), not by the app that asked. | Domain attribution must use the DNS Client ETW provider (§5.4), not port-53 traffic. |
| Programs cannot register the Kernel-Network or Kernel-Process provider IDs (access denied, even as administrator). | These events cannot be faked from user mode (§8). |
| Process-start events are logged under the **parent** process's ID; exits under the exiting process's. | The parent is available for free if needed later (e.g. "started by"). |

Events are aggregated in memory into **flows** (app + remote IP + port + protocol) and flushed to storage in short batches (e.g. every 5 seconds) to keep disk writes low.

### 5.3 Attribution: which app?

A process name alone is not trustworthy (malware can call itself `tiktok.exe`). An app identity is:

- **Executable path**
- **Publisher** from the Authenticode signature (`WinVerifyTrust`), e.g. “TikTok Pte. Ltd.”, or “unsigned”
- **File hash** (to notice when the binary changes, e.g. after an update)
- **Package family name** for Microsoft Store / MSIX apps

How it is implemented (`win-capture::identity`, verified on Windows 11, 2026-11-12):

| Fact | Consequence |
|---|---|
| Many Windows programs (e.g. `curl.exe`) have no embedded signature; their hash is listed in a signed security catalog. | Files without an embedded signature are looked up in the catalogs by hash (SHA-256, then SHA-1). A renamed copy is still recognised; a modified copy is not. |
| A file can be listed in several catalogs signed by different Microsoft certificates (`curl.exe`: "Microsoft Windows" and "Microsoft 3rd Party Application Component"). | The publisher shown is whichever catalog Windows returns first; both are genuine. |
| `WinVerifyTrust` may contact certificate servers by default. | Revocation checks are off and only cached certificates are used (`WTD_REVOKE_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`). A live test checks that no network traffic is made. |
| Process-start events give `\Device\HarddiskVolumeN\...` paths. | Mapped to drive letters with `QueryDosDevice`. |
| Hashing and signature checks take time. | They run on a background thread, only for processes that use the network. Signature results are cached by **content hash** (never by path), so the same program started many times is verified once. |
| Someone who can write to an app's folder could swap its file after it was checked, or between the hash and the signature check. | Each check opens the file once with sharing that blocks writes, renames and deletes, and does everything through that handle. Every process instance is checked on its own and its result is stored with it, not looked up by path. File IDs and timestamps are not trusted: they can be set back by a program with write access. |

Known hard cases (documented, handled best-effort):
- **`svchost.exe`** hosts many Windows services in one process. Where possible we resolve the owning service name; otherwise we show “Windows service host”.
- **Short-lived processes** may exit before we look them up; we cache process info at process-start time (ETW process events).
- **Code injection** (malware running inside a trusted process) will be attributed to the host process. This is a stated limitation.

### 5.4 Domain names

Most connections are made to IPs that were just returned by a DNS lookup. We keep a short-lived **per-process DNS map** (answer IP → queried name, with TTL) from the DNS ETW events and use it to label flows.

Gaps and how we handle them:
- **DNS-over-HTTPS in browsers** bypasses the Windows DNS client, so no DNS event appears. Fallback: show the IP with its network owner (ASN) from the offline database.
- **Optional SNI reader** (off by default, decision D4): reads only the hostname field from the first packet of a TLS connection, using a packet-capture driver. Even when enabled, the parser stops after the hostname and nothing else from the packet is kept. Note that Encrypted Client Hello (ECH) hides the SNI on some sites; this is expected.

Domains are grouped by **registrable domain** (“eTLD+1”) using the Public Suffix List, so `a.tiktokcdn.com` and `b.tiktokcdn.com` count as one place.

Facts about the DNS Client provider (`Microsoft-Windows-DNS-Client`), verified on Windows 11 (2026-11-12):

| Fact | Consequence |
|---|---|
| Event 3008 ("query completed") is logged in the requesting process, also for answers from the cache. Events 3009-3020 come from the DNS service (`svchost.exe`). | Only event 3008 is used; its header process ID is the app. |
| `QueryResults` is `;`-separated: CNAME aliases as `type: 5 <name>`, then addresses. Some IPv4 answers appear as IPv4-mapped IPv6 (`::ffff:a.b.c.d`). | Addresses are converted to plain IPv4 before matching. |
| The record TTL is not in the event. | Answers are kept for a fixed 30 minutes. |
| Lookups made before Whereabouts started are not seen, and Windows answers repeated lookups from its cache without confirming them again. | Running from boot covers most cases. Since v0.2 (N7) the engine also reads **Windows' DNS cache** when it starts and whenever a domain block is added or resumed (below). |
| Event 3008 is written by the app itself, and **any program can write events under the DNS provider's ID**. Windows stamps every event with the writer's real process ID. | An app's own report can be a lie. Labels are *verified* only when the DNS service's event 3020, accepted only from the DNS Client service's process (found via the Service Control Manager), resolved the **same name** to the **same address**. Confirmations are kept per name and checked when the app's report arrives; the result is stored with it, so later floods cannot undo it. Otherwise labels are *unverified* (`?`). Forged service events are rejected and counted. |
| "Verified" proves the app did not invent the name/address pair. It does **not** prove who runs the server: DNS answers can themselves be false (malicious DNS server, poisoned resolver). | The UI and docs say "confirmed by the Windows DNS service", not "authentic". Recording which DNS server answered (events 3010/3011) is a possible later addition. |
| An attacker can point their own domain at any address (e.g. a popular CDN). | Their names never verify a *different* name. Inferred labels (`*`) are given only when exactly one name currently points at an address, so adding names removes the guess instead of steering it. Every name/address pair expires on its own. |
| Event 3020 ("query response") is logged by the DNS service with the same `QueryName`/`QueryResults` format, status in `Status`. | Used as the trusted source; inferred labels come only from it. |

Implementation notes (v0.2, N7 better names, 2026-11-20):

| Decision | Reason |
|---|---|
| The **CNAME chain** of a confirmed answer (the names it points to) is kept with the name and travels with its label; an app's own (unconfirmed) aliases are never used | A tracker can hide behind a site's own name ("CNAME cloaking", e.g. `metrics.shop.example` → `shop.example.sc.omtrdc.net`). |
| The chain is used for the **owner** label (the first known company or tracker in name, then aliases), **tracker alerts** ("Adobe, hidden behind metrics.shop.example"), and **domain blocks** (a blocked domain is blocked when another name points to it; the learned address keeps the matched name, so it still matches after a restart). Connections show **"via <alias>"** when an alias revealed who is behind them | One chain, the same answer everywhere. |
| **Windows' DNS cache** is read (as `ipconfig /displaydns` does) at engine start and when a domain block is added or resumed: names from `DnsGetCacheDataTable`, records from `DnsQuery_W` with `DNS_QUERY_NO_WIRE_QUERY` (cache only, never the network) and without hosts-file entries. Treated as confirmed answers | The cache is filled by the DNS service. `DnsGetCacheDataTable` is undocumented, so it is looked up at run time; if it is missing, nothing is read. At most 4096 names. On some computers (some VPNs or encrypted-DNS setups) the cache stays empty; then this adds nothing. Its live test runs in CI. |

### 5.5 Enrichment (offline only)

| Lookup | Source (candidate) | Licence check needed |
|---|---|---|
| Domain → company, category (tracker, ads, CDN, analytics…) | DuckDuckGo Tracker Radar, Disconnect list, Exodus Privacy | **Yes** – some are non-commercial or copyleft (decision D3) |
| IP → country | DB-IP Lite (country) | Yes – attribution required |
| IP → network owner (ASN) | DB-IP Lite (ASN) or iptoasn.com | Yes |
| Known malicious domains/IPs | abuse.ch feeds (URLhaus, ThreatFox), others TBD | Yes |
| Domain grouping | Public Suffix List | MPL-2.0 |

All of these ship inside the app and update through signed downloads (§7).

**Decision D3 (2026-11-14):** Disconnect, DuckDuckGo Tracker Radar and Ghostery TrackerDB are all CC BY-NC-SA 4.0 (non-commercial) and are **not** used. Whereabouts uses EasyPrivacy (GPL-3.0-or-later / CC BY-SA 3.0) for "is this a tracker", its own `data/companies.tsv` (GPL) for the company behind well-known services, and DB-IP Lite ASN data for the network owner of every other address. Implemented in the `enrich` crate. During development the third-party files are downloaded by `scripts/update-data.ps1` and not committed; signed in-app updates come in v0.2.

| Fact (verified 2026-11-14) | Consequence |
|---|---|
| EasyPrivacy lists many trackers with request-type options, e.g. `\|\|google-analytics.com^$script,third-party,xmlhttprequest`. | Whole-domain rules whose options only name request types count; rules limited to particular websites (`$domain=`), paths, or with other options do not. |
| DB-IP Lite has gaps (e.g. no owner for some Cloudflare IPv6 ranges) and gives one country for addresses used worldwide. | Shown as `-`; country documented as an estimate for CDN addresses. |
| A domain name the app reported about itself may be fake (§5.4). | The OWNER column never takes the company from an *unverified* name; it falls back to the IP's network owner, which comes from the address itself. |

### 5.6 Blocking

- Blocking uses **user-mode WFP filters**. No custom kernel driver is needed, which avoids the cost and risk of a signed driver.
- **Block app:** filter at the ALE connect layers (IPv4 + IPv6) with the app-ID condition from `FwpmGetAppIdFromFileName0`, and at the ALE receive/accept layers (incoming; added 2026-11-22) with the same condition plus "not loopback". Without the incoming filters a blocked torrent client kept trading with peers that connected to it; loopback is left alone because an app's own window often talks to it that way (uTorrent Web's WebView2 does). The outgoing filters keep their pre-existing keys and conditions; the engine re-adds every app block at start-up so blocks made by 0.2.0 get the incoming filters.
- **Apps that show web pages through WebView2** (found with uTorrent Web, 2026-11-22): the pages, ads included, are fetched by `msedgewebview2.exe`, a file shared by every WebView2 app, so an app-ID filter on the app does not cover them, and WFP cannot tell one app's WebView2 from another's. Blocking an app therefore also sets WebView2's per-app `AdditionalBrowserArguments` policy (`HKLM\SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments`, value name = the app's file name) to `--proxy-server=http://127.0.0.1:9`: every request goes to a closed port on this computer, while loopback (the app's own local pages) is never proxied (`win-firewall/src/webview2.rs`). After each app block or unblock and on every "remove all" the values are synced with the app blocks in WFP; only values whose data is exactly ours are changed, so someone else's setting for an app is left alone, and the key is removed when it is empty. Applies from the app's next start (WebView2 reads it at start-up); the block dialog says so. Keyed by file name, so another program with the same file name also loses its WebView2 pages. Live-checked 2026-11-22 with uTorrent Web 1.6 (32-bit; `SOFTWARE\Policies` is shared between the 32- and 64-bit registry views): its WebView2 started with the argument and made no internet connections; its own window kept working.
- **Block domain for an app (or every app):** WFP filters on IPs, not names. When the Windows DNS service confirms that the blocked domain (or a subdomain) resolved, we add an IP filter for that app and remove it a day after the address was last seen (see the N2 notes below). Limitation: a connection racing the filter may slip through once. This is documented.
- All our filters live under **our own WFP provider and sublayer**, so they can be listed and removed cleanly, and an uninstall removes all of them.
- **No interactive “allow?” prompt before a connection** in v0.x. Holding a connection while asking the user requires a kernel callout driver. Instead we use *notify after*: the user sees the new connection and can block it from then on.

Implementation notes (v0.2, N1 blocking core, 2026-11-17):

| Decision | Reason |
|---|---|
| A block is either **a whole program** (filters at ALE connect v4 + v6 with the app-ID condition) or **one remote address**, for one program or for **every program** (decision D14) | Domain blocks become address blocks fed by verified DNS answers (N2). "Every program" exists because the user chose it; the guard-list below limits the damage of shared addresses. |
| **Persistent** provider, sublayer and filters (decision D10) | Blocks stay in force across restarts and while the service is stopped. Safety nets: the guard-list, `--unblock-all`, and uninstalling removes every filter, the sublayer and the provider. |
| **Guard-list**, checked before Windows is asked | Never blocked: core Windows programs in System32 (`svchost`, `lsass`, `services`, `wininit`, `winlogon`, `csrss`, `smss`, `dwm`, `spoolsv`), Microsoft Defender, Whereabouts itself; and addresses the network needs (loopback, local network incl. 100.64/10 and IPv6 ULA/link-local, multicast, broadcast, the configured DNS servers). |
| Filter keys are **derived from the rule** (SHA-256 of scope, rule and layer) | Blocking twice is harmless; unblocking needs no stored IDs. Paths are canonicalised and compared without case, as Windows does. |
| Each filter carries its rule as JSON in its provider data | The list of blocks can be read from WFP itself, even without the database. |
| Tests use a **separate WFP provider and sublayer** and a copy of curl | A failing test can never block real programs or delete real rules. Live-tested 2026-11-17: block/unblock a program, per-program address blocks, guard refusals. |

Implementation notes (v0.2, N2 saved rules and block commands, 2026-11-17):

| Decision | Reason |
|---|---|
| Rules are saved in the encrypted database (schema v2: `rules`, `settings`); WFP holds the filters | The database is the source of truth. At start the service makes WFP match it: it adds what is missing and removes what no rule asks for, so rules survive restarts and upgrades. Deleting the history keeps the rules. A 0.1 database is upgraded in place, keeping its history. |
| The firewall is **not touched until the first rule** | A user who never blocks anything gets no WFP entries at all. |
| A domain rule covers the domain and its subdomains, and is blocked by address, **only from answers the Windows DNS service confirmed** | An app cannot fake a lookup to get an innocent address blocked (worst for "every app" rules). |
| When a rule is added, or blocking resumes, the engine **replays the confirmed answers it remembers** (the last 30 minutes) | Windows answers repeated lookups from its DNS cache, and the DNS service confirms only answers it fetches from the network, so without this a site that is still cached would not be blocked until its cache entry expires. Found by the end-to-end test. |
| A site Windows cached **before the service started** is learned from Windows' DNS cache when the rule is added (since N7, §5.4); where the cache is bypassed, only when Windows looks it up again | Cached answers are never confirmed again by the DNS service. |
| An **"every app" domain rule never blocks an address that an unblocked domain was seen using** in the last day, and lifts its block when one is | Shared CDN addresses are not blocked for everyone, and the owner of a blocked domain cannot point it at someone else's server (a bank, an update service) to get that blocked for every app. The cost, accepted on purpose: a tracker that shares an address with an unblocked site is not blocked for every app (a per-app rule still blocks it), and an app that wants to evade an every-app domain block could point a domain of its own at the same address. Domain blocks are not a defence against a hostile app, which can also use fixed addresses or encrypted DNS; blocking the app itself is. Names covered by any domain rule never count as "elsewhere". |
| A learned address never lifts the block of an **address rule** for the same address and program | They share one filter. |
| Programs must be **on a local drive** (`X:\...` on a fixed, removable, optical or RAM drive), checked before any file system call; a path with `.`/`..` parts or a link or other reparse point anywhere along it is refused **without following it**, then the resolved path is checked again | The service runs as SYSTEM: opening `\\server\...` would connect to another computer and could offer it this computer's credentials. A symbolic link (any user can make one when Developer Mode is on) could lead there too; running programs' paths, as Windows reports them, never contain links. |
| Learned addresses are kept a **day after they were last seen** (refreshed after 12 h), **at most 256 per rule** | Cloud and CDN addresses are shared and reused; a short life limits blocking of unrelated sites. The time is stored in the filter itself, so learned blocks also survive a restart. |
| **Exemption filters** (allow, higher weight, our sublayer only) for `svchost`, `lsass`, `services`, `wininit`, `winlogon` and `spoolsv` | An "every app" address block can never cut off Windows' own networking. These allows only outrank our own blocks; they never weaken anyone else's firewall rules. |
| Rules are checked before anything is saved: the program must exist (its path is canonicalised), the guard-list is applied, domains must be plain lowercase names with a dot (at most 253 characters), at most 256 rules and 512-character paths | Nothing refused is ever saved, and the rule list always fits in one pipe message. |
| Block commands go over the pipe to the engine (`ListRules`, `AddRule`, `RemoveRule`, `SetBlockingPaused`); the command line (`--rules`, `--block-app`, `--block-domain`, `--block-ip`, `--for`, `--unblock`, `--pause-blocking`, `--resume-blocking`) uses them | One owner of the rules (the engine), the same checks for the app and the command line. Who may connect is unchanged (§5.8): administrators, SYSTEM and the user Whereabouts was installed for, through Whereabouts' own programs. **Changing** rules needs the desktop app or an administrator's command line (2026-11-22, below). |
| **Only the desktop app, or a client running as administrator, may change** what is blocked, deleted or warned about (`AddRule`, `RemoveRule`, `SetBlockingPaused`, `DeleteAll`, `DismissAlert`, `SetListUpdates`); reading stays open to the command line (2026-11-22) | Found in the security test: any program can start `whereabouts-service.exe` with any arguments, so `--pause-blocking` lifted every block with no prompt, and a blocked app (running as the user) could unblock itself. The service tells the clients apart when they connect (`peer::trusted_client`): the app is `whereabouts.exe` in the installation folder (it asks in a native dialog before blocking or deleting); a command line counts only if its process token is elevated (`TokenElevation`, read by the SYSTEM service). Code running as the user could still drive the app's window, which is far harder than one command. |
| `AddRule` answers whether the rule **already existed** (`RuleAdded { id, already }`); the app then offers no Undo (2026-11-22) | Rules are deduplicated, so blocking something already blocked returned the existing rule's ID, and the app's Undo removed the original block. |
| **Byte-identical copies of a blocked program are blocked too**, each with a saved rule of its own and a `BlockedCopy` notice (2026-11-22) | App rules match a path (WFP's app ID), so a copy or hard link elsewhere was not blocked, and an app in a user-writable folder could copy itself. When a program's identity check finishes (also unconfirmed ones, for processes that exit within a second: the path is what gets blocked, and the file now there is the blocked program), its SHA-256 is compared with the SHA-256 **pinned** when each app rule was made (saved as a setting keyed by path, removed with the rule; a file that cannot be read is pinned as "none", which never matches; rules saved before pinning are pinned once when the service starts, never when a copy shows up, a moment another program could choose), never with the file now at the rule's path: that path may be user-writable, and swapping another program's file in must not get that program blocked (found by the automated review of this change). Copies are added only while 64 rule slots stay free and at most 5 an hour, so programs cannot use up the user's rules. Not while paused. Accepted costs: the first connection may get through (block after seeing), and identical files elsewhere are blocked too (e.g. two identical `python.exe` launchers); the rule is visible and removable. A modified copy is a different program. |
| Rule targets are checked more strictly (2026-11-22): an app rule's file must start with the `MZ` program header, and a domain rule must not be a public suffix (`registrable_domain` is `None` for `co.uk`, `github.io`) | Security test L5: a key file was accepted as an "app", and `co.uk` as a domain, which as an every-app rule would block countless sites. (L1, a non-admin probing whether files exist through rule paths, is closed by the admin-or-app rule for changes.) |
| Rule IDs are never reused: the highest ID given out is kept as a setting and the next rule gets one more (2026-11-22) | SQLite reuses the highest free rowid, so a removed rule's ID went to the next rule, and an old ID (an Undo note, `--unblock 3`) could remove another rule. |
| A pipe client that waits longer than **2 minutes** for its next request is disconnected (a watchdog cancels the blocking read with `CancelIoEx`); time spent answering does not count (2026-11-22) | Only 4 clients are served at once, and a trusted client that connected and said nothing held its place forever. The app polls every few seconds and reconnects. |
| The app retries a request on a new connection only when the connection was **lost** (`ProblemKind::Lost`), never after an error answer (2026-11-22) | Retrying any error sent Delete everything or Add rule twice and doubled timeouts. |
| A data folder that a normal account created first is, if it is a real, empty folder, **removed and created anew**, secured from the start; it is never adopted, because a handle its maker opened earlier would keep its access after the permissions change (found by an automated review). Links, folders with content and folders held open are still refused (2026-11-22) | A user could create `%ProgramData%\Whereabouts` before install or after uninstall and keep the service from starting; an empty folder cannot hold planted files. |
| **Pause** lifts every block and keeps the rules; the choice is saved. `--unblock-all` is the emergency switch: it removes every block from WFP directly (it works even when the service is stuck or stopped) and saves "paused" | One command always gets the user's network back. |
| Uninstalling removes every filter, the sublayer and the provider; **updating keeps the blocks** (`--unregister` keeps them unless `--remove-blocks` or `--delete-data`) | No gap in blocking during an update; nothing left behind after an uninstall. Without the saved rules nothing could lift the blocks later, so deleting the data also removes them. |
| End-to-end test `scripts/blocking-e2e.ps1` (CI live job) | Runs the engine in console mode and checks app, domain and address rules, pause/resume, refusals and `--unblock-all` with a copy of curl. |

Implementation notes (v0.2, N3 rules in the app, 2026-11-17):

| Decision | Reason |
|---|---|
| **Block…** on every connection (Connections and Apps screens) offers: this domain for this app, this domain for every app (marked as a warning), this address for this app (when there is no domain), or the whole app; **Block app** on an app's page | The choices a person actually has in front of them; the "every app" choice is the one with side effects, so it says so. |
| The app's `add_rule` command shows **exactly what will be blocked in a native Windows dialog** (title, the program's full path for every rule that names one, the every-app and first-connection caveats) and blocks only if the user agrees | Same pattern as Delete everything: a bug or injected script in the web view cannot block anything silently. Lifting blocks (`remove_rule`, `set_blocking_paused`) needs no dialog: it is the safe direction, and "Undo" must be one click. Text in the dialog is made safe to show (no control or bidirectional characters). |
| Live flows carry the program's **full path** (`FlowView.path`, only when at most 260 characters; never shortened) | Rules need the path; a shortened path would name another program. |
| **Rules** screen: what is blocked, for which app, since when, how many addresses a domain rule blocks now, **Unblock**; **Pause all blocks / Resume**; a banner on every screen while paused; a note with **Undo** after each block | Blocking must always be visible and reversible. |
| Blocked-attempt counts are **not shown yet** | They need WFP's dropped-packet events (a system-wide setting and more native code); planned as a follow-up. |

### 5.7 Storage

- **SQLite + SQLCipher** via `rusqlite` (feature `bundled-sqlcipher`).
- The database key is random, generated at install, and protected with **DPAPI** (machine scope, since the service runs as LocalSystem).
- The database file is ACL-restricted to SYSTEM and Administrators.
- **Retention job** runs daily: deletes raw events older than the limit, keeps hourly summaries.
- **Export** (JSON / CSV) and **Delete everything** are available from the UI.

Implementation notes (M4, 2026-11-14):

| Decision | Reason |
|---|---|
| SQLCipher 4 via `rusqlite` with bundled SQLCipher and OpenSSL built from source | Standard, audited whole-file encryption. Needs Strawberry Perl to build on Windows (checked with a spike; Git's Perl cannot build OpenSSL). `sqlcipher-src` also ships LibTomCrypt, which could replace OpenSSL once the bindings support it. |
| Raw 256-bit key (`PRAGMA key = "x'…'"`) from the system RNG | No password, so no slow key derivation is needed. |
| Key protected with DPAPI for **this computer** (machine scope, since M5b) | The service (SYSTEM) and administrators' commands (`--history`, `--export`) share it. The key file sits in the SYSTEM/Administrators-only folder, which is what protects it on this computer. A key from M4 (account scope, `store.key`) is moved over once, by the account that made it (`--install` does this); an unreadable old key is an error, never silently replaced. |
| Data in `%ProgramData%\Whereabouts`, owner Administrators, DACL `SYSTEM + Administrators`, inheritance removed | Created atomically with that descriptor. Ordinary users can create folders in `%ProgramData%`, so an existing folder or key/database file is used only if it is **not a link or junction** and is **owned by SYSTEM or Administrators**; permissions are applied through a handle opened without following links. Otherwise Whereabouts refuses to start saving. |
| `PRAGMA secure_delete = ON`; delete-all ends with `VACUUM` | Deleted data does not linger in free pages. |
| v1 stores flows denormalised (app name, path, hash, signature with each flow) | Simple; an `apps` table can be split out when the UI needs it. |
| Browsers store the registrable domain only (D5) | A browser's domain list is browsing history. |

Main tables (simplified):

| Table | Contents |
|---|---|
| `apps` | app identity (path, publisher, hash, package name) |
| `flows` | app, remote IP, port, protocol, domain, start/end, bytes up/down, foreground flag |
| `hourly` | per-app, per-domain hourly totals (kept longer) |
| `profiles` | learned per-app baselines (§6.2) |
| `alerts` | alert, reasons, severity, user response |
| `rules` | user block/allow rules |

### 5.8 Service ↔ UI communication

Implemented in M5a (`win-pipe` and `ipc` crates); `--console` serves the pipe and `--status` is a client.

- **Named pipe** `\\.\pipe\Whereabouts`. Its permissions give full access to SYSTEM and Administrators and only read and write-data access to the account running Whereabouts (in service mode, the user who installed it): **not** generic write, which for a pipe includes the right to create more instances of it. **Network logons are denied** and remote clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`): the pipe works on this computer only.
- **No squatting:** the service creates the pipe as its *first instance* (`FILE_FLAG_FIRST_PIPE_INSTANCE`), so it fails, rather than silently sharing the name, if another program created it first. It always keeps one instance waiting, so the name stays its own while it runs. Programs running as the user cannot add instances of their own to receive clients (only SYSTEM, Administrators and the owner of what the service creates may).
- **Both sides check who is on the other end** before trusting it. The service asks Windows for the client's process ID and the client asks for the server's; each side then opens that process (so its ID cannot be reused during the check), rejects it if it started after the connection was made (a reused ID), locks its running file (the kernel's image path, re-confirmed after locking, as for app identity) and requires it to be **the same file** as its own, compared by volume and file ID, not by name. Other programs are disconnected before anything is read from them. A client also trusts the installed **service** by its process ID as the Service Control Manager reports it (only administrators can register a service named Whereabouts), because a normal user cannot open a SYSTEM service's process to look at its file. When the desktop app (a separate program) arrives in M6, the file check becomes "a Whereabouts program from the protected install folder, signed by the same publisher".
- **Clients cannot be impersonated:** clients connect at the *anonymous* security level, so even an impostor server could not act with the client's rights.
- **Messages** are typed (`ipc` crate) and versioned: each is a 4-byte length and JSON, at most 1 MiB, and larger lengths are refused before anything is read. Unknown message types and fields are refused. The first message must be `Hello` with the same protocol version. Limits are clamped (500 rows, 30 days of history). At most 4 clients are served at once.
- **Requests so far:** `Hello`, `Status` (counters and health), `LiveFlows` (current flows, largest first), `History` (per-app totals), `ExportPage` (all saved flows as CSV, in pages of at most 2,000 flows and 512 KiB, so even very long program paths fit a message) and `DeleteAll` (only with the exact confirmation phrase; carried out by the engine, which also forgets finished flows still waiting to be saved). Commands (block, unblock, mark as fine) come later. Clients cannot run arbitrary queries.
- **Trust levels travel as fields**, not as markers in text (`publisher_confirmed`, `domain_trust`), so a display that shortens text cannot cut them off.
- **Text from watched programs** (app file names, publisher names from code signatures) is made safe to show: control characters and invisible Unicode formatting characters (such as right-to-left overrides) are replaced with `?`, so a program cannot rewrite the terminal or disguise its name.
- **Limitation:** the pipe check stops *other programs* from connecting directly. Malware running as the same user could still start or control a Whereabouts client and read what that user can see in the app (their own flows and history). Protecting an account from programs running as that account is outside what Whereabouts can do.

### 5.9 UI

- **Tauri v2** (Rust backend, web frontend). Much smaller than Electron and uses the system WebView2.
- Screens: **Overview** (top apps, top companies, map of countries), **App detail** (domains, timeline, upload/download), **Alerts** (with reasons and actions), **Rules**, **Settings**, and **Privacy** (what is stored, retention, export, delete, list of the app's own outbound requests).
- The UI loads **no remote content**: no web fonts, no CDNs, no remote images.

Implementation notes (M6, 2026-11-14):

| Decision | Reason |
|---|---|
| **Svelte 5** + TypeScript, built with Vite (decision D8) | Compiles to small plain JavaScript with almost no runtime: few npm packages to trust. TypeScript stays on version 6 (code intelligence needs `tsserver.js`). |
| Look: a **night chart**: deep ink navy, frosted glass, a signal-teal accent for what is normal and amber only for what deserves a look; Space Grotesk (display) and Inter (text) | Suits what Whereabouts is (a map of where data goes) and stays calm and professional. The background is a globe of characters that shows where connections go (see the globe notes below); nothing to license or download. Fonts (OFL) and Lucide icons (ISC) are bundled. Motion stops when the system asks for reduced motion. |
| Strict content security policy: scripts and fonts from the app only; no network except Tauri's own IPC | Enforces "no remote content". Inline styles are allowed (Svelte sets style attributes); inline scripts are not. |
| The web view can call exactly two read-only commands, `live` and `history` (`AppManifest::commands`), and has no other Tauri permissions | Tauri v2 would otherwise allow every registered command. No file system, shell or network plugins. |
| The app's Rust side holds one pipe connection, checked with the shared `whereabouts-client` crate before anything is sent, and reopens it after a restart of the service | Same checks as `--status`: the server must be the installed service (Service Control Manager process ID) or the same program. |
| The service accepts the app because it runs from the **installation folder** next to the service (compared by folder ID; only administrators can write there) | The app is a different program file from the service, so "same file" alone would refuse it. Development builds elsewhere are refused; the UI shows **demo data** only in an ordinary browser, clearly marked. |
| The Apps screen groups connections by the program's **full path**, not its file name (2026-11-22) | Found in the security test: grouped by name, a copy of curl named `chrome.exe` in a temporary folder joined real Chrome's card and showed "Google LLC, signed" with Chrome's path, and "Block app" took the first path seen. Programs that share a name now get separate cards, each showing its folder (`ui/src/lib/apps.ts`). |
| Overlays opened from inside a card (the Block menu) are moved to the end of `<body>` (`ui/src/lib/portal.ts`) | A `.glass` card's `backdrop-filter` makes it the box that `position: fixed` children are placed in, so the menu opened from the long Connections table was centred about 1,500 px down, out of sight. |
| A **WebView2 process is credited to the app that started it** (only the installed runtime: `msedgewebview2.exe` under `Program Files (x86)` or `Program Files` `\Microsoft\EdgeWebView\Application\`, which only administrators can change, because any program can use that file name and would otherwise borrow its parent's name and publisher; nearest ancestor not named `msedgewebview2.exe`, parent start times checked, giving up rather than guessing); its connections take the app's name, path and identity and are marked `web_content` (2026-11-22) | `msedgewebview2.exe` is one Microsoft-signed file shared by every WebView2 app, so "msedgewebview2 contacted Google" named no app, and "Block" on such a row offered to block WebView2 for every app. Credited to the host, the app's publisher shows and blocking blocks the app, whose web content Whereabouts keeps offline (§5.6). |
| Confirmations that cannot be undone or that silence a warning (**Delete everything**, **Stop these warnings**) use Windows' task dialog with **Cancel as the default**; Escape and closing also mean Cancel (`crates/win-dialog`) (2026-11-22) | Tauri's dialog plugin always makes the first button (the action) the default, so Enter deleted everything. The block dialogs keep "Block" as the default: it is what the user just chose, and Undo exists. |
| The Privacy screen counts Whereabouts' own internet connections from the live data, by process ID: the app, every process it started (its WebView2 helpers, which a name match would miss), and the service (its ID from the Service Control Manager). A child counts only if it started after its parent, so a reused process ID cannot pull in a stranger. | "Whereabouts makes no requests" is shown as a measurement, not a claim. Checked 2026-11-16: the app's 6 WebView2 helpers made no internet connections. |
| Export and delete-all on the Privacy screen | The CSV is streamed over the pipe in pages and written **by the app**, as the user, to a place chosen in a native Save dialog: the SYSTEM service never writes to a path it is given, and the web view never supplies a path (both commands take no arguments). Before deleting, the app's Rust side asks in a native Windows dialog, so even a compromised web view cannot delete without the user. The dialog plugin's own commands are not available to the web view. |

Implementation notes (v0.2, N4 tray and notifications, 2026-11-17):

| Decision | Reason |
|---|---|
| The **app** shows notifications and lives in the **tray**; the service only reports | The service runs as SYSTEM in session 0 and cannot reach the user's desktop. |
| **Start at sign-in** is one value under the user's `HKCU\...\CurrentVersion\Run` (`"...\whereabouts.exe" --background`), set only when the user says yes: asked once on first run, suggested on (decision D13), changeable on the Privacy screen. A program turned off in Windows' "Startup apps" counts as off. Only the installed app can turn it on. Uninstalling removes the value | Windows' own list is the source of truth, so the app never claims something Windows will not do. A developer build must never register itself. The registry code lives in a small crate, `win-startup` (`unsafe` only for the registry calls). |
| Started at sign-in, the app shows **only the tray icon**; the window (and its web view) exists only while open, and closing it keeps the app in the tray only while start-at-sign-in is on (otherwise closing quits). A second start brings the running app forward (single instance) | Little memory in the background; no surprise background app for people who said no. |
| Tray menu: Open, Pause/Resume blocking, Close the app (Whereabouts keeps watching). Left click opens the window | The common actions without opening the window. |
| A background checker in the app asks the service every 5 s and notifies: **stopped watching** (service unreachable for 20 s) and **watching again**; **blocking still paused** after an hour; **new apps** | Health a security tool must surface; the rest are alerts (N5), which will use the same path. |
| If the pipe name is taken when the service starts, it **keeps trying every 5 s** in the background and starts answering (and the list updater) as soon as the name is free (2026-11-22) | Found in the security test: while the service was stopped (an update, or the 10 s restart after a failure), a normal user's program took `\\.\pipe\Whereabouts`; the new service ran without its pipe and never retried, so the app could not reach it until the next restart. The client already refuses to trust an impostor. |
| **New apps:** the service remembers every program that used the network (`known_apps`, schema v3, filled from the saved history when upgrading) and reports the first use of a new one as a notice (`Request::Notices`, at most 100 kept). Programs seen in the **first 24 hours** (and again after the history is deleted) are learned quietly. The app shows at most one new-app notification a minute, grouping the rest, and only notices that arrive while it runs | "Notify after" (§5.6) without a flood of notifications on day one. |
| Notifications **name no apps or sites unless the user allows it** (off by default) | Windows keeps notification history on disk and can show notifications on the lock screen. |
| The app's settings are a small JSON file of on/off choices in `%APPDATA%\org.whereabouts.app` | Per user, never captured data. |

Implementation notes (globe background, 2026-11-20):

| Decision | Reason |
|---|---|
| The background is a **globe drawn in monospace characters** on a canvas (`ui/src/lib/globe/`): a hand-written coarse land map and a table of country centre points, bundled | Interactive and calm; nothing to license or download. Hover stirs the characters, a click on empty background sends a wave, dragging spins the globe; the canvas never takes clicks from the UI. |
| **Only real activity:** countries with an **open** connection glow (the live list also keeps closed ones); an open flow (app + address) not listed in the last **10 minutes** flashes its country, amber when its owner is a tracker; at most 4 flashes per refresh. Nothing flashes on the first refresh, while the service is unreachable (the app then passes no flows, so nothing stale glows), or for **90 s** after the service starts (its uptime goes down), while it re-lists connections that were open all along. No marker for this PC | A privacy tool must not show made-up activity, and Whereabouts does not know where the user is. The live list is cut to the 500 largest rows, so a small new connection below the cut does not flash, and the 10-minute memory stops rows near the cut from flashing as they move in and out. |
| **Power:** the page pauses the globe while the window is minimised (the app's Rust side tells it with a fixed script call, so the web view needs no event permission) or hidden, and draws at 10 frames a second at rest, 30 while something moves. The app also leaves the state in a page variable and sends it again when the page finishes loading, so a page loaded while minimised starts paused. Flashes for connections that arrive while paused are dropped, not played later. Reduced motion (followed live): no loop and no flashes; redrawn only when the set of glowing countries changes. Resizing happens once per frame, keeps the characters that still fit, and follows a change of screen scale | WebView2 keeps drawing while minimised, and the frosted glass above the canvas is recomposited every frame. CSS animations and transitions are paused too while out of sight (`data-out-of-sight` on the root), and the status dot pulses three times instead of forever. Measured on an installed test build with live data: open, about 30% of one core over a minute with real flashes (24-27% at rest; 30-32% at rest with the endless pulse); minimised, about 2% (12-20% with CSS animations still running). 0.2.0's SVG background: 85-120%, also when minimised. |
| The screens' fade-in uses `animation-fill-mode: backwards` | With `both`, the finished opacity animation stayed in effect and made each screen a backdrop root, so the glass cards inside never blurred. |
| On a screen switch each card only **rises**; the **content inside** it fades in (`.screen-in` in `app.css`) | Opacity below 1 makes an element a backdrop root even mid-animation: fading the screen's wrapper left every card unblurred for the whole fade, and fading the card itself lets the sharp background show through it. This way the cards are frosted from the first frame. |

---

## 6. Detection and learning

### 6.1 Layer 1: known lists (from day one)

Matches each flow against bundled lists:

| Match | Severity |
|---|---|
| Known malware / command-and-control | **Critical** |
| Known tracker / analytics / ads | Info (shown in reports, not pushed as a notification by default) |
| Known CDN / cloud provider | None (labelled only) |

### 6.2 Layer 2: per-app behaviour profile

**Learning period:** the first 7 days after an app is first seen (configurable). During this time only Layer 1 alerts are shown.

**Profile contents (per app):**
- set of registrable domains, companies, countries, ports seen (with first-seen and last-seen dates)
- distribution of bytes up and down per hour (stored as rolling median and MAD)
- active hours histogram (24 buckets), foreground vs background share

**Sliding window:** profile entries not seen for 30 days expire, so the profile adapts to app updates.

**Signals:**

| Signal | Rule | Base weight |
|---|---|---|
| New domain | registrable domain not in profile | Low |
| New company | owner company not in profile | Medium |
| New country | country not in profile | Medium |
| Upload spike | robust z-score `(x − median) / (1.4826 × MAD)` > 6 **and** x > 10 MB/hour | High |
| Upload/download ratio flip | app that mainly downloads starts mainly uploading | Medium |
| Unusual time | activity in an hour bucket with < 1% of history, in background | Low |
| Random-looking domain | high character entropy + not on any list | Medium |
| Binary changed + new behaviour | file hash changed (unsigned or new publisher) and any new-destination signal | High |

The thresholds above are starting values and must be tuned in the lab (§6.6).

### 6.3 Layer 3: anomaly model (Isolation Forest)

**Why this model:** it is **unsupervised** (needs no labelled “bad” data, which we will never have from users), small, fast, and can train on the device.

**How it works (simple version):** the model builds many random trees that split the data at random points. Normal behaviour sits in crowded areas and needs many splits to isolate. Unusual behaviour is isolated after few splits, so it gets a high score.

**Feature vector**, per app per 5-minute window:

| Feature | |
|---|---|
| bytes up, bytes down (log-scaled) | |
| up/down ratio | |
| number of connections | |
| unique domains, new domains | |
| unique countries | |
| share of traffic to trackers | |
| share to unknown (unlisted) domains | |
| max domain entropy | |
| foreground flag | |
| hour of day (encoded as sin/cos) | |

**Training:**
- Per app, once it has enough history (e.g. ≥ 500 active windows). Apps with less data rely on Layers 1–2 only.
- Retrained nightly on the last 30 days. Standard settings to start: 100 trees, sub-sample size 256.
- Implementation: our own small Rust implementation in `core` (a few hundred lines, easy to audit), or a vetted crate.
- Every model stores its **version, feature-schema version, training window, and random seed**, so results can be reproduced.

**Explanation:** for a flagged window, report the 2–3 features that differ most from the app's normal range (e.g. “upload 70× normal”, “new country”).

**Ship gate:** Layer 3 is released only if lab evaluation (§6.6) shows it catches more injected problems than Layers 1+2 **without raising the false-alarm rate**. If it doesn't, it stays experimental.

### 6.4 Alert scoring and notification

- Signals from all layers for the same app within a short window are **combined into one alert**: the severity comes from the highest signal, raised one level when several medium signals happen together.
- Every alert stores its **reasons** (list of signals with values) and is shown with them.
- **Alert fatigue protection:** at most one pushed notification per app per hour; lower-severity alerts collect in a daily digest. Critical alerts always notify.

Implementation notes (v0.2, N5 Layer 1 alerts, 2026-11-19):

| Decision | Reason |
|---|---|
| **Malware/C2 list: Spamhaus DROP, downloaded by each computer itself** (decision D11; the download comes with N6, disclosed and switchable). Read from `lists\drop_v4.json` / `drop_v6.json` in the data folder; never bundled | Licences checked 2026-11-19: Feodo Tracker's CC0 grant conflicts with abuse.ch's "no copying" clause (and the list was empty); ThreatFox needs an account and is for not-for-profit use; Maltrail's trails need a written agreement to redistribute; C2IntelFeeds is non-commercial; C2-Tracker has no licence; HaGeZi's and DigitalSide's upstream terms are unclear. Spamhaus lets each user download DROP (credit required, at most once a day) but not redistribute it. Written permission for Feodo Tracker is being asked for. |
| Alerts: **bad network** (DROP range, *high*), **tracker contact** (EasyPrivacy, *info*), **faked DNS events** and **unattributed traffic** (*medium*) | Layer 1 of §6.1 plus the evasion signals v0.1 already counted. Unprotected kernel events stay a status warning: the service (SYSTEM) cannot judge it for the user's account. |
| Only domains confirmed by the Windows DNS service (or seen for the same address in its answers) raise tracker alerts | What an app says about itself is not evidence. |
| One alert per app and tracker (or address) per day; evasion alerts at most once an hour; each flow is checked once a day | Alerts stay readable; the engine's work stays small. |
| Alerts are stored encrypted (schema v4), kept 90 days, deleted with "Delete everything". **Dismiss** clears an alert and nothing more (it is raised again next time); **"This is fine"** marks an alert seen; for trackers and bad networks it also stops alerts for the same app and tracker (or listed range), kept like rules, but only when the program's full path is known (a file name could be any program). The list returns alerts above info first, so tracker contacts can never push a serious alert out of it | The user decides what is normal. Stopping warnings about a bad network is confirmed in a native Windows dialog, so the web view cannot silence them on its own. |
| Notifications: *medium* and higher, at most one per app (or kind of system alert) an hour, *critical* always; trackers only in a **daily summary** (user's choice). No app, site or tracker names unless allowed | §6.4 alert fatigue protection; lock-screen privacy. |
| Spamhaus is credited in the app's footer whenever DROP is in use, and in every alert it raised | Spamhaus' DROP terms ask for credit when DROP is used in a product. |

### 6.5 User feedback

- **“This is fine”** adds the destination to the app's profile and suppresses that signal.
- **“Block”** creates a WFP rule (§5.6).
- **Profile review:** the user can see what was learned for each app and **reset** it. This matters if malware was already present during the learning period.

### 6.6 Evaluation (lab, never on user data)

**Lab dataset:**
- Windows VMs running scripted sessions of popular apps → **normal** behaviour.
- **Injected scenarios:** large hidden uploads, beaconing (regular small connections), random-looking domains, connections to known-bad hosts, a renamed binary posing as a popular app.
- Optional: replay public malware-traffic research datasets after converting them to our event format.

**Metrics:**
- **False alarms per user per week** (medium severity and above). This is the most important trust metric. Initial target: ≤ 1.
- **Detection rate** on injected scenarios, per scenario type.
- **Time to detect** (minutes from the start of a scenario to the alert).

**Baselines:** Layer 1 only → Layers 1+2 → Layers 1+2+3. Each layer must beat the previous one to ship.

The lab harness lives in `/lab` and may use Python for analysis and charts. Python is never part of the shipped app.

Implementation notes (v0.3, L0 lab harness, 2026-11-21; see `lab/README.md`):

| Decision | Reason |
|---|---|
| Sessions run on **GitHub-hosted Windows runners** (fresh VM per job), workflow `lab.yml`, by hand or weekly, never on pull requests | The development PC (Windows 11 Home) has no Hyper-V (D18); runners give a clean machine per session and never touch user data. |
| Apps run **logged out**, launch only; each app's terms are recorded in `lab/APPS.md`; Steam is left out | No accounts or tokens in CI; Steam's terms assume an account and ban non-human-controlled use. |
| The capture is the engine's own **CSV export** plus `session.json` (apps, versions, SHA-256, health counters from `--status --json`, live-scenario labels); GitHub's runner agents are dropped from the data | One format, no new capture code in the app; the runner's own agents exist on no real PC. |
| Short sessions are **stitched into simulated user-weeks** (7 learning days, 7 test days) with **disjoint learning and test pools** per persona | "False alarms per user-week" needs weeks; sharing sessions between a user's two weeks would hide novelty-based false alarms (leakage). |
| Live scenarios only reach example.com (listed as a test `SBL-LAB` entry next to Spamhaus' DROP, downloaded per run and never uploaded) and wikipedia.org (from a renamed copy of curl); upload, beaconing, random domains and swapped programs are **synthetic rows** with labels | Nothing risky is contacted and nothing is uploaded to third parties. |
| Detection runs through the **shipped code**: the Layer 1 detector moved into `whereabouts-detect`, and the app's notification rule into `whereabouts_ipc::notify`; `whereabouts-lab-replay` (never bundled) replays each simulated user with a fresh encrypted store | The lab measures what users get, not a re-implementation. |
| Scoring: a **medium-or-higher** alert for the same user and app within a scenario's window + 1 h detects it; a repeat the same day after a detection counts as covered; every other test-week alert is a false alarm | Tracker contacts (info) are background, not detections; the detector alerts once per app and address a day. |
| Known gaps: no process IDs or DNS alias chains in the export; new-app notices not measured | Listed in every report. |

First run (2026-11-21, run 44848943887; 3-minute sessions, 2 per persona, 1 simulated user per persona — a smoke run, not a measurement): **Layer 1 baseline** — 0.00 false alarms per user-week at medium and up; known-bad host detected in every instance; upload, beaconing, random domains, renamed and swapped programs: 0 % (expected: Layer 1 only knows lists; these are Layer 2's job).

---

## 7. Outbound requests made by the app itself

This is the complete list. Anything not on it is a bug.

| Request | Purpose | Data sent | Can disable? |
|---|---|---|---|
| Download list updates (github.com, Whereabouts' releases) | Tracker, company, country and network lists | None beyond plain HTTPS GETs of fixed URLs (no IDs, no cookies; the only header of our own is the user agent `Whereabouts list updates`) | Yes |
| Download Spamhaus DROP (spamhaus.org) | Networks run by criminals (alerts); Spamhaus does not allow redistribution, so each computer fetches it | Same as above, at most once a day | Yes |
| Check for app updates | New version available | Same as above | Yes (planned) |

- Whereabouts' own downloads are **signed** (Ed25519); the public key is built into the app, and unsigned or invalid files are rejected. Spamhaus DROP comes over HTTPS straight from Spamhaus and is only parsed, never executed.
- Downloads come from static files (GitHub Releases, Spamhaus' public files), so we run no server and see no logs.
- The Privacy screen shows when each request last happened.
- The app monitors **itself** like any other app, so users can check this table against what they observe.

Implementation notes (v0.2, N6 list updates, 2026-11-20):

| Decision | Reason |
|---|---|
| **Nothing is downloaded until the user answers the app's question** (both switches suggested on; decision D12), asked once after the tray question and changeable on the Privacy screen. Two switches: Whereabouts' lists, and Spamhaus | The service starts at install, before anyone sees an explanation. A user who never opens the app never downloads anything. |
| A **bundle** is the data files plus a manifest (format, sequence, date, each file's size and SHA-256, sources) and an **Ed25519 signature over the manifest's exact bytes** (`whereabouts-data-bundle` crate, `ed25519-dalek`). Manifests with unknown fields, missing, extra or repeated files, or files over 64 MB are refused | The signature covers what will be installed; nothing outside the four known file names can be written. |
| The private key exists only as the GitHub Actions secret `WHEREABOUTS_DATA_SIGNING_KEY` and the maintainer's offline backup. The tool refuses to sign with a key that does not match the built-in public key | A leaked or lost key means a new key in an app update (see the threat model, §8). |
| CI (`.github/workflows/data.yml`) builds a bundle weekly: release `data-<sequence>` holds the files; `data-latest` holds only the newest manifest and signature, uploaded last. Clients fetch files from the release named in the signed manifest | Clients never see a half-published bundle; old bundles stay fetchable (the newest four are kept). |
| The service checks once a day (first 90 s after start, then every 15 min whether something is due; failures retried after 6 h). A bundle must have a **higher sequence** than the one in use; files go to `data.new`, are checked against the manifest, and replace `data` as a whole; then the engine reloads, keeping the old data if the new set is incomplete | No replay of old bundles; no half-updated data. |
| Spamhaus DROP: at most once a day ("Check now" at most hourly); refused unless it parses into at least one range; turning it off deletes the copy | Spamhaus' terms; a stale threat list is worse than none. |
| HTTPS only, through **Windows' own TLS and certificate store** (`ureq` with native-tls), redirects at most 5, 3-minute timeout, size limits on every response | Certificates are checked the way Windows checks them; no extra crypto library. |

---

## 8. Threat model

**What we protect:** the connection log. It reveals which apps a person uses, when, and (for browsers) which sites they visit.

| Adversary | Protection | Limitation |
|---|---|---|
| Other non-admin users or processes on the PC | DB file ACLs, DB encryption, named-pipe permissions (SYSTEM, Administrators and the account running Whereabouts; no network access) + client check (must be the same program file, compared by file ID) | Malware running as the *same* user can start or control a Whereabouts client and read what that user can see (§5.8) |
| A program posing as the Whereabouts service on its pipe | The service creates the pipe as its first instance or fails; clients check the server's program file before sending anything, and connect at the anonymous level so they cannot be impersonated | – |
| A program disguising its name or publisher with control or invisible Unicode characters | Replaced with `?` before display; domain names are limited to plain ASCII | – |
| Someone with the disk (stolen laptop) | SQLCipher + DPAPI | DPAPI machine-scope keys can be recovered from an unencrypted Windows disk. **We recommend BitLocker** and say so in the UI. |
| Malware with admin/SYSTEM rights | None. It can stop our service or read memory. | **Out of scope**, stated clearly. We may still observe its network activity before it acts. |
| Malware hiding inside a trusted process | Attributed to the host process | Stated limitation (§5.3) |
| Malware swapping a signed app's file to borrow its publisher | Each process is checked through one locked handle; results are tied to content hash and process instance, not path. The file checked is the process's image per the **kernel's own record** (`QueryFullProcessImageName`, which follows renames and which the process cannot edit, unlike its module list in memory), locked at the process's first network activity and re-confirmed with the kernel after locking | If the running file cannot be confirmed (the process already exited, or cannot be queried), the file at its start path is checked and the publisher is marked `?` (unconfirmed) |
| Malware faking DNS events to disguise its destinations | Labels verified against the DNS service's own events; forged service events rejected by process ID | A label the app reports for itself stays *unverified* (`?`) and is shown as such |
| Malware writing fake *kernel* network/process events under the kernel providers' IDs | Windows refuses user-mode registration of these provider IDs (`EventRegister` → access denied, even as administrator; verified on Windows 11 2026-11-12 and checked on every CI run). Whereabouts re-checks at start-up and warns if a Windows version allows it. **SYSTEM is allowed** to register them (seen with the installed service, 2026-11-14), so the service's own check can be a false alarm; the app and `--status` repeat the check from the user's ordinary account, which is the vantage point that matters. | Kernel-mode malware (a driver) can do anything; out of scope like other administrator-level malware |
| Malware flooding the flow table to hide traffic | Per-process flow limits; excess traffic goes to a per-process overflow flow, so bytes stay visible and attributed | With thousands of processes flooding at once, the overflow limit is exhausted and further traffic lands in one shared flow without per-process attribution. This is counted and reported as a possible evasion attempt. |
| Tampered list update | Signature check with built-in key | Key compromise → rotate key in an app update |
| Supply-chain attack on dependencies | `Cargo.lock` committed, `cargo-audit` + `cargo-deny` in CI, minimal dependencies, review of new crates | – |
| **Us, the developers** | No backend, no telemetry, open source, signed and documented builds, reproducible builds goal | – |

---

## 9. Security engineering practices

- `#![forbid(unsafe_code)]` in `core` and `store`. `unsafe` is allowed only in the thin Windows FFI crates, with each block commented.
- All input from the network (DNS names, SNI) is treated as untrusted: length-limited, validated, never used in file paths or SQL strings (parameterised queries only).
- UI renders domain names as text only (no HTML injection); strict Content Security Policy in Tauri; Tauri capabilities limited to what the UI needs.
- CI: `cargo fmt`, `clippy -D warnings`, tests, `cargo-audit`, `cargo-deny` (licences + advisories), secret scanning.
- Releases: code-signed installer (MSI), checksums, and a public changelog.
  - Signing is built in but needs a certificate (decision D7): `scripts/build-release.ps1 -SignThumbprint <SHA-1>` (or `WHEREABOUTS_SIGN_THUMBPRINT`) signs the service with signtool, Tauri signs the app, uninstaller and installer, and the build fails unless all are signed by that certificate (RFC 3161 timestamps). Until then releases are unsigned: SmartScreen warns, and Whereabouts lists its own service as UNSIGNED (security test, 2026-11-22).
- `SECURITY.md` with a private vulnerability reporting route (GitHub private advisories).

---

## 10. Repository layout (proposed)

```
/
├── crates/
│   ├── core/          # detection, scoring, profiles, anomaly model (platform-independent)
│   ├── enrich/        # PSL, tracker DB, geo/ASN lookups (offline)
│   ├── store/         # SQLCipher persistence, retention, export
│   ├── ipc/           # message types shared by service and UI
│   ├── win-capture/   # ETW + WFP event consumers
│   └── win-firewall/  # WFP filter management
├── service/           # Windows service binary
├── ui/                # Tauri app (Rust + web frontend)
├── data/              # bundled list snapshots + licences
├── lab/               # evaluation harness and scenarios (not shipped)
├── docs/              # this spec, privacy policy, architecture notes
├── .github/           # CI workflows, issue templates
├── LICENSE
├── PRIVACY.md         # short, plain-language version of §3, §4 and §7
├── SECURITY.md
└── README.md
```

Rust **Cargo workspace**; one `Cargo.lock` at the root.

---

## 11. Roadmap

| Version | Theme | Scope |
|---|---|---|
| **v0.1** | *See* | ETW capture, app attribution, DNS mapping, offline enrichment, encrypted storage, retention, read-only dashboard, Layer 1 labels |
| **v0.2** | *Control* | WFP blocking (per app, per domain), Layer 1 alerts, Windows notifications, export / delete-all |
| **v0.3** | *Learn* | Layer 2 profiles, explained alerts, feedback, profile review/reset, lab harness v1 |
| **v0.4** | *Detect* | Layer 3 anomaly model, released only if it passes the ship gate (§6.3) |
| **v1.0** | *Trust* | Signed installer, external security review, full docs, reproducible-build instructions |
| Later | | Optional SNI reader, Android app (VpnService + shared `core`), encrypted PC↔phone sync over local network |

---

## 12. Supported environment

- Windows 10 22H2 and Windows 11, x64 (ARM64 later). (Decision D6.)
- Requires administrator rights **once**, at install, to register the service.
- Implemented in M5b: `--install` copies the program and offline data to `%ProgramFiles%\Whereabouts` (only administrators can change it, so the SYSTEM service never runs a user-replaceable file; the path comes from Windows' known-folder API, not an environment variable), registers the **Whereabouts** service (LocalSystem, automatic start, restart after a failure: 10 s, then 60 s, then stay stopped; count reset daily) and starts it. The installing user becomes the pipe's client account (`--service --client-user <SID>` in the service's command line, which only administrators can change). The service saves its last flows on Stop and on pre-shutdown, and writes its own warnings (never captured data) to `service.log` in the data folder, capped at about 1 MB. `--console` refuses to run while the service runs, because starting a capture ends the other one's event session. `--uninstall` stops and removes the service and the program folder and keeps saved data unless `--delete-data` is given (the database is wiped before the folder is deleted).
- WebView2 runtime (pre-installed on Windows 11; bundled bootstrapper for Windows 10).

---

## 13. Open decisions

| ID | Decision | Options | Suggestion |
|---|---|---|---|
| D1 | Project name | **Decided: Whereabouts** | Still check trademark, domain, GitHub org and crates.io name before v0.1 |
| D2 | Licence | **Decided: GPL-3.0-or-later** | Confirm each bundled data list is compatible before adding it (D3) |
| D3 | Tracker data source | Tracker Radar · Disconnect · Exodus · our own list | Check each licence for redistribution and commercial terms before bundling |
| D4 | SNI reader | Off / opt-in / on | **Opt-in, after v0.2**, because it needs a packet-capture driver and reads packet bytes |
| D5 | Browser traffic detail | Full domain · registrable domain · exclude | **Registrable domain by default**, user can change |
| D6 | Minimum Windows version | Win 10 22H2+ · Win 11 only | Win 10 22H2+ for reach, unless an API forces Win 11 |
| D7 | Code-signing route | Commercial certificate · free OSS signing programme (e.g. SignPath Foundation) | Apply to an OSS programme early; approval takes time |

---

## 14. Glossary

| Term | Meaning |
|---|---|
| **ETW** | Event Tracing for Windows: a built-in Windows system that reports events (like network connections) to listening programs. |
| **WFP** | Windows Filtering Platform: the Windows API used to allow or block network traffic. Windows Firewall is built on it. |
| **DNS** | The “phone book” lookup that turns a name like `tiktok.com` into an IP address. |
| **SNI** | Server Name Indication: the website name sent unencrypted at the start of most HTTPS connections. |
| **ECH** | Encrypted Client Hello: newer TLS feature that hides the SNI. |
| **eTLD+1 / registrable domain** | The part of a domain you can register, e.g. `tiktokcdn.com` from `v16.tiktokcdn.com`. |
| **ASN** | Autonomous System Number: identifies the network (usually a company) that owns an IP range. |
| **DPAPI** | Windows Data Protection API: encrypts secrets using keys managed by Windows. |
| **MAD** | Median Absolute Deviation: a measure of “typical spread” that isn't thrown off by a few extreme values. |
| **Isolation Forest** | An unsupervised ML model that finds unusual data points by how quickly random splits isolate them. |
