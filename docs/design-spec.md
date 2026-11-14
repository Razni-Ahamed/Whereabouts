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
| Lookups made before Whereabouts started are not seen. | Running from boot (service) covers most cases; pre-filling from the Windows DNS cache at start is planned. |
| Event 3008 is written by the app itself, and **any program can write events under the DNS provider's ID**. Windows stamps every event with the writer's real process ID. | An app's own report can be a lie. Labels are *verified* only when the DNS service's event 3020, accepted only from the DNS Client service's process (found via the Service Control Manager), resolved the **same name** to the **same address**. Confirmations are kept per name and checked when the app's report arrives; the result is stored with it, so later floods cannot undo it. Otherwise labels are *unverified* (`?`). Forged service events are rejected and counted. |
| "Verified" proves the app did not invent the name/address pair. It does **not** prove who runs the server: DNS answers can themselves be false (malicious DNS server, poisoned resolver). | The UI and docs say "confirmed by the Windows DNS service", not "authentic". Recording which DNS server answered (events 3010/3011) is a possible later addition. |
| An attacker can point their own domain at any address (e.g. a popular CDN). | Their names never verify a *different* name. Inferred labels (`*`) are given only when exactly one name currently points at an address, so adding names removes the guess instead of steering it. Every name/address pair expires on its own. |
| Event 3020 ("query response") is logged by the DNS service with the same `QueryName`/`QueryResults` format, status in `Status`. | Used as the trusted source; inferred labels come only from it. |

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
- **Block app:** filter at the ALE connect layers (IPv4 + IPv6) with the app-ID condition from `FwpmGetAppIdFromFileName0`.
- **Block domain for an app:** WFP filters on IPs, not names. When the DNS map sees the blocked domain resolve, we add an IP filter for that app and remove it after the DNS TTL. Limitation: a connection racing the filter may slip through once. This is documented.
- All our filters live under **our own WFP provider and sublayer**, so they can be listed and removed cleanly, and an uninstall removes all of them.
- **No interactive “allow?” prompt before a connection** in v0.x. Holding a connection while asking the user requires a kernel callout driver. Instead we use *notify after*: the user sees the new connection and can block it from then on.

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
| Key protected with DPAPI for the **current account** (not machine scope) | Only the account running Whereabouts (later: SYSTEM) can decrypt it. |
| Data in `%ProgramData%\Whereabouts`, DACL `SYSTEM + Administrators`, inheritance removed | Set before any key or data is written. |
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

- **Named pipe** with a security descriptor that allows only SYSTEM and the interactive user who installed the app.
- The service checks the **connecting process's signature** and refuses unsigned clients in release builds.
- Messages are typed (shared `ipc` crate) and versioned. The UI can read data and send commands (block, unblock, mark as fine, delete data). It cannot run arbitrary queries.

### 5.9 UI

- **Tauri v2** (Rust backend, web frontend). Much smaller than Electron and uses the system WebView2.
- Screens: **Overview** (top apps, top companies, map of countries), **App detail** (domains, timeline, upload/download), **Alerts** (with reasons and actions), **Rules**, **Settings**, and **Privacy** (what is stored, retention, export, delete, list of the app's own outbound requests).
- The UI loads **no remote content**: no web fonts, no CDNs, no remote images.

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

---

## 7. Outbound requests made by the app itself

This is the complete list. Anything not on it is a bug.

| Request | Purpose | Data sent | Can disable? |
|---|---|---|---|
| Download list updates | Tracker, malware, geo databases | None beyond a plain HTTPS GET of a fixed URL (no IDs, no cookies, no custom headers) | Yes |
| Check for app updates | New version available | Same as above | Yes |

- Both downloads are **signed** (Ed25519, e.g. minisign); the public key is built into the app, and unsigned or invalid files are rejected.
- Downloads come from static files (e.g. GitHub Releases), so we run no server and see no logs.
- The Privacy screen shows when each request last happened.
- The app monitors **itself** like any other app, so users can check this table against what they observe.

---

## 8. Threat model

**What we protect:** the connection log. It reveals which apps a person uses, when, and (for browsers) which sites they visit.

| Adversary | Protection | Limitation |
|---|---|---|
| Other non-admin users or processes on the PC | DB file ACLs, DB encryption, named-pipe ACL + client signature check | – |
| Someone with the disk (stolen laptop) | SQLCipher + DPAPI | DPAPI machine-scope keys can be recovered from an unencrypted Windows disk. **We recommend BitLocker** and say so in the UI. |
| Malware with admin/SYSTEM rights | None. It can stop our service or read memory. | **Out of scope**, stated clearly. We may still observe its network activity before it acts. |
| Malware hiding inside a trusted process | Attributed to the host process | Stated limitation (§5.3) |
| Malware swapping a signed app's file to borrow its publisher | Each process is checked through one locked handle; results are tied to content hash and process instance, not path. The file checked is the process's image per the **kernel's own record** (`QueryFullProcessImageName`, which follows renames and which the process cannot edit, unlike its module list in memory), locked at the process's first network activity and re-confirmed with the kernel after locking | If the running file cannot be confirmed (the process already exited, or cannot be queried), the file at its start path is checked and the publisher is marked `?` (unconfirmed) |
| Malware faking DNS events to disguise its destinations | Labels verified against the DNS service's own events; forged service events rejected by process ID | A label the app reports for itself stays *unverified* (`?`) and is shown as such |
| Malware writing fake *kernel* network/process events under the kernel providers' IDs | Windows refuses user-mode registration of these provider IDs (`EventRegister` → access denied, even as administrator; verified on Windows 11 2026-11-12 and checked on every CI run). Whereabouts re-checks at start-up and warns if a Windows version allows it. | Kernel-mode malware (a driver) can do anything; out of scope like other administrator-level malware |
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
