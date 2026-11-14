# Whereabouts

**See where your apps send your data, without anyone seeing the data itself.**

Whereabouts is a free, open-source app for Windows that shows **which app on your computer connects to which server, owned by which company, in which country, and how much data it sends**. It warns you when an app starts doing something new or unusual, and lets you block it.

It never reads the contents of your traffic, and it never sends anything about you to anyone. Everything happens on your own computer.

> **Status: early development.** There is nothing to install yet. Follow the [roadmap](#roadmap) or read the [design spec](docs/design-spec.md).

---

## What it will show you

> **TikTok** uploaded 150 MB in the background at 03:12 to `x7fk2q.example` (unknown company, new country).
> This is unusual because: upload is 70× higher than normal · first time this app contacted this country · app was not in use.
> **[Block this domain]** **[Block TikTok]** **[This is fine]**

- **Per app:** every domain it talks to, the company behind it, the country, and how much it uploads and downloads
- **Trackers:** which ad, analytics and tracking companies each app contacts
- **Alerts:** when an app contacts a known malicious server, or behaves differently from its own normal pattern, with the reasons explained
- **Control:** block an app from the internet, or block a single domain for one app

## Our privacy promises

These are rules, not goals. Code that breaks one of them is not merged. The full list is in [PRIVACY.md](PRIVACY.md).

| Whereabouts **does** | Whereabouts **never** |
|---|---|
| Record which app connects where, when, and how much | Reads, decrypts or stores what is *inside* your traffic |
| Process and store everything on your own computer | Sends your data to us or anyone else (we have no servers) |
| Encrypt its local database | Uses telemetry, analytics, ads or accounts |
| Delete old data automatically | Installs a root certificate or intercepts HTTPS |
| Tell you about the only two requests it makes itself (list updates, update checks), both of which you can turn off | Hides what it does: the code is open for anyone to check |

## How it works

```
 Windows (ETW events) ──▶ Whereabouts service ──▶ encrypted local database ──▶ Whereabouts app
   connection + DNS          • which app?                                        dashboard, alerts,
   metadata only             • which company / country? (offline lookups)       block rules
                             • is this normal for this app?
                             • block rules (Windows Filtering Platform)
```

Detection has three layers, from simple to smart:

1. **Known lists:** trackers, ad networks and known malicious servers
2. **Per-app profiles:** learns what is normal for each app, then flags new destinations, new countries and upload spikes
3. **Anomaly model:** a small on-device machine-learning model (Isolation Forest). It ships only if lab tests show it catches more problems *without* more false alarms.

All learning happens on your computer. Details are in the [design spec](docs/design-spec.md#6-detection-and-learning).

## Roadmap

| Version | Theme | What you get |
|---|---|---|
| v0.1 | *See* | Live view of every app's connections, companies and countries |
| v0.2 | *Control* | Block apps and domains, alerts for known-bad servers |
| v0.3 | *Learn* | Per-app behaviour profiles and explained alerts |
| v0.4 | *Detect* | On-device anomaly model (if it passes testing) |
| v1.0 | *Trust* | Signed installer, external security review |
| Later | | Android app, PC + phone dashboard over your local network |

## Trying the current build

The desktop app is not ready yet, but you can already watch live connections per app in a terminal, or install the background service. Open **PowerShell as administrator** in the project folder and run:

```powershell
cargo run -p whereabouts-service -- --console
```

For company and country information, first download the offline databases (once; see [data/README.md](data/README.md)):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\update-data.ps1
```

Stop it with **Ctrl+C**, or add `--seconds 30` to stop automatically. Finished flows are saved, encrypted, in `%ProgramData%\Whereabouts`. Afterwards, also as administrator:

```powershell
cargo run -p whereabouts-service -- --status             # while --console runs: status, top flows and apps
cargo run -p whereabouts-service -- --history            # top apps of the last 24 hours
cargo run -p whereabouts-service -- --export flows.csv   # everything saved, as CSV
cargo run -p whereabouts-service -- --delete-all --yes   # delete all saved data
```

To keep Whereabouts running in the background, starting with Windows whoever is logged in, install it as a service (as administrator):

```powershell
cargo run -p whereabouts-service -- --install
```

This copies the program and its offline data to `%ProgramFiles%\Whereabouts` (which only administrators can change) and starts the **Whereabouts** service, running as LocalSystem. Ask it how it is doing, as yourself, with the installed copy:

```powershell
& "$env:ProgramFiles\Whereabouts\whereabouts-service.exe" --status
```

Remove it with `--uninstall` (your saved history is kept) or `--uninstall --delete-data` (everything is deleted). While the service runs, `--console` refuses to start, because two captures cannot run at once.
 It shows each app's connections with the app's publisher, the company behind the destination (for known tracking and analytics services, otherwise the network owner) and its country (from its code signature, so a renamed program can't pretend to be something else), the domain name (when the app's DNS lookup was seen), remote address and port, and the bytes sent and received.

## Building from source

Requirements:

- Windows 10 22H2 or Windows 11 (x64)
- [Rust](https://rustup.rs) (stable, MSVC toolchain)
- Visual Studio Build Tools with the **Desktop development with C++** workload
- [Strawberry Perl](https://strawberryperl.com) (`winget install StrawberryPerl.StrawberryPerl`), needed once to build OpenSSL for the encrypted database. The first build takes a few extra minutes.

```powershell
git clone https://github.com/Razni-Ahamed/Whereabouts.git
cd Whereabouts
cargo build --workspace
cargo test --workspace
```

## Project layout

| Path | What it is |
|---|---|
| `crates/core` | Platform-independent data model and detection logic (no `unsafe`) |
| `crates/enrich` | Offline domain, company, tracker and country lookups |
| `crates/store` | Encrypted local storage |
| `crates/ipc` | Messages between the service and the app |
| `crates/win-capture` | Windows network event capture |
| `crates/win-pipe` | Locked-down local pipe between the service and the app |
| `crates/win-secrets` | Database key protection (DPAPI) and the restricted data folder |
| `crates/win-firewall` | Windows Filtering Platform block rules |
| `service` | The background Windows service |
| `ui` | The desktop app (Tauri), coming in v0.1 |
| `lab` | Test harness for detection quality, not shipped |
| `docs` | Design spec and other documentation |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first, especially the privacy rules. To report a security problem, follow [SECURITY.md](SECURITY.md) and **do not open a public issue**.

## Licence

Whereabouts is licensed under the [GNU General Public License v3.0 or later](LICENSE). Anyone can use, study, change and share it, and any modified version they distribute must stay open source too.
