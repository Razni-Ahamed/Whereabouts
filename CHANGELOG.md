# Changelog

All notable changes to Whereabouts are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- DNS label trust: labels are now **verified** (the app's lookup matches what the Windows DNS service itself resolved), **unverified** (only the app reported it; shown with `?`), or **inferred** (from another app's verified lookup; shown with `*`). The DNS service's own events (3020) are accepted only from the real service process (looked up via the Service Control Manager), because any program can write events under the DNS provider's ID; forged events are counted as `rejected` and the console warns about them. Inferred labels come only from verified answers, so one app can no longer plant labels on another's connections, and the table of verified answers evicts the oldest entries when full.
- DNS names are limited to characters legal in DNS (ASCII letters, digits, `-`, `_`, `.`), which blocks bidi, invisible and look-alike Unicode characters.
- Domain names for connections (M1): `win-capture` reads "DNS query completed" events from the `Microsoft-Windows-DNS-Client` ETW provider, which are logged in the app that asked (also for cached answers). `core::dns::DnsMap` remembers each process's answers (bounded per process and in total, 30-minute lifetime, cleared when a process exits) and labels its flows. Connections to an address that only another app looked up get an *inferred* label. DNS names are validated (length, no control characters) before use. The console shows a DOMAIN column.
- `win-capture`: live network capture from the `Microsoft-Windows-Kernel-Network` ETW provider (TCP and UDP, IPv4 and IPv6), with bounded queues and counters for dropped and unreadable events. Event decoding is verified against real Windows 11 events and covered by unit tests.
- `win-capture`: executable path lookup for a process ID, plus process start/exit events from `Microsoft-Windows-Kernel-Process`, so flows and names are closed when a process exits and a reused process ID is never mixed up with the old process. Process events are never dropped (network events may be, and are counted), and a process is identified by its ID and start time.
- `core`: `NetEvent` model and `FlowTable`, which aggregates events into per-app, per-destination flows and ignores loopback traffic. Memory is capped per process and in total; traffic beyond a process's limit goes into a visible "many destinations" flow for that process, so one process cannot hide another's traffic by flooding the table. Overflow flows are capped too, with one shared bucket beyond the cap.
- `service`: `--console` mode showing live flows per app (run as administrator).
- `win-capture`: `etw_probe` example for inspecting raw ETW events during development.
- Live ETW integration tests (`crates/win-capture/tests/live_capture.rs`), skipped by default, plus `scripts/live-test.ps1`, which runs them and a console smoke test with one UAC prompt, and a CI job that runs them on GitHub's Windows runners.
- Design specification (`docs/design-spec.md`), privacy policy, security policy and contribution guide.
- Cargo workspace with `core`, `enrich`, `ipc`, `store`, `win-capture`, `win-firewall` and `service` crates.
- `core`: connection metadata model, robust statistics (median, MAD, robust z-score) and domain entropy.
- CI on Windows: formatting, Clippy, tests, and licence/advisory checks with `cargo-deny`.
