# Changelog

All notable changes to Whereabouts are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `win-capture`: live network capture from the `Microsoft-Windows-Kernel-Network` ETW provider (TCP and UDP, IPv4 and IPv6), with bounded queues and counters for dropped and unreadable events. Event decoding is verified against real Windows 11 events and covered by unit tests.
- `win-capture`: executable path lookup for a process ID (first step of app attribution).
- `core`: `NetEvent` model and `FlowTable`, which aggregates events into per-app, per-destination flows, ignores loopback traffic and caps memory use.
- `service`: `--console` mode showing live flows per app (run as administrator).
- `win-capture`: `etw_probe` example for inspecting raw ETW events during development.
- Design specification (`docs/design-spec.md`), privacy policy, security policy and contribution guide.
- Cargo workspace with `core`, `enrich`, `ipc`, `store`, `win-capture`, `win-firewall` and `service` crates.
- `core`: connection metadata model, robust statistics (median, MAD, robust z-score) and domain entropy.
- CI on Windows: formatting, Clippy, tests, and licence/advisory checks with `cargo-deny`.
