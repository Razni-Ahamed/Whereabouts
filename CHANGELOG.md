# Changelog

All notable changes to Whereabouts are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Design specification (`docs/design-spec.md`), privacy policy, security policy and contribution guide.
- Cargo workspace with `core`, `enrich`, `ipc`, `store`, `win-capture`, `win-firewall` and `service` crates.
- `core`: connection metadata model, robust statistics (median, MAD, robust z-score) and domain entropy.
- CI on Windows: formatting, Clippy, tests, and licence/advisory checks with `cargo-deny`.
