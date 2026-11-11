# Whereabouts desktop app

The Tauri desktop app (dashboard, per-app view, alerts, rules, settings and privacy screen) will live here. It arrives in v0.1. See the [design spec, section 5.9](../docs/design-spec.md#59-ui).

Rules for the UI: it runs as the normal user, talks to the service only through the IPC messages in `crates/ipc`, and loads **no remote content** (no web fonts, CDNs or remote images).
