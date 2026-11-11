## What does this change?

<!-- A short description, and the issue it fixes if any (e.g. "Fixes #12"). -->

## Why?

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass
- [ ] New logic has tests
- [ ] Follows the [privacy rules](https://github.com/Razni-Ahamed/Whereabouts/blob/main/CONTRIBUTING.md#the-privacy-rules): no traffic contents, no new outbound requests, no telemetry, offline lookups only
- [ ] Any new `unsafe` is in a Windows API crate and has a `// SAFETY:` comment
- [ ] Any new dependency is explained below, and its licence is GPL-3.0 compatible
- [ ] `CHANGELOG.md` updated if users would notice the change
