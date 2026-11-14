# Contributing to Whereabouts

Thank you for helping. Whereabouts only works if people can trust it, so contributions are judged first on **privacy and security**, then on everything else.

## Before you start

- For anything bigger than a small fix, **open an issue first** so we can agree on the approach.
- Read the [design spec](docs/design-spec.md). It explains the architecture and the reasons behind it.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## The privacy rules

A pull request that breaks any of these will not be merged, however useful the feature is:

1. **Never read traffic contents.** Connection metadata only: no payloads, URL paths, query strings, headers or bodies, and no TLS interception.
2. **Nothing leaves the device.** No new network requests beyond those listed in [PRIVACY.md](PRIVACY.md#requests-whereabouts-makes-itself).
3. **No telemetry, analytics, ads, accounts or crash uploads.** This includes third-party SDKs that do any of these.
4. **Lookups stay offline.** Never send IPs or domains to an online service.
5. **Learning stays local.** No sharing of profiles, models or model updates.

## Development setup

1. Install [Rust](https://rustup.rs) (stable, MSVC toolchain).
2. Install Visual Studio Build Tools with the **Desktop development with C++** workload.
3. Install [Strawberry Perl](https://strawberryperl.com) (`winget install StrawberryPerl.StrawberryPerl`). The encrypted database (SQLCipher) needs OpenSSL, which is built from source and needs a native Windows Perl. If you build from **Git Bash**, its own Perl comes first on `PATH` and cannot build OpenSSL; set `OPENSSL_SRC_PERL=C:/Strawberry/perl/bin/perl.exe`. Keep the project in a short path (e.g. `D:\Projects\Whereabouts`): OpenSSL's deepest source files can exceed Windows' 260-character path limit in long paths.
4. Clone and build:

   ```powershell
   git clone https://github.com/Razni-Ahamed/Whereabouts.git
   cd Whereabouts
   cargo build --workspace
   ```

## Checks to run before opening a pull request

CI runs the same checks, so running them locally saves time:

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Live tests

Some tests read real network and process events from Windows (ETW). They need administrator rights, so `cargo test` skips them. Run them with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1
```

The script builds everything as you, asks for administrator rights once (UAC), runs the live tests and a short check of `whereabouts-service --console`, and prints **PASS** or **FAIL**. It makes a few HTTPS requests to example.com. Its logs contain your computer's connection metadata, so they go to a temporary folder and must never be committed.

To also test the Windows service, add `-Service`. This **installs the Whereabouts service on your computer**, checks it (running as LocalSystem, starting automatically, `--status` from the installed copy as administrator and as a normal user, another copy refused, `--console` refused while it runs, history readable after it stops, a clean log), then uninstalls it. The saved-data folder `%ProgramData%\Whereabouts` is deleted afterwards only if it did not exist before the test. The service uses your real data folder, so flows captured during the test are saved there while it runs.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1 -Service
```

CI runs the same live tests on GitHub's Windows runners (job "Live ETW tests").

## Code guidelines

- **`unsafe` code** is forbidden in `core`, `enrich`, `ipc` and `store`. It is allowed only in the Windows API crates (`win-capture`, `win-firewall`, `win-pipe`, `win-secrets`), and every `unsafe` block needs a `// SAFETY:` comment explaining why it is sound.
- **Treat network data as untrusted.** Domain names and other values from the network must be length-limited and validated, and never used to build file paths or SQL strings. Use parameterised queries.
- **Dependencies:** add new crates only when they are clearly needed. Explain why in the pull request. Their licences must be compatible with GPL-3.0 (CI checks this with `cargo-deny`).
- **Tests:** new logic needs tests. Bug fixes need a test that fails without the fix.
- **Never commit** real traffic captures, databases, logs with real domains, keys or certificates.

## Commit messages

Write a short summary line in the imperative mood, such as "Add robust z-score to core stats", followed by a blank line and an explanation of *why* if the change is not obvious.

## Licence

By contributing, you agree that your contributions are licensed under the [GPL-3.0-or-later](LICENSE), the same licence as the project.
