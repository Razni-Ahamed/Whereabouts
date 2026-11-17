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
4. Install [Node.js](https://nodejs.org) LTS (24 or newer) for the desktop app's web UI.
5. Clone and build. The desktop app embeds the built UI, so build the UI first:

   ```powershell
   git clone https://github.com/Razni-Ahamed/Whereabouts.git
   cd Whereabouts
   cd ui; npm ci; npm run build; cd ..
   cargo build --workspace
   ```

### Working on the desktop app

The app is in `ui/`: a Svelte 5 + TypeScript web UI in `ui/src`, and the Tauri (Rust) side in `ui/src-tauri`.

- **Design work in a browser:** `npm run dev` in `ui/` serves the UI at http://127.0.0.1:5173 with **made-up demo data** (marked "Demo data" in the top bar). This needs no service and no administrator rights.
- **The real app:** `npm run tauri build -- --no-bundle` in `ui/` builds `target\release\whereabouts.exe`. It shows real data only from the **installed** service, which answers only programs installed next to it: build the service in release too (`cargo build --release -p whereabouts-service`), then run `target\release\whereabouts-service.exe --install` as administrator, which copies both programs to `%ProgramFiles%\Whereabouts`.
- **Rules:** the UI loads nothing from the network: fonts, icons and the background are bundled or drawn in code. The content security policy in `tauri.conf.json` enforces it. The web view may call only the commands listed in `ui/src-tauri/build.rs`.

### Building the installer

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
```

This downloads the offline data if it is missing, builds the service and the app in release mode, and builds the NSIS installer with the settings in `ui/src-tauri/tauri.installer.json` (kept apart from `tauri.conf.json` so ordinary builds do not need the data files). The installer and `SHA256SUMS.txt` end up in `target\dist`. The installer's own steps (refusing other install folders, registering and removing the service, asking about saved history) are in `ui/src-tauri/installer-hooks.nsh`.

The **Release** workflow builds the installer on a fresh GitHub Windows machine, installs it silently, checks the service, uninstalls it and checks it is gone, for every pull request that touches the installer. Pushing a `v*` tag also creates a **draft** GitHub release with the installer and checksums, using the notes in `docs/releases/<tag>.md`; a maintainer reviews and publishes it.

## Checks to run before opening a pull request

CI runs the same checks, so running them locally saves time:

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ui; npm run check; cd ..
```

## Live tests

Some tests read real network and process events from Windows (ETW). They need administrator rights, so `cargo test` skips them. Run them with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\live-test.ps1
```

The script builds everything as you, asks for administrator rights once (UAC), runs the live tests (including blocking tests, which only touch a separate test scope of the Windows Filtering Platform and a temporary copy of curl) and a short check of `whereabouts-service --console`, and prints **PASS** or **FAIL**. If the Whereabouts service is installed and running, the console and storage checks are skipped, because two captures cannot run at once. It makes a few HTTPS requests to example.com. Its logs contain your computer's connection metadata, so they go to a temporary folder and must never be committed.

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
