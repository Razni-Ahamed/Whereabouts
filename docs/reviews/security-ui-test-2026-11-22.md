# Security and UI test: 2026-11-22

Build tested: branch `feat/lab-harness` (uncommitted changes included), installed with the
real NSIS installer over 0.2.0 on Windows 11. Every "Confirmed" finding below was
reproduced on that machine, as a **normal (non-admin) user** unless it says otherwise.
Test rules and test programs were removed afterwards; no saved data was deleted.

> Contains working attack steps. Fix before publishing this file in a public repository.

## Summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| H1 | High | Any program running as the user can pause, remove or add blocks through the trusted command-line tool, with no prompt; a blocked app can free itself | **Fixed**, verified live |
| H2 | High | Apps screen merges programs by file name: a fake `chrome.exe` is shown as signed Google Chrome | **Fixed**, verified live |
| H3 | High (UX) | "Block…" on the Connections screen opens off-screen when the list is long | **Fixed**, verified live |
| M1 | Medium | Pipe squatting while the service restarts leaves it without its pipe until the next restart | **Fixed**, verified live |
| M2 | Medium | "Undo" after blocking something already blocked deletes the original rule | **Fixed**, verified live |
| M3 | Medium | A copy or hard link of a blocked program is not blocked | **Fixed** (byte-identical copies), verified live |
| M4 | Medium | WebView2 traffic is shown as `msedgewebview2`, not the app that owns it | **Fixed**, verified live |
| M5 | Medium | "Delete everything" is the default button of an irreversible dialog | **Fixed**, verified live |
| M6 | Medium | No file is code-signed; Whereabouts labels itself "UNSIGNED" | **Ready**: signing built in, needs a certificate |
| L1 | Low | The service reveals whether a file exists in folders the user cannot read | **Fixed** (closed by H1), verified live |
| L2 | Low | The desktop app re-sends a request after any error, not only a lost connection | **Fixed** |
| L3 | Low | No idle timeout on pipe clients (4 slots) | **Fixed** |
| L4 | Low | Domain rules do not stop apps that resolve names themselves (DoH, fixed IPs) | **Fixed** |
| L5 | Low | Public suffixes (`co.uk`) and non-program files are accepted as rules | **Fixed**, verified live |
| L6 | Low | Rule IDs are reused | **Fixed**, verified live |
| L7 | Low | A user who creates `%ProgramData%\Whereabouts` first stops the service starting | **Fixed**, verified live |
| L8 | Low | Tracker false positive: `lsass` → `geotrust.com` (certificate checks) | **Fixed** |
| L9 | Low | UI copy and layout nits | **Fixed**, verified live |

## High

### H1. Blocks can be lifted, or added, by any program running as the user

The pipe refuses programs other than Whereabouts' own (a PowerShell client was disconnected
before a byte was read). But it trusts `whereabouts-service.exe`, and any program can start
that file with any arguments. As a normal user:

```
"C:\Program Files\Whereabouts\whereabouts-service.exe" --pause-blocking   # every block lifted
"C:\Program Files\Whereabouts\whereabouts-service.exe" --unblock 1        # one rule removed
"C:\Program Files\Whereabouts\whereabouts-service.exe" --block-app <path> # added, no dialog
```

All three worked with no prompt. The blocked app itself runs as the user (uTorrent Web
does), so it can unblock itself. The app's "Windows asks you to confirm" protection only
covers the app, and the app's own Pause button also has no confirmation.

**Fix:** treat rule changes (`AddRule`, `RemoveRule`, `SetBlockingPaused`, `DeleteAll`,
`DismissAlert{allow}`, `SetListUpdates`) as privileged. Accept them only from the desktop
app (which confirms in a native dialog) or from an **elevated** client: the server can open
the client process token (it already opens the process) and check `TokenElevation`. Have the
CLI say "run as administrator" otherwise. Read-only requests (`Status`, `LiveFlows`,
`ListRules`) can stay open to the user. Same-user code could still drive the app's window,
but that is much harder than one command line.

### H2. A fake program borrows a real app's identity on the Apps screen

`groupByApp` (`ui/src/lib/state.svelte.ts`) groups connections by **file name** and takes
the path, publisher and "signed" badge from the first connection. Test: a copy of `curl.exe`
named `chrome.exe` in `%TEMP%` downloaded a file while Chrome ran. The Apps screen showed a
single "chrome · Google LLC · signed · C:\Program Files\Google\Chrome\…\chrome.exe ·
process 28112, 37936"; 37936 was the fake, and its `speed.cloudflare.com` download was
listed under Chrome. "Block app" on that card blocks whichever path came first. (The
Connections screen shows each connection's own publisher correctly.)

**Fix:** group by full path (fall back to name only when there is no path). Two programs
with the same name become two cards; show the folder when names collide.

### H3. The Block menu opens off-screen on the Connections screen

`BlockMenu` uses `position: fixed`, but on Connections it is rendered inside the
`.glass` panel. An element with `backdrop-filter` becomes the containing block for fixed
children, so the menu is centred in the whole table (≈1,500 px down with 63 rows), not the
window. To the user, "Block…" does nothing. On Alerts it works, because there the menu is
rendered outside the card.

**Fix:** render the menu outside any `.glass` element (as Alerts does), for example from
the screen's top level or `App.svelte`.

### Re-test after the fixes (same day, installer rebuilt and installed)

- **H1:** as a normal user, `--pause-blocking`, `--unblock 1` and `--block-app` now exit with code 1 and
  "Changing what Whereabouts blocks, deletes or warns about needs the Whereabouts app, or administrator
  rights…"; `--rules` and `--status` still work. From an administrator terminal, pause and resume work.
  The app's own Pause and Resume still work. Code: `peer::trusted_client` / `Client::may_change`
  (`crates/client/src/peer.rs`), `changes_something` in `service/src/server.rs`, `is_elevated` in
  `crates/win-capture/src/process.rs`; tests for both the rule and the real pipe.
- **H2:** with the fake `chrome.exe` running, the Apps screen shows two cards: Chrome (Google LLC,
  process 28112 only) and the fake (Microsoft 3rd Party Application Component, its Temp path, its own
  process), each with its folder. Code: `ui/src/lib/apps.ts` (tested in `apps.test.ts`).
  Left over: the card's "Last 24 hours" line comes from saved history, which the service still totals
  by file name. **Fixed 2026-11-24**: `Store::top_apps` totals saved flows
  per program path (by name only when no path was saved), `AppTotals` carries the `path`, and the card
  shows the totals of its own path (`savedTotals` in `ui/src/lib/apps.ts`). `--status` and `--history` show the folder
  under "Top apps" rows that share a name. Tests: `programs_that_share_a_name_get_separate_totals`
  (store), `apps.test.ts`.
  Re-tested 2026-11-24 with an installer built from the fix and installed over the previous build: run as
  a normal user, `--status` listed two `claude.exe` programs from different folders (Claude Code and the
  Claude desktop app) as two "Top apps" rows with their own totals (37 and 24 flows), each with an
  `in <folder>` line under it. (The first re-test build printed the folder lines only in `--history`, so
  the two rows looked the same; fixed in `console::folder_lines`, used by both tables.) Not re-tested:
  the fake `chrome.exe` itself and the app card's "Last 24 hours" line, because history saving was
  off on the test PC.
- **H3:** the Block menu opens centred over the 60-row Connections list. Code: `ui/src/lib/portal.ts`,
  used by `BlockMenu.svelte`.

### Re-test of the Medium findings (same day, installer rebuilt and installed)

- **M1:** a normal-user script took `\\.\pipe\Whereabouts` 3 s into the upgrade. The new service logged
  "trying again every 5 s", took the pipe 2 s after the squatter let go and answered `--status` with
  no restart (`server::start_or_retry`; test `a_taken_pipe_name_is_tried_again_until_it_is_free`).
- **M2:** `AddRule` answers `already`; the app says "… was already blocked" with no Undo, and the Block
  menu for an already blocked app only says so ("utweb is already blocked completely").
- **M3:** with `blocked.exe` blocked, a byte-identical `renamed-copy.exe` in another folder got a rule of
  its own and a notification. A first fix only counted confirmed identity checks and missed copies that
  ran for under a second; unconfirmed checks now count too (the path is what is blocked).
- **M4:** WebView2 traffic is credited to its app: WhatsApp's appears as "WhatsApp.Root · web content",
  and no `msedgewebview2` rows remain (`process::ancestor_not_named`).
- **M5:** "Delete everything" and "Stop these warnings" use a task dialog with Cancel as the default
  (`crates/win-dialog`): Enter closed the dialog and the history was intact.
- **M6:** `scripts/build-release.ps1 -SignThumbprint <SHA-1>` signs the service (signtool) and has Tauri
  sign the app, uninstaller and installer, then fails unless all carry that signer. Checked with a
  throw-away self-signed certificate (removed afterwards). Releases stay unsigned until there is a
  certificate (SignPath Foundation, Azure Trusted Signing or a commercial one).

### Follow-up: automated review of the Medium fixes

An automated security review of the pushed Medium fixes found two weaknesses in them, both fixed:

- **WebView2 crediting could be spoofed (high).** Any program can be called `msedgewebview2.exe`; such a
  copy was credited to whatever started it (for example Explorer), with that program's name and
  publisher, and "Block app" on it would have blocked Explorer. Only the installed runtime under
  `Program Files (x86)\Microsoft\EdgeWebView\Application\` (or `Program Files`), which only
  administrators can change, is now credited to its app.
- **Copy-blocking could be steered (medium).** Copies were compared with the file *now* at the blocked
  path. uTorrent Web's folder is user-writable, so swapping another program's file in there would have
  got that other program blocked, and many copies could fill all 256 rule slots. Each app rule now
  keeps the SHA-256 pinned when it was made (saved and removed with the rule; older rules pinned once at service start, never lazily; an unreadable file is pinned as "none", which never matches; a second review round found the lazy pinning and the stale pins), copies are added
  only while 64 slots stay free, and at most 5 an hour.

### Re-test of the Low findings (same day, installer rebuilt and installed)

- **L1:** a normal user's `--block-app` on a file in a folder it cannot read is refused before any
  path is looked at ("needs the Whereabouts app, or administrator rights").
- **L2:** the app retries only a lost connection (`ProblemKind::Lost`), never an error answer.
- **L3:** a client silent for 2 minutes is let go (a watchdog cancels its read with `CancelIoEx`);
  test `a_silent_client_is_disconnected_and_frees_its_place` fills all 4 places with silent clients.
- **L4:** the domain-block dialog and menu say that programs using their own DNS or fixed addresses
  can get around a domain block.
- **L5:** as administrator, `--block-domain co.uk` ("shared by many unrelated sites") and
  `--block-app ...\drivers\etc\hosts` ("not a program") are refused.
- **L6:** a rule with ID 2 was removed; the next rule got ID 3.
- **L7:** an empty `%ProgramData%` folder made by the normal account was replaced by a new one owned
  by Administrators; one holding a planted `whereabouts.db` was refused. A first version adopted the
  folder in place; an automated review pointed out that a handle its maker opened earlier would keep
  its access, so the folder is now removed and created anew, and a folder held open is refused.
- **L8:** no tracker alerts for `lsass`, `svchost`, `services`, `wininit` and `winlogon` in System32
  (copies with those names elsewhere still get them).
- **L9:** "No connections match." for an empty search; the tab bar stays in view while scrolling;
  "1 internet connection"; the installer removed the leftover `.before-wal` file.

## Medium

### M1. Pipe squatting during a restart

When the service is stopped (update, crash with its 10-second restart), any program can create
`\\.\pipe\Whereabouts`. Test: a normal-user script took the name 3 ms after the installer
stopped the old service. The new service logged "could not create the pipe … All pipe
instances are busy", kept running **without a pipe and never retried**; after the squatter
let go, `--status` still said "not running" until the service was restarted. (The client
correctly refused to trust the impostor.)

**Fix:** if `server::start` fails, retry binding in the background (for example every few
seconds) instead of giving up; consider raising a notice while the pipe is unavailable.

### M2. Undo deletes a rule that already existed

The service deduplicates rules (blocking utweb again returns the existing ID 1), but the app
then shows "Blocked utweb · Undo", and Undo removes rule 1. Tested: it lifted a block that
had existed for hours (its creation date was lost when it was re-added).

**Fix:** have `AddRule` say whether the rule is new (for example `RuleAdded { id, new }`);
show "Already blocked" without Undo when it is not. Also hide "Everything X connects to" in
the Block menu when the app is already blocked.

### M3. Copies and hard links are not blocked

App blocks match the program's path. A copy and a hard link of a blocked program both
connected. Apps in user-writable folders (uTorrent Web in AppData) can do this themselves.
Windows Firewall has the same limit.

**Fix (mitigation):** say so in the block dialog; optionally flag new programs whose file
hash matches a blocked one, as an alert with "Block this too".

### M4. WebView2 traffic is credited to Microsoft, not the app

uTorrent Web's ads appear as "msedgewebview2 contacted Google (google-analytics.com)". Users
cannot tell which app is behind it, so they block the wrong program (this is what made the
uTorrent block look broken).

**Fix:** attribute `msedgewebview2.exe` processes to their host app (the service already walks
process trees for its own WebView2; the network process also carries
`--webview-exe-name=<host>.exe`), for example "utweb (web content)".

### M5. Destructive default button

In "Delete everything Whereabouts saved?" the focused default is **Delete everything**, so
Enter wipes the history. The Block dialogs also default to Block.

**Fix:** make Cancel the default for Delete everything (at least).

### M6. Nothing is code-signed

`whereabouts-service.exe`, `whereabouts.exe`, `uninstall.exe` and the installer are all
`NotSigned`. The Connections screen lists Whereabouts' own service as "UNSIGNED", SmartScreen
will warn on install, and users cannot verify what they run as SYSTEM.

**Fix:** sign releases (Authenticode, or Azure Trusted Signing / SignPath for open source).

## Low

- **L1. Existence oracle.** The service normalises rule paths as SYSTEM: `--block-app` with a
  real file in a folder the user cannot list was accepted; a made-up name said "cannot find
  the file". Fix: check the path from the client side or with an access check for the
  client's account, and accept only `.exe` files.
- **L2. Retries.** `Connection::with` (`ui/src-tauri/src/main.rs`) runs the request again after
  *any* error, including the service's own error replies. Delete Everything or Add Rule can
  be sent twice, and a 60-second timeout becomes 120. Fix: reconnect and retry only on I/O
  (connection) errors.
- **L3. No idle timeout.** A trusted client that connects and stays silent holds one of the 4
  slots forever. Fix: a read timeout on idle connections.
- **L4. Domain rules and private DNS.** With DNS-over-HTTPS the "blocked" program reached the
  site every time until Windows' DNS had seen the name once (documented in the spec, §174 and
  §249), but the dialog says the app "will not be able to connect". Fix: say it in the dialog.
- **L5. Over-broad rules.** `co.uk` was accepted as a domain rule; a `.key` file was accepted as
  an app. Fix: refuse public suffixes (a small built-in list) and non-`.exe` targets.
- **L6. Reused rule IDs.** A rule removed and re-added got ID 1 again; stale IDs (an Undo note,
  a script) can hit another rule. Fix: `AUTOINCREMENT`, or random IDs.
- **L7. Folder squatting.** A normal user can create `%ProgramData%\Whereabouts` before install
  or after uninstall; the service then refuses it (correctly) and will not start. Fix: say how
  to recover in the error, or create it from the installer.
- **L8. False positive.** "lsass contacted geotrust.com" is flagged as tracking; it is most
  likely a certificate revocation check.
- **L9. UI nits.** Search with no matches says "No connections yet."; "1 internet
  connections"; the tab bar is not sticky, so long lists need scrolling back up; changes made
  outside the app take up to 10 s to show; an old `whereabouts-service.exe.before-wal` (9 MB)
  is left in `C:\Program Files\Whereabouts`.

## What held up

- Pipe: local only, remote and network logons denied, no instance squatting while running,
  untrusted programs disconnected before anything is read, 1 MiB message cap checked before
  allocating, strict JSON, limits clamped.
- Data folder: created restricted to SYSTEM/Administrators, planted folders, links and files
  refused, permissions reapplied through a handle that does not follow links; the user gets
  "Access denied".
- Service: quoted binary path, default service permissions (users can only query), program
  folder writable by administrators only.
- Updates: Ed25519-signed manifest, HTTPS only, size limits, per-file hashes, no rollback;
  "Check now" worked live.
- App: strict CSP, no `{@html}`/`innerHTML`, hostile search text inert; blocking, deleting,
  exporting and silencing high alerts all go through native dialogs that show full paths.
- Notifications XML-escaped; CSV export protected against formula injection.
- Paths: network, device (`GLOBALROOT`), 8.3 short names and Whereabouts itself refused.
- In-memory tables bounded (flows, DNS, identities); no panicking slices in the parsers.
- Today's fixes, live: WebView2 setting set on block, removed on unblock and pause, restored on
  resume; new dialog text shown.

## Not tested

- A peer on another machine connecting in to a blocked app (incoming filters).
- A real "Delete everything" (dialog only; history was kept).
- Exhausting the 4 pipe slots live (needs freezing the CLI mid-request).
