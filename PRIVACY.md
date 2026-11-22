# Privacy

Whereabouts exists to protect your privacy, so it has to protect it first. This page explains, in plain language, exactly what Whereabouts does and does not do with your data. The technical version is in the [design spec](docs/design-spec.md#3-privacy-principles-our-contract-with-users).

If the code ever does something this page says it does not, that is a bug. Please [report it](SECURITY.md).

## The short version

- Whereabouts looks at the **outside of your network traffic** (which app, which server, when, how much), never the **inside**.
- Everything stays **on your computer**. We have no servers and we never receive your data.
- There is **no telemetry, no analytics, no ads and no account**.

## What Whereabouts records

| Recorded | Example |
|---|---|
| Which app made the connection (path, publisher) | `TikTok.exe`, signed by "TikTok Pte. Ltd." |
| The server's IP address and port | `203.0.113.10:443` |
| The domain name, if known from a DNS lookup (and, to spot trackers hidden behind a site's own name, the names it points to, kept in memory only) | `analytics.example.com` |
| The company and country of that server (looked up offline) | "Example Analytics Inc., Singapore" |
| How much data was sent and received, and when | 12 MB sent, 3 MB received, 03:12–03:15 |

**Web browsers:** the list of sites a browser connects to is basically your browsing history. Whereabouts stores only the main domain for browsers (for example `example.com`, not `mail.example.com`).

## What Whereabouts never reads

- Web addresses beyond the domain name (paths like `/user/48213/messages`, or search terms)
- Headers, cookies, passwords or login tokens
- Messages, files, photos, videos or any other content you send or receive

Almost all of this is encrypted anyway. Whereabouts never decrypts traffic and never installs a root certificate to do so.

## Where your data is kept

- In an **encrypted database** on your computer (`%ProgramData%\Whereabouts`), in a folder only administrators and the system can open. The whole file is encrypted; its key is itself encrypted with Windows' DPAPI for this computer and kept in that same protected folder, so copying the files to another computer gives nothing readable. New data first goes into a log next to the database (`whereabouts.db-wal`), encrypted the same way. Deleted data is overwritten, and deleting history also empties that log.
- **Old data is deleted automatically**: individual connections after 30 days, hourly summaries after 180 days.
- **You choose whether history is saved** (from version 0.3; asked once, on by default, changeable on the Privacy screen). With it off, finished connections are shown live and then forgotten: none is written to disk. Turning it off asks whether to keep what is already saved (it is then deleted as it ages, as above) or delete it now. Live connections, alerts, blocking and new-app notifications keep working, so alerts, your rules, the list of programs seen and your settings are still saved. The History view and export get nothing new, and learning what is normal for each app (planned, below) needs history. How much saving writes to disk (from version 0.3, which keeps a write-ahead log): measured with Windows' own file tracing, about 8 MB an hour with ordinary traffic (about 0.2 GB a day) and about 95 MB an hour with very heavy traffic such as a torrent client. That is well under 1% a year of the rated write endurance of a small SSD, even with heavy traffic. Version 0.2 wrote about 20 to 70 MB an hour with ordinary traffic.
- You can **export** your data or **delete everything** at any time, from the app's **Privacy** screen (Windows asks you to confirm each step), with `--export` and `--delete-all --yes` (as administrator), or by answering Yes when uninstalling. An export is a plain CSV file, so keep it private. Deleting everything removes all history saved so far; Whereabouts keeps recording new connections afterwards.
- The background service keeps a small **log of its own health** (`service.log`, at most about 1 MB, in the same protected folder). It never contains what was captured: no app names, domains or addresses.
- For **web browsers**, only the main domain of each site is saved (e.g. `example.com`, not `mail.example.com`).
- The Whereabouts app reads your data from the background service over a **local channel** (a named pipe) that cannot be reached from the network and that only administrators, the system and the account running Whereabouts can open. The service also checks that the program connecting is Whereabouts itself (installed in its protected folder).
- The **desktop app** loads nothing from the internet: its fonts, icons and background are part of the app, and its security policy blocks any other network access. Its Privacy screen counts Whereabouts' own internet connections, as seen by Whereabouts itself: those of the service, the app, and the Microsoft WebView2 helper processes that draw the app's window.

We recommend turning on **BitLocker** so that someone who steals your computer's disk cannot read it.

## Alerts (from version 0.2)

- Whereabouts checks connections against lists on your computer and raises **alerts**: an app contacted a known tracker, connected to a network that Spamhaus lists as run by criminals, or something seems to be hiding from Whereabouts (fake name lookups, traffic that cannot be tied to an app). Alerts are kept in the encrypted database for 90 days and deleted with "Delete everything".
- **Dismiss** only clears an alert. **"This is fine"** is remembered (which app and which tracker or network), like your blocking rules, so you aren't told again.
- Tracker contacts are never notified one by one: you get one summary a day. Like all notifications, it names no apps or trackers unless you allow it.
- The Spamhaus list is not part of Whereabouts: Spamhaus does not allow it to be passed on, so your computer downloads it from Spamhaus itself, if you allow it (see "Requests Whereabouts makes itself").

## Notifications and the tray (from version 0.2)

- Whereabouts remembers **which programs have used the network** (their path and when it first saw them), in the same encrypted database, so it can tell you when a program uses the internet for the first time. Programs seen in the first day, and those already in your history, are learned quietly. Deleting everything also deletes this list (and starts a quiet day again).
- Notifications **don't name apps or sites** unless you turn that on on the Privacy screen. Windows keeps a history of notifications on your computer and can show them on the lock screen.
- **Starting in the tray when you sign in** only happens if you say yes (you are asked once, and can change it on the Privacy screen). It adds one entry to your Windows sign-in programs, which uninstalling removes.
- The app's own settings (these on/off choices) are kept in a small file in your user profile.

## Blocking (from version 0.2)

- The **rules you make** (which programs, domains and addresses to block) are saved in the same encrypted database, and applied as rules in the Windows firewall (the Windows Filtering Platform), under Whereabouts' own name so they can be listed and removed. Deleting your history keeps your rules; deleting all data when uninstalling deletes them too.
- **Domain blocks** use the DNS answers Whereabouts already sees; blocking needs no extra data and makes no requests. The addresses learned for a blocked domain are stored in the firewall rules themselves and removed a day after they were last seen. A block for every app skips addresses that other, unblocked sites also use, so it cannot cut you off from them.
- Whereabouts never blocks what Windows needs to stay online (core Windows programs, DNS servers, your local network). **Pause** lifts every block at once and keeps your rules; `whereabouts-service --unblock-all` (as administrator) does the same even if the service is not running. **Uninstalling removes every block.**

## Requests Whereabouts makes itself

Only **list updates**, and only if you allow them. Nothing is downloaded until you answer the app's question about them (both are suggested on), and you can switch each off on the Privacy screen at any time:

| Request | Why | How often | What it sends |
|---|---|---|---|
| **Whereabouts' lists** from Whereabouts' releases on github.com | Keep the tracker, company, country and network lists current | Checked once a day; about 20 MB when there is a new set (usually weekly) | A plain download of fixed public files. No ID, no cookies, nothing about you or your apps. |
| **Spamhaus' list of criminal networks** from spamhaus.org | Risky-network alerts. Spamhaus does not allow the list to be passed on, so your computer fetches it itself | At most once a day; under 1 MB | The same: a plain download of fixed public files. |

As with any website, those servers see your computer's IP address. Whereabouts' lists are digitally signed by Whereabouts and refused if the signature or any file does not match; an older set is never accepted in place of a newer one. Whereabouts monitors itself like every other app, and its Privacy screen counts its own internet connections and shows when each download last happened, so you can check this.

The one other exception is the **installer**: the desktop app needs Microsoft Edge WebView2, which Windows 10 and 11 normally include. If it is missing, the installer downloads it from Microsoft.

Planned for a later version, optional and off-switchable, signed and rejected if the signature check fails: **checking for app updates**, with the same kind of plain download.

## Company and country information

To show who is behind a connection and in which country, Whereabouts uses databases stored on your computer (DB-IP for countries and network owners, EasyPrivacy for tracker domains, and its own company list). It never sends an address or a domain name to an online lookup service.

Data credits: IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). Tracker list: EasyPrivacy by the [EasyList authors](https://easylist.to) (GPL-3.0). Domain suffixes: [Public Suffix List](https://publicsuffix.org) (MPL-2.0).

## Checking which app is which

To tell you who really made an app, Whereabouts checks the program file's digital signature and computes its hash, on your computer. Windows normally lets signature checks contact certificate servers on the internet; Whereabouts turns that off, so this check never sends anything out. Only programs that use the network are checked.

## Crash reports

Whereabouts has **no crash reporting**: nothing is ever uploaded. If the background service stops unexpectedly, Windows restarts it, and its health log (see above) notes problems it could detect.

## Planned, not in this version

These are designed but not built yet. This page will describe them exactly when they are.

- **Learning what is normal** for each app, to warn about unusual behaviour. It will happen **only on your computer**; learned profiles will be stored encrypted, viewable and resettable, and never shared, not even as anonymised model updates.
- **Settings** to change how long history is kept, and to exclude web browsers from history completely.
- **Recording whether an app was in use** (in the foreground) when it connected.
- **App update checks**, described above.
