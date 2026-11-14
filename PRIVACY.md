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
| The domain name, if known from a DNS lookup | `analytics.example.com` |
| The company and country of that server (looked up offline) | "Example Analytics Inc., Singapore" |
| How much data was sent and received, and when | 12 MB sent, 3 MB received, 03:12–03:15 |
| Whether the app was in use at the time | background |

**Web browsers:** the list of sites a browser connects to is basically your browsing history. By default, Whereabouts stores only the main domain for browsers (for example `example.com`, not `mail.example.com`), and you can exclude browsers completely.

## What Whereabouts never reads

- Web addresses beyond the domain name (paths like `/user/48213/messages`, or search terms)
- Headers, cookies, passwords or login tokens
- Messages, files, photos, videos or any other content you send or receive

Almost all of this is encrypted anyway. Whereabouts never decrypts traffic and never installs a root certificate to do so.

## Where your data is kept

- In an **encrypted database** on your computer (`%ProgramData%\Whereabouts`), in a folder only administrators and the system can open. The whole file is encrypted; its key is itself encrypted with Windows' DPAPI for the account running Whereabouts, so copying the files to another computer gives nothing readable. Deleted data is overwritten.
- **Old data is deleted automatically**: individual connections after 30 days, hourly summaries after 180 days. You can change these limits.
- You can **export** your data or **delete everything** at any time (today with `--export` and `--delete-all --yes`; later from the app). An export is a plain CSV file, so keep it private.
- For **web browsers**, only the main domain of each site is saved (e.g. `example.com`, not `mail.example.com`).
- The Whereabouts app reads your data from the background service over a **local channel** (a named pipe) that cannot be reached from the network and that only administrators, the system and the account running Whereabouts can open. The service also checks that the program connecting is Whereabouts itself.

We recommend turning on **BitLocker** so that someone who steals your computer's disk cannot read it.

## Requests Whereabouts makes itself

This is the complete list. You can turn off both.

| Request | Why | What it sends |
|---|---|---|
| Download list updates | Keep tracker, company and country data current | A plain download of a fixed public file. No ID, no cookies, nothing about you. |
| Check for app updates | Tell you when a new version exists | The same: a plain download of a fixed public file. |

Both downloads are digitally signed, and Whereabouts rejects any file that fails the signature check. Whereabouts monitors itself like every other app, so you can check this list against what it actually does.

## Company and country information

To show who is behind a connection and in which country, Whereabouts uses databases stored on your computer (DB-IP for countries and network owners, EasyPrivacy for tracker domains, and its own company list). It never sends an address or a domain name to an online lookup service.

Data credits: IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). Tracker list: EasyPrivacy by the [EasyList authors](https://easylist.to) (GPL-3.0). Domain suffixes: [Public Suffix List](https://publicsuffix.org) (MPL-2.0).

## Checking which app is which

To tell you who really made an app, Whereabouts checks the program file's digital signature and computes its hash, on your computer. Windows normally lets signature checks contact certificate servers on the internet; Whereabouts turns that off, so this check never sends anything out. Only programs that use the network are checked.

## Learning and machine learning

Whereabouts learns what is normal for each of your apps so it can warn you about unusual behaviour. This learning happens **only on your computer**. The learned profiles are stored encrypted, you can view and reset them, and nothing is ever shared, not even anonymised model updates.

## Crash reports

If Whereabouts crashes, the report is saved on your computer. It is never uploaded. If you want to help fix the problem, you can attach it to a GitHub issue yourself, after reviewing it.
