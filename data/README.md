# Offline data

Whereabouts never looks anything up online while it runs. It uses these
databases on your computer instead.

| Source | Licence | Used for | How it gets here |
|---|---|---|---|
| `companies.tsv` (this folder) | GPL-3.0-or-later (written for Whereabouts) | Which company runs a tracking, analytics or messaging domain | Committed |
| [EasyPrivacy](https://easylist.to) by the EasyList authors | GPL-3.0-or-later or CC BY-SA 3.0 | Which domains are trackers | `scripts/update-data.ps1` |
| [DB-IP IP to Country Lite](https://db-ip.com) | CC BY 4.0 | Country of an IP address | `scripts/update-data.ps1` |
| [DB-IP IP to ASN Lite](https://db-ip.com) | CC BY 4.0 | Organisation that runs an IP address's network | `scripts/update-data.ps1` |
| [Public Suffix List](https://publicsuffix.org) | MPL-2.0 | Registrable domains (`a.cdn.example.com` → `example.com`) | Built in, via the `psl` crate |

The downloaded files are large and change often, so they are **not committed**
(see `.gitignore`). Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\update-data.ps1
```

It writes `SOURCES.generated.txt` with each file's source, version and SHA-256.

## Why not Disconnect, DuckDuckGo Tracker Radar or Ghostery?

Their tracker and company lists are licensed **CC BY-NC-SA 4.0** (non-commercial
only). Bundling them would stop anyone from using Whereabouts commercially,
which conflicts with its GPL licence. EasyPrivacy plus our own company list has
no such restriction.

## Accuracy

- The free "Lite" databases are less complete than paid ones. Some address
  ranges have no network owner, and for addresses shared worldwide (content
  delivery networks such as Cloudflare), the country is the database's estimate,
  not where the server you reached really is.
- EasyPrivacy is written for browsers; Whereabouts uses only its whole-domain
  rules.
- `companies.tsv` covers well-known services only. Corrections and additions
  are welcome (one line per domain: `domain<TAB>company<TAB>category`).

## Adding a source

Check its licence against GPL-3.0-or-later **before** adding it, add a row to
the table above, and give credit in `whereabouts_enrich::ATTRIBUTION`.
