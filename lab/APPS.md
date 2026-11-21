# Apps in the lab, and why their terms allow it

The lab runs real apps on GitHub's disposable Windows runners to record their **normal background traffic** (which server, how much, never contents). Every app is installed fresh, **started logged out, never signed in, never clicked through by a script**, and the runner is destroyed afterwards. Nothing is decrypted or redirected. GitHub's terms allow runners for work related to the repository's project, and this lab is that.

Each app's published terms were read on 2026-11-21 (a reading, not legal advice). An app goes in only if nothing in its terms forbids this use; doubtful cases are left out.

| App | Terms | Verdict | Notes |
|---|---|---|---|
| Google Chrome | [Chrome terms](https://www.google.com/chrome/terms/), [Google terms](https://policies.google.com/terms) | In | No account needed; Google's automation rule is about site content and robots.txt, not running the browser. Preinstalled on the runner. |
| Microsoft Edge (via Playwright) | [Edge terms](https://explore.microsoft.com/en-us/edge/terms) | In | No account, no automation rule. Preinstalled. The runner's Windows Server licence was not read. |
| Firefox (Playwright's build) | [Playwright browsers](https://playwright.dev/docs/browsers), [licence](https://github.com/microsoft/playwright/blob/main/LICENSE) | In | Open-source builds made for automation (Firefox build under MPL 2.0, Playwright Apache 2.0). |
| Visual Studio Code | [VS Code licence](https://code.visualstudio.com/license) | In | "any number of copies"; no account. Installed in the job. Its telemetry is part of what we record. |
| Git for Windows | [GPL v2](https://github.com/git-for-windows/git/blob/main/COPYING) | In | Running the program is not restricted. Preinstalled. |
| Spotify | [Terms of Use](https://www.spotify.com/us/legal/end-user-agreement/), [User Guidelines](https://www.spotify.com/us/legal/user-guidelines/) | In, launch only | An account "may" be needed; the guidelines ban automated access to the service (bots, scrapers), so the lab only starts the client, which stays on its login screen. No scripted clicks. |
| Discord | [Terms](https://discord.com/terms) | In, launch only | The licence lets you install and run the software; the scraping and auto-message bans do not cover an idle client. No scripted clicks. |
| Steam | [Subscriber Agreement](https://store.steampowered.com/subscriber_agreement/) | **Out** | The client licence assumes a Steam account and §4.C bans "non-human-controlled systems". Not clearly forbidden for an idle, logged-out client, but too doubtful. |

**Rules for adding an app:** read its terms first and add a row here; launch only, logged out; no accounts, passwords or tokens; no decrypting, proxying or protocol tricks; no scripted interaction with a service that bans automated access.
