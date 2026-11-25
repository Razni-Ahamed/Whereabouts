# Whereabouts lab

The lab measures how well Whereabouts' detection works **before** it ships: how many false alarms a person would get per week, how many staged problems it catches, and how fast. It exists for v0.3 ("Learn") and later layers; every threshold is judged by its numbers.

**It never uses real user data.** All traffic comes from scripted sessions on GitHub's disposable Windows runners, destroyed after each run. Nothing in this folder ships with the app.

> The numbers compare detection layers with each other. They are **not real-world rates**: the sessions are short, on datacenter machines, with no real person behind them.

## How it works

```
capture (one runner per session)         analyse (one runner)
  engine --console records                  lab timeline   sessions → simulated user-weeks
  a persona uses real apps, logged out                     + synthetic scenarios, labels
  live scenarios (optional)                 lab droplist   Spamhaus DROP + test entries
  --export → session.csv + session.json     whereabouts-lab-replay   → alerts (shipped detector)
                                            lab report     → report.md, charts, job summary
```

1. **Capture** (`capture/run-session.ps1`): the Whereabouts engine records while a persona (`office`, `media`, `gamer`, `developer`) uses real apps, all logged out (see [APPS.md](APPS.md) for each app's terms). Health counters are sampled with `--status --json`, and the engine's lab-only `--record-connections` writes when each connection was opened (for beaconing; the installed service refuses it). Session 0 of each persona also stages two **live scenarios**: a copy of `curl.exe` named `Discord.exe` (a program posing as a popular app) and a fetch of example.com, which the analysis lists as a test "known-bad" address. Nothing risky is ever contacted.
2. **Simulated user-weeks** (`lab timeline`): each simulated user has one persona and 14 days: 7 learning days (design spec D15) and a 7-day test week. Sessions are placed at the persona's usual hours. Per persona the sessions are split into a learning pool and a test pool, so **a user's test week never reuses a session it learned from** (no leakage).
3. **Synthetic scenarios** (`--inject`), added to the test week with labels, because they must not be staged for real: a 200 MB hidden upload, 3 hours of beaconing, random-looking domains, a swapped program reaching new destinations. Their addresses are documentation ranges and `example.*` names.
4. **Replay** (`crates/lab-replay`): runs every simulated user through **the same detection code the app ships** (`whereabouts-detect`), with a fresh temporary encrypted store each, and the same rule the app uses to decide what becomes a notification (`whereabouts_ipc::notify`). `--layers 1` runs the list and health checks; `--layers 1,2` also runs the behaviour Learner with **every** signal on (beaconing too), fed as the app feeds it: each flow's bytes spread over the hours it spans, its destinations learned by the app's own rule, and each recorded connection time for beaconing.
5. **Score and report** (`lab report`): an alert of medium or higher matches a scenario when it is for the same user and app within the scenario's window plus an hour. Everything else in the test week is a false alarm. Reported: false alarms per simulated user-week (medium and up; and notified), detection rate and time to detect per scenario type, each behaviour signal on its own, and the **release bar** (U8): at most 1.0 medium+ false alarm per user-week and at least 50 % detection in 3 of the 5 Layer 2 scenario types (`upload`, `beacon`, `random_domain`, `swapped_binary`, `renamed_binary`), checked on the last `--alerts` given. `--signals a,b,c` scores a subset of the signals (an estimate: Layer 1 alerts always count, a behaviour alert counts if one of its reasons is on).

## Running it

On GitHub (Actions → **Lab** → Run workflow), or:

```powershell
gh workflow run lab.yml -f minutes=8 -f sessions_per_persona=4 -f users_per_persona=3 -f seed=1
```

It also runs weekly. Results: the job summary, and the `lab-report-<run>` and `lab-dataset-<run>` artifacts (kept 90 days; datasets are never committed). To re-analyse an earlier run's sessions, pass `-f reanalyse_run_id=<run id>`.

## Working on the lab code

```powershell
uv sync --project lab
uv run --project lab pytest -q lab/tests
cargo test -p whereabouts-lab-replay
```

Replay and report by hand (after `lab timeline`):

```powershell
cargo run --release -p whereabouts-lab-replay -- --timeline dataset\timeline.jsonl --data data --layers 1,2 --out dataset\alerts-layer2.jsonl
uv run --project lab lab report --timeline-dir dataset --alerts "Layers 1+2=dataset\alerts-layer2.jsonl" --signals upload_spike,beaconing --out report
```

Python runs only through uv (the version is pinned in `.python-version`, dependencies in `uv.lock`). Random choices take an explicit seed, recorded in `info.json`.

## Formats

- **Session**: the engine's CSV export (`whereabouts-service --export`), `connections.jsonl` (one line per connection a program opened: `app_path`, `app_name`, `destination` (a confirmed name's registrable domain, else the address), `remote_ip`, `remote_port`, `time_ms`; older sessions have none) and `session.json` (persona, times, runner image, engine commit, apps with versions and SHA-256, health counters, live-scenario labels).
- **Timeline** (`timeline.jsonl`): a header line `{"type":"header","schema":2}`, then `flow`, `connection` and `counters` lines sorted by time (simulated Unix seconds). Schema 2 adds each flow's `signature` and `publisher`, and `connection` lines (`user`, `app_path`, `app_name`, `destination`, `time`: when a program opened a connection, for beaconing). The replay still reads schema 1.
- **Labels** (`labels.jsonl`): one per scenario instance: type, user, app, start, end, live or synthetic.
- **Alerts** (`alerts-layer1.jsonl`, `alerts-layer2.jsonl` for Layers 1 and 2): user, time, layer (2 for behaviour alerts), kind, severity, app, target, detail, reasons (the behaviour signals behind it), notified.

## Known gaps

- The capture is the engine's CSV export: no process IDs and no DNS alias chains, so trackers hidden behind a site's own name are not detected in the lab (they are in the app).
- New-app notices are not measured.
- GitHub's runner agents (`Runner.Worker.exe`, the Azure guest agents, `provjobd.exe…`) are dropped from the data; `info.json` records how many flows were dropped.
- Steam is left out (its terms assume an account); apps run logged out, so their traffic is start-up, update and telemetry chatter, not active use.
