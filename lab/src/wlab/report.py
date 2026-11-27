"""Writes the lab report: report.md, summary.md, metrics.json and charts, with each
Layer 2 signal on its own and the release bar (U8).

The release bar is checked with the signals that ship (`SHIPPED`, as
`Toggles::default` in `crates/detect/src/signals.rs`), and for comparison with
every signal on. For the bar, a staged problem counts as detected only by a
Layer 1 alert or a behaviour alert whose reasons fit its type (`FITTING`, R26)."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (after choosing the backend)

from .score import SERIOUS, Scored, match  # noqa: E402

# Layer 2's signals (the store's spellings) and their starting severities.
SIGNAL_SEVERITY = {
    "new_site": "info", "new_company": "info", "new_country": "info", "upload_spike": "high",
    "ratio_flip": "medium", "beaconing": "medium", "unusual_time": "info", "random_name": "medium",
    "binary_changed": "high", "impostor": "high",
}
SIGNALS = tuple(SIGNAL_SEVERITY)
# What ships on: every signal except beaconing (spec §8; `Toggles::default`).
SHIPPED = tuple(signal for signal in SIGNALS if signal != "beaconing")
# For the release bar, the signals that count as catching each scenario type (R26).
# Other types (the live known_bad) are caught by any medium+ alert.
FITTING = {
    "upload": {"upload_spike", "ratio_flip"},
    "beacon": {"beaconing"},
    "random_domain": {"random_name"},
    "swapped_binary": {"binary_changed"},
    "renamed_binary": {"impostor"},
}
# Release bar U8 (design spec v0.3): with the shipped signals on together, at most
# 1.0 medium+ false alarms per user-week, and at least 50 % detection in at least 3
# of the 5 Layer 2 scenario types.
BAR_TYPES = ("upload", "beacon", "random_domain", "swapped_binary", "renamed_binary")
BAR_FALSE_ALARMS = 1.0
BAR_RATE = 0.5
BAR_TYPES_NEEDED = 3

CAVEAT = (
    "These numbers come from short scripted sessions on GitHub's disposable Windows runners "
    "(datacenter network, no real user), stitched into simulated weeks. They compare detection "
    "layers with each other; they are **not real-world rates**."
)
GAPS = (
    "Known gaps of L0: the capture is the engine's CSV export, so the replay has no process IDs "
    "and no DNS alias chains (trackers hidden behind a site's own name are not detected here); "
    "new-app notices are not measured. Beaconing false alarms are under-measured: sessions last about "
    "8 minutes and beaconing needs 6 connections, so only check-ins every 90 s or less can show up "
    "(real telemetry every 5 to 15 minutes cannot). Connection lines carry no bytes, so the 64 KB "
    "per connection limit never rules a beacon out here (pessimistic). Each flow's bytes are spread "
    "evenly over the hours it spans, which smooths bursts across hour boundaries. Swapped programs "
    "are staged only for apps that were signed: a swap of a program that was never signed isn't "
    "detected, by design. A swapped app's later rows from other scenarios are also unsigned. "
    "The lab's synthetic DROP entry (SBL-LAB, the known_bad scenario's example.com address) is shared "
    "with other apps' traffic, such as Chrome's to Cloudflare; those hits are lab artifacts, not false "
    "alarms, and are excluded from the false-alarm counts and listed apart."
)
TARGET = 1.0  # design spec §6.6: at most 1 medium+ false alarm per user-week


def _fmt(value: float | None, unit: str = "") -> str:
    return "—" if value is None else f"{value:.2f}{unit}" if isinstance(value, float) else f"{value}{unit}"


def _artifacts(count: int) -> str:
    noun = "alert" if count == 1 else "alerts"
    return (f"{count} {noun} (any severity) from the synthetic SBL-LAB entry on other apps' traffic "
            "to shared addresses")


def _minutes(seconds: float | None) -> str:
    return "—" if seconds is None else f"{seconds / 60:.1f} min"


def parse_signals(text: str) -> set[str]:
    """'upload_spike,beaconing' -> {'upload_spike', 'beaconing'}."""
    chosen = {part.strip() for part in text.split(",") if part.strip()}
    if not chosen:
        raise ValueError(f"no signals given (known: {', '.join(SIGNALS)})")
    unknown = sorted(chosen - set(SIGNALS))
    if unknown:
        raise ValueError(f"unknown signal {', '.join(unknown)} (known: {', '.join(SIGNALS)})")
    return chosen


def only_signals(alerts: list[dict], signals: set[str]) -> list[dict]:
    """The alerts as if only `signals` were on: Layer 1 alerts always count; a
    behaviour (Layer 2) alert counts if one of its reasons is on. One whose reasons
    that are on are all info signals would have been info (and not notified).

    An estimate: with signals off, the app might also have combined or held back
    other alerts differently. Medium+ (what scoring counts) is exact per alert."""
    kept = []
    for alert in alerts:
        if alert.get("layer", 1) != 2:
            kept.append(alert)
            continue
        on = [reason for reason in alert.get("reasons", []) if reason in signals]
        if not on:
            continue
        if all(SIGNAL_SEVERITY.get(reason) == "info" for reason in on):
            alert = {**alert, "severity": "info", "notified": False}
        kept.append(alert)
    return kept


def per_signal(alerts: list[dict], labels: list[dict], info: dict, signals: list[str]) -> dict[str, Scored]:
    """Each signal on its own: the behaviour alerts it was behind, at the signal's own
    severity, scored against the labels."""
    table = {}
    for signal in signals:
        mine = [{**a, "severity": SIGNAL_SEVERITY[signal]} for a in alerts
                if a.get("layer", 1) == 2 and signal in a.get("reasons", [])]
        table[signal] = match(mine, labels, info)
    return table


def fits_type(alert: dict, kind: str) -> bool:
    """Whether an alert counts as catching a scenario of type `kind` for the release
    bar (R26): any Layer 1 alert; a behaviour alert if one of its reasons fits."""
    if alert.get("layer", 1) != 2 or kind not in FITTING:
        return True
    return bool(FITTING[kind] & set(alert.get("reasons", [])))


def release_bar(scored: Scored) -> tuple[bool, str]:
    """Release bar U8 for one scored run: whether it passes, and the report's line.
    The false-alarm figure is compared as printed (3 decimals)."""
    fa = round(scored.fa_medium_plus, 3)
    types = sum(1 for kind in BAR_TYPES if scored.per_type.get(kind, {}).get("rate", 0.0) >= BAR_RATE)
    passed = fa <= BAR_FALSE_ALARMS and types >= BAR_TYPES_NEEDED
    line = (f"Release bar: {'PASS' if passed else 'FAIL'} (false alarms {fa:.3f} ≤ {BAR_FALSE_ALARMS}; "
            f"types at ≥ {BAR_RATE * 100:.0f} %: {types} of {len(BAR_TYPES)})")
    return passed, line


def bar_check(label: str, result: str, alerts: list[dict], labels: list[dict], info: dict,
              signals: tuple[str, ...] | list[str]) -> dict:
    """The release bar for one run's alerts with `signals` on, detections by the
    fitting rule. `label` says which signals (e.g. "shipped signals")."""
    scored = match(only_signals(alerts, set(signals)), labels, info, fits=fits_type)
    passed, line = release_bar(scored)
    return {"label": label, "result": result, "signals": list(signals), "passed": passed, "line": line,
            "per_type": {kind: scored.per_type[kind]["rate"] for kind in BAR_TYPES if kind in scored.per_type}}


def _metrics(scored: Scored, signal_table: dict[str, Scored] | None = None) -> dict:
    metrics = {
        "user_weeks": scored.user_weeks,
        "alerts_in_test_week": scored.alerts_in_test_week,
        "false_alarms_per_user_week": {"medium_plus": scored.fa_medium_plus, "notified": scored.fa_notified},
        "false_alarms_medium_plus": sum(1 for a in scored.false_alarms if a["severity"] in SERIOUS),
        "lab_artifacts_excluded": len(scored.artifacts),
        "kinds": dict(scored.kinds),
        "per_type": scored.per_type,
    }
    if signal_table is not None:
        metrics["per_signal"] = {
            signal: {"alerts_in_test_week": s.alerts_in_test_week,
                     "false_alarms_per_user_week": s.fa_medium_plus,
                     "detected": {kind: e["detected"] for kind, e in s.per_type.items()}}
            for signal, s in signal_table.items()
        }
    return metrics


def write(results: list[tuple[str, Scored]], info: dict, out: Path,
          signal_tables: list[tuple[str, dict[str, Scored]]] | None = None,
          bars: list[dict] | None = None) -> None:
    """Writes the report. `signal_tables`: per result name, each Layer 2 signal on its
    own (see `per_signal`). `bars`: release-bar checks (see `bar_check`), the first
    being the one that decides."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    tables = dict(signal_tables or [])
    bars = bars or []
    metrics: dict = {name: _metrics(s, tables.get(name)) for name, s in results}
    if bars:
        metrics["release_bar"] = bars
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    names = [name for name, _ in results]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    width = 0.38
    xs = range(len(results))
    ax.bar([x - width / 2 for x in xs], [s.fa_medium_plus for _, s in results], width, label="medium and up")
    ax.bar([x + width / 2 for x in xs], [s.fa_notified for _, s in results], width, label="notified")
    ax.axhline(TARGET, color="grey", linestyle="--", linewidth=1, label="target (medium and up)")
    ax.set_xticks(list(xs), names)
    ax.set_ylabel("false alarms per user-week")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "false_alarms.png", dpi=120)
    plt.close(fig)

    types = sorted({t for _, s in results for t in s.per_type})
    fig, ax = plt.subplots(figsize=(6, 3.5))
    width = 0.8 / max(1, len(results))
    for i, (name, scored) in enumerate(results):
        rates = [scored.per_type.get(t, {}).get("rate", 0.0) for t in types]
        ax.bar([j + i * width for j in range(len(types))], rates, width, label=name)
    ax.set_xticks([j + width * (len(results) - 1) / 2 for j in range(len(types))], types, rotation=20)
    ax.set_ylim(0, 1)
    ax.set_ylabel("detection rate")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "detection.png", dpi=120)
    plt.close(fig)

    apps = sorted({f"{a.get('name') or a.get('id')} {a.get('version') or '?'}"
                   for s in info.get("sessions", []) for a in s.get("apps", []) if a.get("installed")})
    commits = sorted({s.get("engine_commit") for s in info.get("sessions", []) if s.get("engine_commit")})
    images = sorted({s.get("runner_image") for s in info.get("sessions", []) if s.get("runner_image")})
    users = info["users_per_persona"] * len(info["pools"])

    lines = [
        "# Whereabouts lab report",
        "",
        f"> {CAVEAT}",
        "",
        f"- Simulated users: {users} ({info['users_per_persona']} per persona: {', '.join(sorted(info['pools']))}), "
        f"{info['learning_days']} learning days + {info['test_days']} test days each; seed {info['seed']}",
        f"- Session pools (learning / test): "
        + ", ".join(f"{p} {v['learning']}/{v['test']}" for p, v in sorted(info["pools"].items())),
        f"- Sessions skipped (captured nothing): {len(info.get('skipped', []))}",
        f"- Engine commit: {', '.join(commits) or '—'}; runner image: {', '.join(images) or '—'}",
        f"- Apps: {', '.join(apps) or '—'}",
        "",
        "## False alarms per simulated user-week (test week)",
        "",
        "| Layers | Medium and up | Notified | Target |",
        "|---|---|---|---|",
    ]
    for name, s in results:
        lines.append(f"| {name} | {_fmt(s.fa_medium_plus)} | {_fmt(s.fa_notified)} | ≤ {TARGET:g} |")
    for name, s in results:
        lines.append("")
        lines.append(f"Lab artifacts excluded ({name}): {_artifacts(len(s.artifacts))}")
    lines += ["", "![False alarms](false_alarms.png)", "", "## Staged problems", "",
              "| Layers | Scenario | Instances | Detected | Rate | Time to detect (median / max) |",
              "|---|---|---|---|---|---|"]
    for name, s in results:
        for kind in types:
            e = s.per_type.get(kind)
            if e:
                covered = f" ({e['covered']} covered)" if e.get("covered") else ""
                lines.append(f"| {name} | {kind} | {e['instances']} | {e['detected']}{covered} | {e['rate']:.0%} | "
                             f"{_minutes(e['ttd_median'])} / {_minutes(e['ttd_max'])} |")
    lines += ["", "![Detection](detection.png)", "", "## Alerts in the test week by kind", ""]
    for name, s in results:
        kinds = ", ".join(f"{k} {v}" for k, v in sorted(s.kinds.items())) or "none"
        lines.append(f"- {name}: {kinds}")
    for name, table in tables.items():
        lines += ["", f"## Behaviour signals one by one ({name})", "",
                  "Each signal's behaviour alerts in the test week at the signal's own severity: how many, "
                  "medium+ false alarms per user-week, and scenario instances detected.", "",
                  "| Signal | Alerts | False alarms / user-week | " + " | ".join(BAR_TYPES) + " |",
                  "|---|---|---|" + "---|" * len(BAR_TYPES)]
        for signal, s in table.items():
            found = " | ".join(f"{s.per_type[kind]['detected']}/{s.per_type[kind]['instances']}"
                               if kind in s.per_type else "—" for kind in BAR_TYPES)
            lines.append(f"| {signal} | {s.alerts_in_test_week} | {_fmt(s.fa_medium_plus)} | {found} |")
    if bars:
        lines += ["", f"## Release bar (U8), {bars[0]['result']}", "",
                  f"Needs at most {BAR_FALSE_ALARMS:g} medium+ false alarm per user-week and at least "
                  f"{BAR_RATE * 100:.0f} % detection in {BAR_TYPES_NEEDED} of: {', '.join(BAR_TYPES)}. Here a "
                  "staged problem counts as detected only by a Layer 1 alert or a behaviour alert whose "
                  "reasons fit its type (upload: upload spike or ratio flip; beacon: beaconing; random_domain: "
                  "random name; swapped_binary: binary changed; renamed_binary: any), so the rates can be "
                  "lower than in the table above. The first line decides; others are for comparison.", ""]
        for bar in bars:
            lines.append(f"- **{bar['label']}** ({', '.join(bar['signals'])}): {bar['line']}")
    lines += ["", "## Notes", "", GAPS, ""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")

    summary = ["## Whereabouts lab", "", f"_{CAVEAT}_", "",
               "| Layers | False alarms / user-week (medium+) | Notified | Detected (all staged) |",
               "|---|---|---|---|"]
    for name, s in results:
        total = sum(e["instances"] for e in s.per_type.values())
        found = sum(e["detected"] for e in s.per_type.values())
        summary.append(f"| {name} | {_fmt(s.fa_medium_plus)} | {_fmt(s.fa_notified)} | {found}/{total} |")
    for name, s in results:
        if s.artifacts:
            summary += ["", f"Lab artifacts excluded ({name}): {_artifacts(len(s.artifacts))}"]
    for bar in bars:
        summary += ["", f"**{bar['label']}**, {bar['result']}: **{bar['line']}**"]
    summary += ["", "Full report and charts: the `lab-report` artifact."]
    (out / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
