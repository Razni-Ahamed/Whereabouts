"""Writes the lab report: report.md, summary.md, metrics.json and charts."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (after choosing the backend)

from .score import SERIOUS, Scored  # noqa: E402

CAVEAT = (
    "These numbers come from short scripted sessions on GitHub's disposable Windows runners "
    "(datacenter network, no real user), stitched into simulated weeks. They compare detection "
    "layers with each other; they are **not real-world rates**."
)
GAPS = (
    "Known gaps of L0: the capture is the engine's CSV export, so the replay has no process IDs "
    "and no DNS alias chains (trackers hidden behind a site's own name are not detected here); "
    "new-app notices are not measured."
)
TARGET = 1.0  # design spec §6.6: at most 1 medium+ false alarm per user-week


def _fmt(value: float | None, unit: str = "") -> str:
    return "—" if value is None else f"{value:.2f}{unit}" if isinstance(value, float) else f"{value}{unit}"


def _minutes(seconds: float | None) -> str:
    return "—" if seconds is None else f"{seconds / 60:.1f} min"


def _metrics(scored: Scored) -> dict:
    return {
        "user_weeks": scored.user_weeks,
        "alerts_in_test_week": scored.alerts_in_test_week,
        "false_alarms_per_user_week": {"medium_plus": scored.fa_medium_plus, "notified": scored.fa_notified},
        "false_alarms_medium_plus": sum(1 for a in scored.false_alarms if a["severity"] in SERIOUS),
        "kinds": dict(scored.kinds),
        "per_type": scored.per_type,
    }


def write(results: list[tuple[str, Scored]], info: dict, out: Path) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps({name: _metrics(s) for name, s in results}, indent=2),
                                      encoding="utf-8")
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
    lines += ["", "## Notes", "", GAPS, ""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")

    summary = ["## Whereabouts lab", "", f"_{CAVEAT}_", "",
               "| Layers | False alarms / user-week (medium+) | Notified | Detected (all staged) |",
               "|---|---|---|---|"]
    for name, s in results:
        total = sum(e["instances"] for e in s.per_type.values())
        found = sum(e["detected"] for e in s.per_type.values())
        summary.append(f"| {name} | {_fmt(s.fa_medium_plus)} | {_fmt(s.fa_notified)} | {found}/{total} |")
    summary += ["", "Full report and charts: the `lab-report` artifact."]
    (out / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
