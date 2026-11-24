"""Matches alerts to scenario labels and computes the lab's metrics.

- An alert **matches** a scenario instance when it is for the same user and
  app (and program path, when both are known) and falls between the
  instance's start and its end plus a grace period.
- Only **medium and higher** alerts detect anything: info alerts (tracker
  contacts) are background, never a detection and never a medium+ false alarm.
- Health alerts (no app) never match: in L0 no scenario stages evasion.
- The detector alerts once per app and address a day, so an instance after
  one already detected for the same user, app and scenario type **the same
  simulated day** counts as **covered** (detected, with no delay of its own).
- Only the **test week** counts: learning-week alerts and labels are left out.
- **False alarm** = a test-week alert that matches nothing; reported per
  simulated user-week, at medium and above, and as "notified" (what the app
  would have pushed).
"""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field

from .timeline import DAY

GRACE = 3_600
SERIOUS = {"medium", "high", "critical"}


@dataclass
class Scored:
    user_weeks: float
    false_alarms: list[dict] = field(default_factory=list)
    per_type: dict[str, dict] = field(default_factory=dict)
    fa_medium_plus: float = 0.0
    fa_notified: float = 0.0
    kinds: Counter = field(default_factory=Counter)
    alerts_in_test_week: int = 0


def _matches(alert: dict, label: dict, grace: int) -> bool:
    if alert["severity"] not in SERIOUS:
        return False
    if alert.get("app_name") is None or alert["user"] != label["user"]:
        return False
    if alert["app_name"] != label.get("app_name"):
        return False
    if alert.get("app_path") and label.get("app_path") and alert["app_path"] != label["app_path"]:
        return False
    return label["start"] <= alert["time"] <= label["end"] + grace


def match(alerts: list[dict], labels: list[dict], info: dict, grace: int = GRACE) -> Scored:
    test_start = info["t0"] + info["learning_days"] * DAY
    users = info["users_per_persona"] * len(info["pools"])
    scored = Scored(user_weeks=users * info["test_days"] / 7)

    in_test = [a for a in alerts if a["time"] >= test_start]
    test_labels = [label for label in labels if label["start"] >= test_start]
    first_hit: dict[str, int] = {}
    for alert in sorted(in_test, key=lambda a: a["time"]):
        scored.kinds[alert["kind"]] += 1
        hits = [label for label in test_labels if _matches(alert, label, grace)]
        if hits:
            for label in hits:
                first_hit.setdefault(label["scenario"], alert["time"] - label["start"])
        else:
            scored.false_alarms.append(alert)
    scored.alerts_in_test_week = len(in_test)

    t0 = info["t0"]
    detected_days: set[tuple] = set()
    for label in sorted(test_labels, key=lambda lab: lab["start"]):
        entry = scored.per_type.setdefault(
            label["type"], {"instances": 0, "detected": 0, "covered": 0, "delays": []})
        entry["instances"] += 1
        day_key = (label["user"], label.get("app_name"), label["type"], (label["start"] - t0) // DAY)
        if label["scenario"] in first_hit:
            entry["detected"] += 1
            entry["delays"].append(max(0, first_hit[label["scenario"]]))
            detected_days.add(day_key)
        elif day_key in detected_days:
            entry["detected"] += 1
            entry["covered"] += 1
    for entry in scored.per_type.values():
        delays = entry.pop("delays")
        entry["rate"] = entry["detected"] / entry["instances"]
        entry["ttd_median"] = statistics.median(delays) if delays else None
        entry["ttd_max"] = max(delays) if delays else None

    if scored.user_weeks:
        serious = [a for a in scored.false_alarms if a["severity"] in SERIOUS]
        notified = [a for a in scored.false_alarms if a.get("notified")]
        scored.fa_medium_plus = len(serious) / scored.user_weeks
        scored.fa_notified = len(notified) / scored.user_weeks
    return scored
