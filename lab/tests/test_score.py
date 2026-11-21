from __future__ import annotations

import json

from wlab import report, score
from wlab.timeline import DAY, T0

TEST = T0 + 7 * DAY  # first second of the test week
INFO = {"t0": T0, "learning_days": 7, "test_days": 7, "users_per_persona": 2, "seed": 1,
        "pools": {"office": {"learning": 2, "test": 2}}, "skipped": [], "sessions": []}


def alert(user="office-1", time=TEST + 100, app="chat.exe", severity="medium", kind="bad_network",
          notified=True, path=None):
    return {"user": user, "time": time, "layer": 1, "kind": kind, "severity": severity,
            "app_name": app, "app_path": path, "target": None, "detail": None, "reasons": [],
            "notified": notified}


def label(kind="upload", user="office-1", start=TEST + 50, end=TEST + 50 + 3600, app="chat.exe"):
    return {"scenario": f"{kind}-{user}", "type": kind, "user": user, "app_name": app,
            "app_path": None, "start": start, "end": end, "live": False}


def test_match_boundaries():
    lab = label()
    on_edge = alert(time=lab["end"] + 3600)
    past_edge = alert(time=lab["end"] + 3601)
    learning = alert(time=TEST - 10)
    scored = score.match([on_edge, past_edge, learning], [lab], INFO)
    assert scored.per_type["upload"]["detected"] == 1
    assert len(scored.false_alarms) == 1 and scored.false_alarms[0]["time"] == lab["end"] + 3601


def test_other_user_or_app_does_not_match():
    lab = label()
    scored = score.match([alert(user="office-2"), alert(app="game.exe")], [lab], INFO)
    assert scored.per_type["upload"]["detected"] == 0
    assert len(scored.false_alarms) == 2


def test_health_alert_in_test_week_is_false_alarm():
    scored = score.match([alert(app=None, kind="faked_dns")], [label()], INFO)
    assert len(scored.false_alarms) == 1
    assert scored.kinds == {"faked_dns": 1}


def test_rates_per_user_week():
    alerts = [alert(time=TEST + 10_000 * i, notified=(i == 0)) for i in range(3)]
    alerts.append(alert(severity="info", notified=False))
    scored = score.match(alerts, [], INFO)
    assert scored.user_weeks == 2
    assert scored.fa_medium_plus == 1.5
    assert scored.fa_notified == 0.5


def test_detection_and_time_to_detect():
    labels = [label(kind="beacon", user="office-1"), label(kind="beacon", user="office-2")]
    alerts = [alert(user="office-1", time=TEST + 50 + 600)]
    scored = score.match(alerts, labels, INFO)
    beacon = scored.per_type["beacon"]
    assert beacon["instances"] == 2 and beacon["detected"] == 1 and beacon["rate"] == 0.5
    assert beacon["ttd_median"] == 600 and beacon["ttd_max"] == 600


def test_learning_week_labels_are_not_counted():
    early = label(kind="known_bad", start=T0 + DAY, end=T0 + DAY + 30)
    early["live"] = True
    scored = score.match([], [early], INFO)
    assert scored.per_type == {}


def test_report_files_written(tmp_path):
    scored = score.match([alert()], [label()], INFO)
    report.write([("Layer 1", scored)], INFO, tmp_path)
    for name in ("report.md", "summary.md", "metrics.json", "false_alarms.png", "detection.png"):
        assert (tmp_path / name).exists(), name
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "not real-world rates" in text
    assert "Layer 1" in (tmp_path / "summary.md").read_text(encoding="utf-8")
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["Layer 1"]["user_weeks"] == 2


def test_info_alert_never_detects():
    scored = score.match([alert(severity="info", kind="tracker", notified=False)], [label()], INFO)
    assert scored.per_type["upload"]["detected"] == 0
    assert scored.false_alarms == [] or all(a["severity"] == "info" for a in scored.false_alarms)
    assert scored.fa_medium_plus == 0


def test_same_day_repeat_is_covered():
    # The detector alerts once per app and address a day: a second instance
    # the same day, after the user was already warned, counts as covered.
    first = label(kind="known_bad", start=TEST + 100, end=TEST + 110)
    first["scenario"] = "kb-1"
    second = label(kind="known_bad", start=TEST + 7200, end=TEST + 7210)
    second["scenario"] = "kb-2"
    scored = score.match([alert(time=TEST + 105, severity="high")], [first, second], INFO)
    entry = scored.per_type["known_bad"]
    assert entry["instances"] == 2 and entry["detected"] == 2
    assert entry["covered"] == 1
    assert entry["ttd_max"] == 5  # covered instances have no delay of their own
