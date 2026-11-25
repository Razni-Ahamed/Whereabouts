from __future__ import annotations

import json

import pytest

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


def bar_result(fa: float, rates: dict[str, float]) -> score.Scored:
    per_type = {kind: {"instances": 2, "detected": round(rate * 2), "covered": 0, "rate": rate,
                       "ttd_median": None, "ttd_max": None} for kind, rate in rates.items()}
    return score.Scored(user_weeks=10, per_type=per_type, fa_medium_plus=fa)


def test_release_bar_pass_and_fail():
    three = {"upload": 1.0, "beacon": 0.5, "random_domain": 0.5, "swapped_binary": 0.0, "renamed_binary": 0.0}
    two = {**three, "random_domain": 0.0}
    passed, line = report.release_bar(bar_result(0.8, three))
    assert passed
    assert line == "Release bar: PASS (false alarms 0.80 ≤ 1.0; types at ≥ 50 %: 3 of 5)"
    passed, line = report.release_bar(bar_result(1.2, three))
    assert not passed
    assert line == "Release bar: FAIL (false alarms 1.20 ≤ 1.0; types at ≥ 50 %: 3 of 5)"
    passed, line = report.release_bar(bar_result(0.5, two))
    assert not passed
    assert line == "Release bar: FAIL (false alarms 0.50 ≤ 1.0; types at ≥ 50 %: 2 of 5)"
    # Only the five Layer 2 scenario types count; missing ones count as 0 %.
    passed, _ = report.release_bar(bar_result(0.0, {"known_bad": 1.0, "upload": 1.0, "beacon": 1.0}))
    assert not passed


def behaviour(reasons, severity="medium", time=TEST + 100, app="chat.exe"):
    return {**alert(time=time, app=app, severity=severity, kind="behaviour"), "layer": 2, "reasons": reasons}


def test_only_signals_keeps_layer1_and_matching_behaviour_alerts():
    layer1 = alert()
    spike = behaviour(["upload_spike"], severity="high")
    mixed = behaviour(["new_site", "random_name"])
    kept = report.only_signals([layer1, spike, mixed], {"new_site"})
    assert kept[0] == layer1
    assert len(kept) == 2
    # With only new site on, the alert would have been info.
    assert kept[1]["severity"] == "info" and kept[1]["notified"] is False
    assert report.only_signals([mixed], {"random_name"}) == [mixed]
    with pytest.raises(ValueError, match="unknown signal"):
        report.parse_signals("upload_spike,bogus")
    assert report.parse_signals("upload_spike, beaconing") == {"upload_spike", "beaconing"}


def test_per_signal_table(tmp_path):
    labels = [label(kind="upload"), label(kind="beacon", start=TEST + 20_000, end=TEST + 30_000)]
    alerts = [behaviour(["upload_spike"], severity="high", time=TEST + 200),
              behaviour(["beaconing", "new_site"], time=TEST + 21_000),
              behaviour(["beaconing"], time=TEST + 200_000)]  # matches nothing
    table = report.per_signal(alerts, labels, INFO, sorted(report.SIGNALS))
    assert table["upload_spike"].per_type["upload"]["detected"] == 1
    assert table["beaconing"].per_type["beacon"]["detected"] == 1
    assert table["beaconing"].fa_medium_plus == 0.5  # 1 false alarm, 2 user-weeks
    assert table["new_site"].alerts_in_test_week == 1
    assert table["new_site"].fa_medium_plus == 0  # info on its own
    results = [("Layers 1+2", score.match(alerts, labels, INFO))]
    report.write(results, INFO, tmp_path, signal_tables=[("Layers 1+2", table)],
                 bar=("Layers 1+2", sorted(report.SIGNALS)))
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "| upload_spike | 1 |" in text
    assert "Release bar: FAIL" in text
    assert "Release bar: FAIL" in (tmp_path / "summary.md").read_text(encoding="utf-8")
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["release_bar"]["passed"] is False
    assert metrics["Layers 1+2"]["per_signal"]["beaconing"]["alerts_in_test_week"] == 2


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


def test_report_command_scores_the_chosen_signals(tmp_path, capsys):
    from wlab import cli

    data = tmp_path / "dataset"
    data.mkdir()
    upload = label(kind="upload")
    cli.write_jsonl(data / "labels.jsonl", [upload])
    (data / "info.json").write_text(json.dumps(INFO), encoding="utf-8")
    cli.write_jsonl(data / "layer1.jsonl", [alert(time=TEST + 200_000)])
    spike = behaviour(["upload_spike"], severity="high", time=TEST + 200)
    unusual = behaviour(["new_country"], time=TEST + 300_000)
    cli.write_jsonl(data / "layer2.jsonl", [alert(time=TEST + 200_000), spike, unusual])
    out = tmp_path / "report"
    cli.main(["report", "--timeline-dir", str(data), "--alerts", f"Layer 1={data / 'layer1.jsonl'}",
              "--alerts", f"Layers 1+2={data / 'layer2.jsonl'}", "--signals", "upload_spike",
              "--out", str(out)])
    metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["release_bar"]["result"] == "Layers 1+2"
    assert metrics["release_bar"]["signals"] == ["upload_spike"]
    # new_country is off: its alert is gone, so only the Layer 1 false alarm is left.
    assert metrics["Layers 1+2"]["false_alarms_medium_plus"] == 1
    assert metrics["Layers 1+2"]["per_type"]["upload"]["detected"] == 1
    assert list(metrics["Layers 1+2"]["per_signal"]) == ["upload_spike"]
    assert "Release bar: FAIL" in capsys.readouterr().out
