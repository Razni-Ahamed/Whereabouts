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
    assert line == "Release bar: PASS (false alarms 0.800 ≤ 1.0; types at ≥ 50 %: 3 of 5)"
    passed, line = report.release_bar(bar_result(1.2, three))
    assert not passed
    assert line == "Release bar: FAIL (false alarms 1.200 ≤ 1.0; types at ≥ 50 %: 3 of 5)"
    passed, line = report.release_bar(bar_result(0.5, two))
    assert not passed
    assert line == "Release bar: FAIL (false alarms 0.500 ≤ 1.0; types at ≥ 50 %: 2 of 5)"
    # Only the five Layer 2 scenario types count; missing ones count as 0 %.
    passed, _ = report.release_bar(bar_result(0.0, {"known_bad": 1.0, "upload": 1.0, "beacon": 1.0}))
    assert not passed
    # Compared as printed: 1.0004 shows as 1.000, so it passes.
    passed, line = report.release_bar(bar_result(1.0004, three))
    assert passed and "false alarms 1.000 ≤" in line
    passed, _ = report.release_bar(bar_result(1.0006, three))
    assert not passed


def test_bar_counts_only_fitting_reasons():
    upload, beacon = label(kind="upload"), label(kind="beacon", start=TEST + 20_000, end=TEST + 30_000)
    off_topic = behaviour(["new_company"], time=TEST + 200)  # during the upload, but not about it
    fitting = behaviour(["beaconing"], time=TEST + 21_000)
    general = score.match([off_topic, fitting], [upload, beacon], INFO)
    assert general.per_type["upload"]["detected"] == 1
    bar = score.match([off_topic, fitting], [upload, beacon], INFO, fits=report.fits_type)
    assert bar.per_type["upload"]["detected"] == 0
    assert bar.per_type["beacon"]["detected"] == 1
    assert bar.false_alarms == []  # caused by a staged problem: never a false alarm
    for kind, reasons in [("upload", ["ratio_flip"]), ("upload", ["upload_spike"]),
                          ("random_domain", ["new_site", "random_name"]), ("swapped_binary", ["binary_changed"]),
                          ("renamed_binary", ["new_country"])]:
        assert report.fits_type(behaviour(reasons), kind), (kind, reasons)
    assert not report.fits_type(behaviour(["new_site", "new_company"]), "random_domain")
    assert report.fits_type(alert(), "upload")  # a Layer 1 alert always fits


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
    bars = [report.bar_check("shipped signals", "Layers 1+2", alerts, labels, INFO, report.SHIPPED)]
    report.write(results, INFO, tmp_path, signal_tables=[("Layers 1+2", table)], bars=bars)
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "| upload_spike | 1 |" in text
    assert "Release bar: FAIL" in text
    assert "Release bar: FAIL" in (tmp_path / "summary.md").read_text(encoding="utf-8")
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["release_bar"][0]["passed"] is False
    assert metrics["release_bar"][0]["label"] == "shipped signals"
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


def report_dataset(tmp_path):
    """A dataset with a Layer 1 run and a Layers 1+2 run; returns (folder, alerts args)."""
    from wlab import cli

    data = tmp_path / "dataset"
    data.mkdir()
    cli.write_jsonl(data / "labels.jsonl", [label(kind="upload"),
                                            label(kind="beacon", start=TEST + 20_000, end=TEST + 30_000)])
    (data / "info.json").write_text(json.dumps(INFO), encoding="utf-8")
    cli.write_jsonl(data / "layer1.jsonl", [alert(time=TEST + 200_000)])
    spike = behaviour(["upload_spike"], severity="high", time=TEST + 200)
    beacon = behaviour(["beaconing"], time=TEST + 21_000)
    country = behaviour(["new_country"], time=TEST + 300_000)
    cli.write_jsonl(data / "layer2.jsonl", [alert(time=TEST + 200_000), spike, beacon, country])
    return data, ["--alerts", f"Layer 1={data / 'layer1.jsonl'}", "--alerts", f"Layers 1+2={data / 'layer2.jsonl'}"]


def run_report(tmp_path, data, extra):
    from wlab import cli

    out = tmp_path / "report"
    cli.main(["report", "--timeline-dir", str(data), *extra, "--out", str(out)])
    return json.loads((out / "metrics.json").read_text(encoding="utf-8"))


def test_report_command_scores_the_chosen_signals(tmp_path, capsys):
    data, alerts = report_dataset(tmp_path)
    metrics = run_report(tmp_path, data, [*alerts, "--signals", "upload_spike"])
    [bar] = metrics["release_bar"]
    assert bar["result"] == "Layers 1+2" and bar["signals"] == ["upload_spike"]
    # new_country and beaconing are off: only the Layer 1 false alarm is left.
    assert metrics["Layers 1+2"]["false_alarms_medium_plus"] == 1
    assert metrics["Layers 1+2"]["per_type"]["upload"]["detected"] == 1
    assert "beacon" not in {k for k, v in metrics["Layers 1+2"]["per_type"].items() if v["detected"]}
    # Each signal on its own is shown for all of them.
    assert list(metrics["Layers 1+2"]["per_signal"]) == list(report.SIGNALS)
    assert "Release bar: FAIL" in capsys.readouterr().out


def test_report_command_checks_what_ships_and_everything(tmp_path, capsys):
    data, alerts = report_dataset(tmp_path)
    metrics = run_report(tmp_path, data, alerts)
    shipped, everything = metrics["release_bar"]
    assert shipped["signals"] == list(report.SHIPPED) and "beaconing" not in shipped["signals"]
    assert everything["signals"] == list(report.SIGNALS)
    assert "not shipped" in everything["label"]
    # Beaconing is off in what ships: its detection does not count there.
    assert metrics["Layers 1+2"]["per_type"]["beacon"]["detected"] == 0
    text = (tmp_path / "report" / "report.md").read_text(encoding="utf-8")
    assert text.count("Release bar: ") == 2


def test_report_command_picks_the_layer2_run_or_the_named_one(tmp_path, capsys):
    data, alerts = report_dataset(tmp_path)
    swapped = [alerts[2], alerts[3], alerts[0], alerts[1]]  # Layers 1+2 first
    metrics = run_report(tmp_path, data, swapped)
    assert metrics["release_bar"][0]["result"] == "Layers 1+2"
    metrics = run_report(tmp_path, data, [*swapped, "--bar", "Layer 1"])
    assert metrics["release_bar"][0]["result"] == "Layer 1"
    capsys.readouterr()
    metrics = run_report(tmp_path, data, alerts[:2])  # no Layer 2 alerts anywhere
    assert metrics["release_bar"][0]["result"] == "Layer 1"
    assert "no run has Layer 2 alerts" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run_report(tmp_path, data, [*alerts, "--bar", "Layer 3"])


def test_report_command_rejects_unknown_signals(tmp_path, capsys):
    data, alerts = report_dataset(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        run_report(tmp_path, data, [*alerts, "--signals", "upload_spike,bogus"])
    assert stopped.value.code == 2
    assert "unknown signal bogus" in capsys.readouterr().err


def test_report_command_rejects_empty_signals(tmp_path, capsys):
    data, alerts = report_dataset(tmp_path)
    for empty in ("", " , "):
        with pytest.raises(SystemExit) as stopped:
            run_report(tmp_path, data, [*alerts, "--signals", empty])
        assert stopped.value.code == 2
        assert "no signals" in capsys.readouterr().err


def test_sbl_lab_hit_on_another_app_is_an_artifact_not_a_false_alarm():
    known_bad = label(kind="known_bad", app="curl.exe")
    hit = {**alert(app="curl.exe"), "detail": "93.184.215.0/24 (SBL-LAB)"}
    other = {**alert(app="chrome.exe", time=TEST + 200), "detail": "104.20.0.0/16 (SBL-LAB)"}
    real_drop = {**alert(app="chrome.exe", time=TEST + 300), "detail": "1.10.16.0/20 (SBL549867)"}
    scored = score.match([hit, other, real_drop], [known_bad], INFO)
    assert scored.per_type["known_bad"]["detected"] == 1
    assert scored.artifacts == [other]
    assert scored.false_alarms == [real_drop]
    assert scored.fa_medium_plus == pytest.approx(1 / scored.user_weeks)
    assert scored.fa_notified == pytest.approx(1 / scored.user_weeks)


def test_report_prints_the_artifact_count(tmp_path):
    other = {**alert(app="chrome.exe"), "detail": "104.20.0.0/16 (SBL-LAB)"}
    scored = score.match([other], [], INFO)
    report.write([("Layer 1", scored)], INFO, tmp_path)
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Lab artifacts excluded (Layer 1): 1 alerts from the synthetic SBL-LAB entry" in text
    assert "lab artifacts, not false alarms" in text
