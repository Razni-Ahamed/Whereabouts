from __future__ import annotations

import csv

import pytest

from helpers import HEADER, flow, write_session
from wlab import sessions, timeline

DAY = 86_400


def make(tmp_path, persona="office", count=4, **kw):
    for i in range(count):
        write_session(tmp_path, f"{persona}-{i}", persona, start=1000 + i, **kw)
    return sessions.load(tmp_path)


def test_reads_quoted_and_guarded_fields(tmp_path):
    folder = write_session(tmp_path, "q", "office", flows=[])
    with (folder / "session.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerow(flow(owner="Google, LLC", domain="'=evil.example", app_path=""))
    [session] = sessions.load(tmp_path)
    [row] = session.flows
    assert row["owner"] == "Google, LLC"
    assert row["domain"] == "=evil.example"
    assert row["app_path"] is None
    assert row["first_seen"] == 1000 and row["remote_port"] == 443


def test_skips_failed_sessions(tmp_path):
    write_session(tmp_path, "bad", "office", ok=False)
    loaded = make(tmp_path, count=2)
    assert len(loaded) == 3
    rows, _, info = timeline.build(loaded, users_per_persona=1, seed=1)
    assert info["skipped"] == ["bad"]
    assert all("bad" not in row.get("session", "") for row in rows)


def test_learning_and_test_pools_disjoint(tmp_path):
    rows, _, info = timeline.build(make(tmp_path, count=6), users_per_persona=3, seed=7)
    for user in {r["user"] for r in rows}:
        learn = {r["session"] for r in rows if r["user"] == user and r["day"] <= 7}
        test = {r["session"] for r in rows if r["user"] == user and r["day"] > 7}
        assert learn and test and not (learn & test)
    assert info["pools"]["office"] == {"learning": 3, "test": 3}


def test_deterministic_for_seed(tmp_path):
    loaded = make(tmp_path, count=4)
    assert timeline.build(loaded, 2, seed=3)[0] == timeline.build(loaded, 2, seed=3)[0]
    assert timeline.build(loaded, 2, seed=3)[0] != timeline.build(loaded, 2, seed=4)[0]


def test_times_fall_inside_their_day(tmp_path):
    rows, _, _ = timeline.build(make(tmp_path, count=4), 2, seed=1)
    assert {r["day"] for r in rows} == set(range(1, 15))
    for row in rows:
        t = row["first_seen"] if row["type"] == "flow" else row["time"]
        assert (t - timeline.T0) // DAY + 1 == row["day"]
    times = [r["first_seen"] if r["type"] == "flow" else r["time"] for r in rows]
    assert times == sorted(times)


def test_too_few_sessions_is_an_error(tmp_path):
    with pytest.raises(ValueError, match=r"media: 1 usable session"):
        timeline.build(make(tmp_path, persona="media", count=1), 1, seed=1)


def test_live_labels_shift_with_their_session(tmp_path):
    live = [{"scenario": "s-knownbad", "type": "known_bad", "app_name": "curl.exe",
             "app_path": "C:\\Windows\\System32\\curl.exe", "start": 1030, "end": 1040,
             "addresses": ["93.184.215.14"]}]
    loaded = [s for s in make(tmp_path, count=2, live=live)]
    rows, labels, _ = timeline.build(loaded, 1, seed=2)
    assert labels, "live labels are carried into the timeline"
    for label in labels:
        assert label["live"] is True and label["user"] == "office-1"
        assert label["end"] - label["start"] == 10
        # 30 s after its session's start (sessions start at 1000/1001, placed on the hour)
        assert (label["start"] - timeline.T0) % 3600 in (29, 30)
        assert label["addresses"] == ["93.184.215.14"]
    assert len({label["scenario"] for label in labels}) == len(labels)
