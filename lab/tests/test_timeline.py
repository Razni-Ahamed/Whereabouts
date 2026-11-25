from __future__ import annotations

import csv

import pytest

from helpers import HEADER, connection, flow, write_session
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


def test_drops_runner_infrastructure(tmp_path):
    flows = [flow(app=name, at=1010) for name in (
        "Runner.Worker.exe", "Runner.Listener.exe", "WindowsAzureGuestAgent.exe", "WaAppAgent.exe",
        "hosted-compute-agent", "provjobd.exe2979537984", "chrome.exe")]
    write_session(tmp_path, "r", "office", flows=flows)
    [session] = sessions.load(tmp_path)
    assert [f["app_name"] for f in session.flows] == ["chrome.exe"]
    assert session.meta["dropped_runner_flows"] == 6


def test_counters_keep_growing_across_sessions(tmp_path):
    # Each captured session's counters start at 0; a simulated user's engine runs on,
    # so stitched counters must only grow, or later increases would go unseen.
    counters = [{"time": 1005, "rejected": 0, "unattributed": 0},
                {"time": 1100, "rejected": 2, "unattributed": 5}]
    loaded = make(tmp_path, count=2, counters=counters)
    rows, _, _ = timeline.build(loaded, 1, seed=1)
    samples = [r for r in rows if r["type"] == "counters"]
    assert len(samples) == 14 * 2 * 2  # 14 days, 2 sessions a day, 2 samples each
    unattributed = [r["unattributed"] for r in samples]
    assert unattributed == sorted(unattributed)
    assert unattributed[-1] == 5 * 28  # every placed session added its 5
    assert [r["rejected"] for r in samples][-1] == 2 * 28


def test_persona_without_usable_sessions_is_an_error(tmp_path):
    make(tmp_path, persona="office", count=2)
    write_session(tmp_path, "media-0", "media", ok=False)
    with pytest.raises(ValueError, match=r"media: 0 usable sessions \(of 1\)"):
        timeline.build(sessions.load(tmp_path), 1, seed=1)


def test_no_sessions_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="no usable sessions"):
        timeline.build([], 1, seed=1)


def test_recorded_connections_become_connection_lines(tmp_path):
    lines = [connection(at=1010), connection(at=1070, time_ms=1070_999),
             connection(app="Runner.Worker.exe", at=1020), connection(app="x.exe", at=1030, app_path=""),
             '{"app_path": "C:\\Apps\\cut']  # the engine stopped mid-line
    loaded = make(tmp_path, count=2, connections=lines)
    assert [c["time"] for c in loaded[0].connections] == [1010, 1070]
    rows, _, _ = timeline.build(loaded, 1, seed=1)
    flows = [r for r in rows if r["type"] == "flow"]
    placed = [r for r in rows if r["type"] == "connection"]
    assert len(placed) == 14 * 2 * 2  # 14 days, 2 sessions a day, 2 connections each
    for line in placed:
        assert set(line) >= {"user", "app_path", "app_name", "destination", "time", "day", "session"}
        assert line["app_path"] == "C:\\Apps\\chrome.exe" and line["destination"] == "example.org"
        assert (line["time"] - timeline.T0) // DAY + 1 == line["day"]
        # Shifted with its session, like its flows. Sessions start at 1000 + i with their
        # flow 10 s in; the connections are at 1010 and 1070 in both.
        flow_time = max(f["first_seen"] for f in flows if f["session"] == line["session"]
                        and f["user"] == line["user"] and f["first_seen"] <= line["time"] + 1)
        i = int(line["session"].rsplit("-", 1)[1])
        assert line["time"] - flow_time + i in (0, 60)
    times = [r["first_seen"] if r["type"] == "flow" else r["time"] for r in rows]
    assert times == sorted(times)


def test_sessions_without_a_connection_file_still_load(tmp_path):
    loaded = make(tmp_path, count=2)
    assert all(s.connections == [] for s in loaded)
    rows, _, _ = timeline.build(loaded, 1, seed=1)
    assert not [r for r in rows if r["type"] == "connection"]
