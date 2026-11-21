from __future__ import annotations

import math
from collections import Counter

from helpers import flow, write_session
from wlab import inject, sessions, timeline

ALL = {"upload": 1, "beacon": 1, "random_domain": 1, "swapped_binary": 1}


def base(tmp_path, users=2, seed=5):
    for i in range(4):
        write_session(tmp_path, f"office-{i}", "office", start=1000 + i,
                      flows=[flow(app="chrome.exe", at=1010 + i), flow(app="teams.exe", ip="198.51.100.9", at=1020 + i)])
    rows, labels, _ = timeline.build(sessions.load(tmp_path), users, seed=seed)
    return rows, labels


def injected(tmp_path, counts=ALL, seed=9):
    rows, labels = base(tmp_path)
    return inject.add(rows, labels, seed=seed, per_user=counts)


def of(rows, labels, kind):
    instances = [label for label in labels if label["type"] == kind]
    ids = {label["scenario"] for label in instances}
    return instances, [r for r in rows if r.get("scenario") in ids]


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def test_upload_shape(tmp_path):
    rows, labels = injected(tmp_path)
    instances, extra = of(rows, labels, "upload")
    assert len(instances) == 2  # one per user
    for label in instances:
        mine = [r for r in extra if r["scenario"] == label["scenario"]]
        sent = sum(r["bytes_sent"] for r in mine)
        assert sent >= 200_000_000
        assert sum(r["bytes_received"] for r in mine) < 0.05 * sent
        assert all(label["start"] <= r["first_seen"] <= label["start"] + 3600 for r in mine)
        assert label["end"] - label["start"] == 3600
        assert len({(r["remote_ip"], r["domain"]) for r in mine}) == 1


def test_beacon_period_and_span(tmp_path):
    rows, labels = injected(tmp_path)
    for label in [label for label in labels if label["type"] == "beacon"]:
        times = sorted(r["first_seen"] for r in rows if r.get("scenario") == label["scenario"])
        gaps = [b - a for a, b in zip(times, times[1:])]
        assert all(55 <= g <= 65 for g in gaps)
        assert 3 * 3600 - 120 <= times[-1] - times[0] <= 3 * 3600
        assert len({r["remote_ip"] for r in rows if r.get("scenario") == label["scenario"]}) == 1


def test_random_domain_entropy(tmp_path):
    rows, labels = injected(tmp_path)
    _, extra = of(rows, labels, "random_domain")
    assert len(extra) == 10  # 5 per user
    for row in extra:
        name, _, tld = row["domain"].rpartition(".")
        assert tld in ("com", "net", "info")
        assert 14 <= len(name) <= 18 and name.isalnum() and name == name.lower()
        assert entropy(name) >= 3.5
        assert row["domain_source"] == "verified"


def test_swapped_binary_changes_hash_after_start_only(tmp_path):
    rows, labels = injected(tmp_path, counts={"swapped_binary": 1})
    for label in labels:
        if label["type"] != "swapped_binary":
            continue
        app_rows = [r for r in rows if r["type"] == "flow" and r["user"] == label["user"]
                    and r["app_name"] == label["app_name"]]
        before = {r["app_sha256"] for r in app_rows if r["first_seen"] < label["start"]}
        after = {r["app_sha256"] for r in app_rows if r["first_seen"] >= label["start"]}
        assert before and after and not (before & after)
        assert len(after) == 1 and len(next(iter(after))) == 64
        new = [r for r in app_rows if r.get("scenario") == label["scenario"]]
        assert len(new) == 3


def test_only_in_test_week(tmp_path):
    rows, labels = injected(tmp_path)
    assert all(r["day"] >= 8 for r in rows if r.get("scenario"))
    assert all(label["start"] >= timeline.T0 + 7 * timeline.DAY for label in labels if not label["live"])


def test_labels_match_rows(tmp_path):
    rows, labels = injected(tmp_path)
    for label in labels:
        assert label["live"] is False
        assert label["user"] in {"office-1", "office-2"}
        assert any(r.get("scenario") == label["scenario"] for r in rows)
        assert label["app_name"] in {"chrome.exe", "teams.exe"}  # an app the user ran while learning
    times = [r["first_seen"] if r["type"] == "flow" else r["time"] for r in rows]
    assert times == sorted(times)


def test_deterministic_for_seed(tmp_path):
    a = injected(tmp_path / "a", seed=3)
    b = injected(tmp_path / "b", seed=3)
    c = injected(tmp_path / "c", seed=4)
    assert a[1] == b[1] and a[1] != c[1]


def test_parse_counts():
    assert inject.parse_counts("upload=2, beacon=1") == {"upload": 2, "beacon": 1}
    assert inject.parse_counts("") == {}
