"""Synthetic scenarios: rows added to a timeline's test week, with labels.

They stand for problems that must not be staged for real (design spec
§6.6, lab design §9): nothing is sent anywhere. Each instance targets an
app the user ran in its learning week, starts at a moment the user was
active in the test week, and gets a label with its time window.

- upload: 200 MB or more sent in one hour to a new destination
- beacon: small connections every 60 s +/- 5 s for 3 hours to one new host:
  `connection` lines (when each was opened) plus one flow row with their bytes
- random_domain: 5 connections to random-looking names not on any list
- swapped_binary: the app's program changes (new SHA-256, unsigned: a swapped
  vendor program can't keep the vendor's valid signature) and it reaches
  3 new destinations
"""

from __future__ import annotations

import math
import random
from collections import Counter

from .timeline import DAY, HOUR, T0

TYPES = ("upload", "beacon", "random_domain", "swapped_binary")
UPLOAD_BYTES = 200_000_000
BEACON_SPAN = 3 * HOUR
_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def parse_counts(text: str) -> dict[str, int]:
    """'upload=1,beacon=2' -> {'upload': 1, 'beacon': 2}."""
    counts: dict[str, int] = {}
    for part in filter(None, (p.strip() for p in text.split(","))):
        name, _, value = part.partition("=")
        if name not in TYPES:
            raise ValueError(f"unknown scenario {name!r} (known: {', '.join(TYPES)})")
        counts[name] = int(value or 1)
    return counts


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def _random_name(rng: random.Random) -> str:
    while True:
        name = "".join(rng.choice(_ALNUM) for _ in range(rng.randint(14, 18)))
        if _entropy(name) >= 3.5:
            return f"{name}.{rng.choice(('com', 'net', 'info'))}"


def _new_ip(rng: random.Random) -> str:
    # Documentation range (TEST-NET-3): never a real host, never on a list.
    return f"203.0.113.{rng.randint(1, 254)}"


def _row(template: dict, at: int, **changes) -> dict:
    row = {**template, "first_seen": at, "last_seen": at + 2, "day": (at - T0) // DAY + 1,
           "session": "synthetic", "connections": 1}
    row.update(changes)
    return row


def _connection(template: dict, at: int, destination: str) -> dict:
    """A connection line (timeline schema 2): when one connection was opened."""
    return {"type": "connection", "user": template["user"], "day": (at - T0) // DAY + 1,
            "session": "synthetic", "app_path": template["app_path"], "app_name": template["app_name"],
            "destination": destination, "time": at, "scenario": template["scenario"]}


def add(rows: list[dict], labels: list[dict], seed: int, per_user: dict[str, int]) -> tuple[list[dict], list[dict]]:
    """Returns new lists with the scenarios added (rows sorted by time)."""
    rng = random.Random(seed)
    out = [dict(r) for r in rows]
    labels = list(labels)
    end_of_test = T0 + 14 * DAY
    users = sorted({r["user"] for r in out if r["type"] == "flow"})
    # Apps used by live scenarios are left alone, so their genuine alerts
    # never look like detections of a synthetic scenario.
    staged = {label.get("app_name") for label in labels if label.get("live")}
    for user in users:
        flows = [r for r in out if r["type"] == "flow" and r["user"] == user]
        learned = sorted({r["app_name"] for r in flows if r["day"] <= 7} - staged)
        # Beaconing is learned per program file: apps without a path are never profiled.
        with_path = sorted({r["app_name"] for r in flows if r["day"] <= 7 and r.get("app_path")} - staged)
        active = [r for r in flows if r["day"] >= 8 and not r.get("scenario")]
        if not learned or not active:
            continue
        for kind in TYPES:
            for k in range(per_user.get(kind, 0)):
                candidates = with_path if kind == "beacon" else learned
                if not candidates:
                    continue
                app = rng.choice(candidates)
                template = next(r for r in flows if r["app_name"] == app and r["day"] <= 7)
                anchor = rng.choice(active)
                start = min(anchor["first_seen"], end_of_test - BEACON_SPAN - 600)
                scenario = f"{kind}-{user}-{k + 1}"
                base = {**template, "user": user, "scenario": scenario}
                if kind == "upload":
                    ip, host = _new_ip(rng), f"files-{rng.randrange(16**6):06x}.example.net"
                    for i in range(12):
                        out.append(_row(base, start + i * 300, remote_ip=ip, domain=host,
                                        domain_source="verified", bytes_sent=UPLOAD_BYTES // 12 + 1,
                                        bytes_received=(UPLOAD_BYTES // 12) // 100))
                    end = start + HOUR
                elif kind == "beacon":
                    ip, host = _new_ip(rng), f"cdn-{rng.randrange(16**6):06x}.example.org"
                    times = []
                    t = start
                    while t + 65 <= start + BEACON_SPAN:
                        times.append(t)
                        t += 60 + rng.randint(-5, 5)
                    # As the engine sees it: one flow (same program and server) whose
                    # connection count rises, and when each connection was opened.
                    out.append(_row(base, start, remote_ip=ip, domain=host, domain_source="verified",
                                    last_seen=times[-1], connections=len(times),
                                    bytes_sent=1000 * len(times), bytes_received=1000 * len(times)))
                    out.extend(_connection(base, at, host) for at in times)
                    end = start + BEACON_SPAN
                elif kind == "random_domain":
                    for i in range(5):
                        out.append(_row(base, start + i * 120, remote_ip=_new_ip(rng), domain=_random_name(rng),
                                        domain_source="verified", owner=None, bytes_sent=800, bytes_received=4000))
                    end = start + 10 * 60
                else:  # swapped_binary
                    new_hash = f"{rng.getrandbits(256):064x}"
                    for row in out:
                        if (row["type"] == "flow" and row["user"] == user and row["app_name"] == app
                                and row["first_seen"] >= start):
                            row.update(app_sha256=new_hash, signature="unsigned", publisher=None)
                    for i in range(3):
                        out.append(_row(base, start + 60 + i * 300, remote_ip=_new_ip(rng),
                                        domain=f"upd-{rng.randrange(16**6):06x}.example.com",
                                        domain_source="verified", app_sha256=new_hash,
                                        signature="unsigned", publisher=None,
                                        bytes_sent=5000, bytes_received=20000))
                    end = start + HOUR
                labels.append({"scenario": scenario, "type": kind, "user": user, "app_name": app,
                               "app_path": template.get("app_path"), "start": start, "end": end,
                               "live": False})
    out.sort(key=lambda r: (r["first_seen"] if r["type"] == "flow" else r["time"]))
    return out, labels
