"""Builds small captured-session folders for tests."""

from __future__ import annotations

import csv
import json
from pathlib import Path

HEADER = [
    "app_name", "app_path", "app_sha256", "signature", "publisher", "signature_confirmed",
    "protocol", "remote_ip", "remote_port", "domain", "domain_source", "owner", "country",
    "first_seen_unix_ms", "last_seen_unix_ms", "bytes_sent", "bytes_received", "connections",
]


def flow(app: str = "chrome.exe", ip: str = "198.51.100.1", at: int = 1000, **extra) -> dict:
    row = {
        "app_name": app, "app_path": f"C:\\Apps\\{app}", "app_sha256": "a" * 64, "signature": "valid",
        "publisher": "Example", "signature_confirmed": "true", "protocol": "TCP", "remote_ip": ip,
        "remote_port": "443", "domain": "example.org", "domain_source": "verified", "owner": "Example Ltd",
        "country": "US", "first_seen_unix_ms": str(at * 1000), "last_seen_unix_ms": str((at + 20) * 1000),
        "bytes_sent": "1000", "bytes_received": "5000", "connections": "1",
    }
    row.update({k: str(v) for k, v in extra.items()})
    return row


def write_session(root: Path, sid: str, persona: str, *, ok: bool = True, start: int = 1000,
                  flows: list[dict] | None = None, live: list[dict] | None = None,
                  counters: list[dict] | None = None, connections: list[dict] | None = None) -> Path:
    folder = root / f"session-{sid}"
    folder.mkdir(parents=True)
    with (folder / "session.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        for row in flows if flows is not None else [flow(at=start + 10)]:
            writer.writerow(row)
    meta = {
        "schema": 1, "id": sid, "persona": persona, "ok": ok, "start": start, "end": start + 600,
        "runner_image": "test", "engine_commit": "abc", "seed": 1, "apps": [],
        "counters": counters if counters is not None else [{"time": start + 5, "rejected": 0, "unattributed": 0}],
        "live": live or [],
    }
    (folder / "session.json").write_text(json.dumps(meta), encoding="utf-8")
    if connections is not None:
        lines = [json.dumps(c) if isinstance(c, dict) else c for c in connections]
        (folder / "connections.jsonl").write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return folder


def connection(app: str = "chrome.exe", at: int = 1000, destination: str = "example.org", **extra) -> dict:
    """One line of the engine's --record-connections file."""
    row = {"app_path": f"C:\\Apps\\{app}", "app_name": app, "destination": destination,
           "remote_ip": "198.51.100.1", "remote_port": 443, "time_ms": at * 1000}
    row.update(extra)
    return row
