"""Reads captured lab sessions: the engine's CSV export plus session.json."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

# Text the export guarded against spreadsheet formulas gets a leading "'".
_RISKY = ("=", "+", "-", "@")

INT_FIELDS = ("remote_port", "bytes_sent", "bytes_received", "connections")
TEXT_FIELDS = (
    "app_name", "app_path", "app_sha256", "protocol", "remote_ip",
    "domain", "domain_source", "owner", "country",
)


@dataclass
class Session:
    id: str
    persona: str
    ok: bool
    start: int
    end: int
    flows: list[dict] = field(default_factory=list)
    counters: list[dict] = field(default_factory=list)
    live: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def unguard(text: str) -> str:
    """Undoes the export's formula guard ("'=x" back to "=x")."""
    if text.startswith("'"):
        rest = text[1:]
        if rest[:1] in ("\t", "\r") or rest.lstrip(" \t\r\n").startswith(_RISKY):
            return rest
    return text


def read_flows(path: Path) -> list[dict]:
    """The export's rows as timeline flow fields (times in Unix seconds)."""
    flows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            flow: dict = {}
            for name in TEXT_FIELDS:
                value = unguard(row.get(name) or "")
                flow[name] = value or None
            for name in INT_FIELDS:
                flow[name] = int(row.get(name) or 0)
            flow["first_seen"] = int(row["first_seen_unix_ms"]) // 1000
            flow["last_seen"] = int(row["last_seen_unix_ms"]) // 1000
            flows.append(flow)
    return flows


def load(root: Path) -> list[Session]:
    """Every session folder (one holding session.json) under `root`, by id."""
    found = []
    for meta_path in sorted(Path(root).rglob("session.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
        csv_path = meta_path.with_name("session.csv")
        flows = read_flows(csv_path) if csv_path.exists() else []
        found.append(Session(
            id=str(meta["id"]),
            persona=meta["persona"],
            ok=bool(meta.get("ok")) and bool(flows),
            start=int(meta["start"]),
            end=int(meta["end"]),
            flows=flows,
            counters=list(meta.get("counters") or []),
            live=list(meta.get("live") or []),
            meta=meta,
        ))
    return sorted(found, key=lambda s: s.id)
