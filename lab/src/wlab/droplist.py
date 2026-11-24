"""The lab's DROP list: Spamhaus' real list plus test entries.

The known_bad live scenario fetches example.com; its addresses, recorded
in the session labels, are added as `SBL-LAB` entries so the shipped
detector treats them as listed. Spamhaus' files are downloaded by the
workflow and never put into an artifact (they may not be redistributed).
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

FILES = {4: "drop_v4.json", 6: "drop_v6.json"}


def build(labels: list[dict], real: Path | None, out: Path) -> int:
    """Writes drop_v4.json / drop_v6.json to `out`; returns the test entries added."""
    out.mkdir(parents=True, exist_ok=True)
    texts = {v: "" for v in FILES}
    if real is not None:
        for version, name in FILES.items():
            path = real / name
            if path.exists():
                texts[version] = path.read_text(encoding="utf-8")
    added = set()
    for label in labels:
        if label.get("type") != "known_bad":
            continue
        for address in label.get("addresses") or []:
            ip = ipaddress.ip_address(address)
            added.add((ip.version, f"{ip}/{ip.max_prefixlen}"))
    for version, cidr in sorted(added):
        line = json.dumps({"cidr": cidr, "sblid": "SBL-LAB", "rir": "lab"})
        if texts[version] and not texts[version].endswith("\n"):
            texts[version] += "\n"
        texts[version] += line + "\n"
    for version, name in FILES.items():
        (out / name).write_text(texts[version], encoding="utf-8")
    return len(added)
