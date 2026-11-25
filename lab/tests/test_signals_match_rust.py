"""The lab's copy of the signal table must match the shipped Rust code."""

from __future__ import annotations

import re
from pathlib import Path

from wlab import report

ROOT = Path(__file__).resolve().parents[2]
SIGNALS_RS = ROOT / "crates" / "detect" / "src" / "signals.rs"
# The severity table lives with the store's `Signal` (`Signal::severity`), so
# the store can keep an alert's most severe reasons; `severity_of` uses it.
REASONS_RS = ROOT / "crates" / "store" / "src" / "reasons.rs"


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def rust_source() -> str:
    return SIGNALS_RS.read_text(encoding="utf-8")


def body(text: str, start: str) -> str:
    """The text of the `{ ... }` block that follows `start`."""
    at = text.index(start)
    open_at = text.index("{", at)
    depth = 0
    for i in range(open_at, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[open_at:i + 1]
    raise AssertionError(f"no block after {start!r}")


def test_severities_match_severity_of():
    assert "signal.severity()" in body(rust_source(), "pub fn severity_of")
    arms = re.findall(r"((?:\|?\s*Self::\w+\s*)+)=>\s*\{?\s*Severity::(\w+)",
                      body(REASONS_RS.read_text(encoding="utf-8"), "pub fn severity(self)"))
    rust = {snake(signal): severity.lower()
            for signals, severity in arms for signal in re.findall(r"Self::(\w+)", signals)}
    assert len(rust) == 9
    assert report.SIGNAL_SEVERITY == rust
    assert set(report.SIGNALS) == set(rust)


def test_shipped_set_matches_toggles_default():
    default = body(rust_source(), "impl Default for Toggles")
    # Every signal is on except those compared away: `(s, s != Signal::Beaconing)`.
    off = {snake(name) for name in re.findall(r"s != Signal::(\w+)", default)}
    assert off == {"beaconing"}
    assert set(report.SHIPPED) == set(report.SIGNALS) - off
