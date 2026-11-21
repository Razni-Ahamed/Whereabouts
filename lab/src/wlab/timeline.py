"""Stitches short captured sessions into simulated user-weeks.

Each simulated user has one persona and lives 14 simulated days: a
learning week (days 1-7, design spec D15) and a test week (days 8-14).
Each day places a few of the persona's sessions at hours the persona is
usually active, shifting their times. **No leakage:** per persona the
sessions are split (seeded) into a learning pool and a test pool, so a
user's test week never reuses a session from its learning week.
"""

from __future__ import annotations

import random
from collections import defaultdict

from .sessions import Session

DAY = 86_400
HOUR = 3_600
# Simulated time starts at a fixed midnight (UTC), far from real capture dates.
T0 = 1_800_000_000 - 1_800_000_000 % DAY
LEARNING_DAYS = 7
TEST_DAYS = 7

# Hours (UTC, simulated) at which each persona tends to be active.
PERSONA_HOURS: dict[str, range] = {
    "office": range(8, 18),
    "media": range(17, 24),
    "gamer": range(15, 24),
    "developer": range(9, 20),
}


def _split(group: list[Session], rng: random.Random) -> tuple[list[Session], list[Session]]:
    shuffled = group[:]
    rng.shuffle(shuffled)
    half = len(shuffled) // 2
    return shuffled[:half], shuffled[half:]


def build(
    sessions: list[Session],
    users_per_persona: int,
    seed: int,
    learning_days: int = LEARNING_DAYS,
    test_days: int = TEST_DAYS,
    sessions_per_day: int = 2,
) -> tuple[list[dict], list[dict], dict]:
    """Returns (timeline rows sorted by time, live labels, info)."""
    rng = random.Random(seed)
    skipped = [s.id for s in sessions if not s.ok]
    by_persona: dict[str, list[Session]] = defaultdict(list)
    for session in sessions:
        if session.ok:
            by_persona[session.persona].append(session)

    rows: list[dict] = []
    labels: list[dict] = []
    pools: dict[str, dict[str, int]] = {}
    days = learning_days + test_days
    for persona in sorted(by_persona):
        group = sorted(by_persona[persona], key=lambda s: s.id)
        learn, test = _split(group, rng)
        if not learn or not test:
            raise ValueError(
                f"{persona}: {len(group)} usable session{'s' if len(group) != 1 else ''}; "
                "need at least 2 (separate ones for the learning and the test week)"
            )
        pools[persona] = {"learning": len(learn), "test": len(test)}
        hours = list(PERSONA_HOURS.get(persona, range(8, 22)))
        for number in range(1, users_per_persona + 1):
            user = f"{persona}-{number}"
            for day in range(1, days + 1):
                pool = learn if day <= learning_days else test
                for hour in sorted(rng.sample(hours, min(sessions_per_day, len(hours)))):
                    session = rng.choice(pool)
                    shift = T0 + (day - 1) * DAY + hour * HOUR - session.start
                    _place(session, user, day, hour, shift, rows, labels)
    rows.sort(key=lambda r: (r["first_seen"] if r["type"] == "flow" else r["time"]))
    info = {"seed": seed, "users_per_persona": users_per_persona, "pools": pools,
            "skipped": skipped, "learning_days": learning_days, "test_days": test_days, "t0": T0}
    return rows, labels, info


def _place(session: Session, user: str, day: int, hour: int, shift: int,
           rows: list[dict], labels: list[dict]) -> None:
    day_start = T0 + (day - 1) * DAY
    day_end = day_start + DAY - 1

    def clamp(t: int) -> int:  # a flow from the engine's first seconds stays in its day
        return min(max(t + shift, day_start), day_end)

    for flow in session.flows:
        row = {"type": "flow", "user": user, "day": day, "session": session.id, **flow,
               "first_seen": clamp(flow["first_seen"]), "last_seen": clamp(flow["last_seen"]),
               "scenario": None}
        rows.append(row)
    for sample in session.counters:
        rows.append({"type": "counters", "user": user, "day": day, "session": session.id,
                     "time": clamp(int(sample["time"])),
                     "rejected": int(sample.get("rejected") or 0),
                     "unattributed": int(sample.get("unattributed") or 0)})
    for live in session.live:
        label = {**live, "scenario": f"{live['scenario']}@{user}-d{day}-h{hour}", "user": user,
                 "start": clamp(int(live["start"])), "end": clamp(int(live["end"])), "live": True}
        labels.append(label)
