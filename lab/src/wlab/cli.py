"""The lab's command line: `lab timeline` and `lab report`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import sessions, timeline

TIMELINE_SCHEMA = 1


def write_jsonl(path: Path, rows: list[dict], header: dict | None = None) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        if header is not None:
            f.write(json.dumps(header) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def cmd_timeline(args: argparse.Namespace) -> None:
    loaded = sessions.load(args.sessions)
    rows, labels, info = timeline.build(loaded, args.users_per_persona, args.seed)
    if args.inject:
        from . import inject

        counts = inject.parse_counts(args.inject)
        rows, labels = inject.add(rows, labels, seed=args.seed, per_user=counts)
        info["injected_per_user"] = counts
    info["sessions"] = [
        {"id": s.id, "persona": s.persona, "ok": s.ok, "flows": len(s.flows),
         "dropped_runner_flows": s.meta.get("dropped_runner_flows", 0),
         "runner_image": s.meta.get("runner_image"), "engine_commit": s.meta.get("engine_commit"),
         "apps": s.meta.get("apps", [])}
        for s in loaded
    ]
    args.out.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out / "timeline.jsonl", rows, header={"type": "header", "schema": TIMELINE_SCHEMA})
    write_jsonl(args.out / "labels.jsonl", labels)
    (args.out / "info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    for warning in info["skipped"]:
        print(f"warning: session {warning} captured nothing and was skipped", file=sys.stderr)
    print(f"{len(rows)} timeline rows, {len(labels)} labels, users per persona: {args.users_per_persona}")


def cmd_report(args: argparse.Namespace) -> None:
    from . import report, score

    labels = read_jsonl(args.timeline_dir / "labels.jsonl")
    info = json.loads((args.timeline_dir / "info.json").read_text(encoding="utf-8"))
    results = []
    for spec in args.alerts:
        name, _, path = spec.partition("=")
        results.append((name, score.match(read_jsonl(Path(path)), labels, info)))
    report.write(results, info, args.out)
    print((args.out / "summary.md").read_text(encoding="utf-8"))


def cmd_droplist(args: argparse.Namespace) -> None:
    from . import droplist

    added = droplist.build(read_jsonl(args.labels), args.real, args.out)
    print(f"lab DROP list: {added} test entries" + ("" if args.real else " (no Spamhaus list given)"))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="lab", description="Whereabouts lab (never shipped)")
    sub = parser.add_subparsers(dest="command", required=True)

    t = sub.add_parser("timeline", help="captured sessions -> simulated user-weeks")
    t.add_argument("--sessions", type=Path, required=True)
    t.add_argument("--users-per-persona", type=int, default=3)
    t.add_argument("--seed", type=int, default=1)
    t.add_argument("--inject", default="", help="e.g. upload=1,beacon=1,random_domain=1,swapped_binary=1")
    t.add_argument("--out", type=Path, required=True)
    t.set_defaults(func=cmd_timeline)

    r = sub.add_parser("report", help="alerts + labels -> report")
    r.add_argument("--timeline-dir", type=Path, required=True)
    r.add_argument("--alerts", action="append", required=True, help='"Layer 1=alerts.jsonl" (repeatable)')
    r.add_argument("--out", type=Path, required=True)
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("droplist", help="Spamhaus DROP + the lab's test entries -> a lists folder")
    d.add_argument("--labels", type=Path, required=True)
    d.add_argument("--real", type=Path, default=None, help="folder with Spamhaus' drop_v4.json / drop_v6.json")
    d.add_argument("--out", type=Path, required=True)
    d.set_defaults(func=cmd_droplist)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
