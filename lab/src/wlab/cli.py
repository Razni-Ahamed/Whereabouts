"""The lab's command line: `lab timeline` and `lab report`."""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from . import sessions, timeline

TIMELINE_SCHEMA = 2


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
         "connections": len(s.connections),
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
    # By default, what ships; the tables are scored with these signals on.
    chosen = args.signals if args.signals is not None else set(report.SHIPPED)
    signals = [signal for signal in report.SIGNALS if signal in chosen]
    runs: list[tuple[str, list[dict]]] = []
    for spec in args.alerts:
        name, _, path = spec.partition("=")
        runs.append((name, read_jsonl(Path(path))))
    names = [name for name, _ in runs]
    if args.bar is not None and args.bar not in names:
        args.parser.error(f"--bar {args.bar}: no --alerts with that name (given: {', '.join(names)})")
    # The release bar and the per-signal table are for the named run, or else the last
    # run with Layer 2 alerts.
    with_layer2 = [name for name, alerts in runs if any(a.get("layer") == 2 for a in alerts)]
    bar_name = args.bar or (with_layer2[-1] if with_layer2 else names[-1])
    if args.bar is None and not with_layer2:
        print(f"warning: no run has Layer 2 alerts; checking the release bar on {bar_name!r}", file=sys.stderr)
    bar_alerts = dict(runs)[bar_name]

    results = [(name, score.match(report.only_signals(alerts, chosen), labels, info)) for name, alerts in runs]
    table = report.per_signal(bar_alerts, labels, info, list(report.SIGNALS))
    label = "chosen signals" if args.signals is not None else "shipped signals"
    bars = [report.bar_check(label, bar_name, bar_alerts, labels, info, signals)]
    if args.signals is None:
        bars.append(report.bar_check("every signal on, beaconing too (not shipped)", bar_name, bar_alerts,
                                     labels, info, report.SIGNALS))
    report.write(results, info, args.out, signal_tables=[(bar_name, table)], bars=bars)
    print((args.out / "summary.md").read_text(encoding="utf-8"))


def _signals(text: str) -> set[str]:
    from . import report

    try:
        return report.parse_signals(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def cmd_droplist(args: argparse.Namespace) -> None:
    from . import droplist

    added = droplist.build(read_jsonl(args.labels), args.real, args.out)
    print(f"lab DROP list: {added} test entries" + ("" if args.real else " (no Spamhaus list given)"))


def main(argv: list[str] | None = None) -> None:
    # The report's text has "≤" and "—"; a Windows console may default to a code page without them.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
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
    r.add_argument("--alerts", action="append", required=True,
                   help='"Layer 1=alerts.jsonl" (repeatable)')
    r.add_argument("--signals", type=_signals, default=None,
                   help="score only these Layer 2 signals, e.g. upload_spike,beaconing (default: the ones "
                        "that ship, plus a second release-bar line with every signal on)")
    r.add_argument("--bar", default=None,
                   help="the --alerts name to check the release bar on (default: the last with Layer 2 alerts)")
    r.add_argument("--out", type=Path, required=True)
    r.set_defaults(func=cmd_report, parser=r)

    d = sub.add_parser("droplist", help="Spamhaus DROP + the lab's test entries -> a lists folder")
    d.add_argument("--labels", type=Path, required=True)
    d.add_argument("--real", type=Path, default=None, help="folder with Spamhaus' drop_v4.json / drop_v6.json")
    d.add_argument("--out", type=Path, required=True)
    d.set_defaults(func=cmd_droplist)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
