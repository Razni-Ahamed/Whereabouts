//! `whereabouts-lab-replay`: runs a lab timeline through the shipped
//! detection code and writes the alerts as JSON Lines (see `lab/README.md`).

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use whereabouts_enrich::{DropList, Enricher};
use whereabouts_lab_replay::{replay, timeline};

const USAGE: &str = "usage: whereabouts-lab-replay --timeline <timeline.jsonl> --data <dir> \
[--lists <dir>] [--layers 1] --out <alerts.jsonl>";

struct Options {
    timeline: PathBuf,
    data: PathBuf,
    lists: Option<PathBuf>,
    out: PathBuf,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let (mut timeline, mut data, mut lists, mut out) = (None, None, None, None);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--timeline" => timeline = Some(PathBuf::from(value()?)),
            "--data" => data = Some(PathBuf::from(value()?)),
            "--lists" => lists = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--layers" => {
                let layers = value()?;
                if layers != "1" {
                    return Err(format!("--layers {layers}: only Layer 1 exists so far"));
                }
            }
            "--help" | "-h" => return Err(String::from(USAGE)),
            other => return Err(format!("unknown option {other:?}\n{USAGE}")),
        }
    }
    Ok(Options {
        timeline: timeline.ok_or(USAGE)?,
        data: data.ok_or(USAGE)?,
        lists,
        out: out.ok_or(USAGE)?,
    })
}

fn run(options: &Options) -> Result<usize, String> {
    let text = std::fs::read_to_string(&options.timeline)
        .map_err(|e| format!("{}: {e}", options.timeline.display()))?;
    let lines = timeline::parse(&text)?;
    let (enricher, _) = Enricher::load(&options.data);
    let drop = match &options.lists {
        Some(dir) => DropList::load(dir).map_err(|e| format!("{}: {e}", dir.display()))?,
        None => None,
    };
    if drop.is_none() {
        eprintln!("note: no Spamhaus DROP list given; risky-network alerts are off");
    }
    let work = std::env::temp_dir().join(format!("whereabouts-lab-replay-{}", std::process::id()));
    let alerts = replay::run(&lines, &enricher, drop.as_ref(), &work)?;
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(&options.out)
            .map_err(|e| format!("{}: {e}", options.out.display()))?,
    );
    for alert in &alerts {
        let line = serde_json::to_string(alert).map_err(|e| e.to_string())?;
        writeln!(file, "{line}").map_err(|e| e.to_string())?;
    }
    file.flush().map_err(|e| e.to_string())?;
    Ok(alerts.len())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse_args(&args).and_then(|options| run(&options));
    match result {
        Ok(count) => {
            eprintln!("{count} alerts");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
