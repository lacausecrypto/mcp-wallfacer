use std::{collections::BTreeMap, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use serde::Serialize;
use std::path::PathBuf;

use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    finding::{Finding, FindingKind},
    fuzz_corpus::FuzzCorpus,
    mutate::GenMode,
    run::{DestructiveDetector, FuzzPlan, Reporter},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct FuzzArgs {
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long)]
    pub iterations: Option<u64>,
    #[arg(long, value_enum, default_value_t = FuzzMode::Mixed)]
    pub mode: FuzzMode,
    #[arg(long)]
    pub include: Vec<String>,
    #[arg(long)]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub max_tools: Option<usize>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Exit with status `2` when at least one tool was skipped because its
    /// schema could not be generated.
    #[arg(long)]
    pub coverage_strict: bool,
    /// Phase R — enable the persistent fuzz corpus. Inputs that
    /// trigger findings or produce a previously-unseen response
    /// fingerprint are saved under
    /// `<corpus_dir>/../fuzz_corpus/<tool>/`. Subsequent runs read
    /// the corpus and mutate from it 90 % of the time. The
    /// remaining 10 % stays pure schema-driven random.
    #[arg(long)]
    pub corpus_feedback: bool,
    /// Override the corpus directory (defaults to a sibling of
    /// `[output] corpus_dir`).
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,
    /// Phase R — fraction of iterations that mutate from the
    /// corpus instead of generating a fresh schema-driven payload.
    /// Range `0.0..=1.0`. Default `0.9` matches AFL convention.
    #[arg(long, default_value_t = 0.9)]
    pub mutate_ratio: f64,
    /// Phase AC.2 (v0.8) — repeat the fuzz plan `N` times with
    /// derived seeds (master_seed + run_index) and collect every
    /// finding. Combined with `--aggregate`, the per-run output
    /// is suppressed and a single aggregate report is emitted at
    /// the end with each finding tagged `stable` (every run),
    /// `flaky` (some runs), or `one-shot` (only one run). Useful
    /// for separating real bugs from environment / scheduling
    /// noise before filing them upstream.
    #[arg(long, default_value_t = 1)]
    pub runs: u32,
    /// Phase AC.2 — emit an aggregate flakiness report instead of
    /// the per-run JSON. Requires `--runs > 1`.
    #[arg(long, requires = "runs")]
    pub aggregate: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FuzzMode {
    Conform,
    Adversarial,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl From<FuzzMode> for GenMode {
    fn from(value: FuzzMode) -> Self {
        match value {
            FuzzMode::Conform => GenMode::Conform,
            FuzzMode::Adversarial => GenMode::Adversarial,
            FuzzMode::Mixed => GenMode::Mixed,
        }
    }
}

pub async fn run(args: FuzzArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    if args.runs == 0 {
        bail!("--runs must be at least 1");
    }
    if args.aggregate && args.runs < 2 {
        bail!("--aggregate requires --runs >= 2");
    }

    // Phase R — enable the persistent fuzz corpus when requested.
    // Default location is `<corpus_dir>/../fuzz_corpus/`, sibling
    // to the findings corpus, so cleaning `.wallfacer/` clears
    // both atomically.
    let fuzz_corpus = if args.corpus_feedback {
        let dir = args.corpus_dir.clone().unwrap_or_else(|| {
            let findings_dir = PathBuf::from(&config.output.corpus_dir);
            findings_dir
                .parent()
                .map(|p| p.join("fuzz_corpus"))
                .unwrap_or_else(|| PathBuf::from(".wallfacer/fuzz_corpus"))
        });
        Some(FuzzCorpus::new(dir))
    } else {
        None
    };

    let base_seed = args.seed.unwrap_or_else(rand::random);

    let make_plan = |seed: u64| -> Result<FuzzPlan> {
        Ok(FuzzPlan {
            iterations: args.iterations.unwrap_or(200),
            mode: args.mode.into(),
            master_seed: seed,
            include: args.include.clone(),
            exclude: args.exclude.clone(),
            max_tools: args.max_tools,
            timeout: Duration::from_millis(config.target.timeout_ms),
            transport_name: config.target.transport_name().to_string(),
            detector: DestructiveDetector::from_config(
                &config.destructive,
                &config.allow_destructive,
            )
            .context("invalid destructive / allowlist regex in config")?,
            severity: config.severity.clone(),
            fuzz_corpus: fuzz_corpus.clone(),
            mutate_ratio: args.mutate_ratio,
        })
    };

    if args.dry_run {
        let plan = make_plan(base_seed)?;
        for name in plan.dry_run(&client).await? {
            println!("{name}");
        }
        client.shutdown().await.ok();
        return Ok(());
    }

    // Phase AC.2 — flakiness tracker. Each run uses
    // `master_seed = base_seed + i` so the iteration sequence
    // differs across runs (different inputs probed) but stays
    // reproducible. Findings stream into the configured corpus
    // exactly as in single-run mode; the aggregate output
    // replaces the per-run stdout.
    if args.aggregate {
        let mut all_findings: Vec<(u32, Finding)> = Vec::new();
        let mut total_skipped = 0usize;
        for run_index in 0..args.runs {
            let seed = base_seed.wrapping_add(run_index as u64);
            let plan = make_plan(seed)?;
            let mut reporter = CapturingReporter::default();
            let report = plan.execute(&mut client, &corpus, &mut reporter).await?;
            for finding in reporter.findings {
                all_findings.push((run_index, finding));
            }
            total_skipped += report.skipped.len();
        }
        client.shutdown().await.ok();

        let report = aggregate_findings(args.runs, &all_findings);
        let any_findings = !report.aggregate.is_empty();
        match args.format {
            OutputFormat::Json => {
                let body = serde_json::to_string_pretty(&report)
                    .context("failed to render aggregate JSON")?;
                println!("{body}");
            }
            OutputFormat::Human => print_aggregate_human(&report),
        }

        if any_findings {
            std::process::exit(1);
        }
        if args.coverage_strict && total_skipped > 0 {
            std::process::exit(2);
        }
        return Ok(());
    }

    let plan = make_plan(base_seed)?;
    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => Box::new(HumanReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
    };
    let report = plan
        .execute(&mut client, &corpus, reporter.as_mut())
        .await?;
    client.shutdown().await.ok();

    if report.findings_count > 0 {
        std::process::exit(1);
    }
    if args.coverage_strict && !report.skipped.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

/// Reporter that captures every finding into a `Vec` without any
/// other side effects. Used by `--runs N --aggregate` so the
/// per-run output doesn't pollute stdout.
#[derive(Default)]
struct CapturingReporter {
    findings: Vec<Finding>,
}

impl Reporter for CapturingReporter {
    fn on_finding(&mut self, finding: &Finding) {
        self.findings.push(finding.clone());
    }
}

#[derive(Serialize)]
struct AggregateReport {
    runs: u32,
    aggregate: Vec<AggregateEntry>,
}

#[derive(Serialize)]
struct AggregateEntry {
    /// Bucket key — `(tool, kind_keyword, invariant_or_step_name)`,
    /// hashed into one stable string. v0.8.1 widened this from
    /// `Finding::id` (which hashes the full input) so that fuzz
    /// findings with mutated payloads can still merge into the
    /// same bucket. Inputs differ → ids differ → without this they
    /// were always tagged `one-shot`, even for transport-level
    /// bugs that fire on every payload.
    bucket: String,
    tool: String,
    kind: String,
    /// Number of distinct `Finding::id`s grouped into this bucket.
    /// Useful for sanity-checking: a deterministic crash bucket
    /// should have `unique_inputs == 1`; a transport flake will
    /// have `unique_inputs == occurrences`.
    unique_inputs: u32,
    occurrences: u32,
    /// `stable` (occurrences == runs), `flaky` (1 < occurrences <
    /// runs), or `one-shot` (occurrences == 1).
    label: &'static str,
    /// First instance seen. Carries the seed that triggered it,
    /// so `wallfacer corpus replay <sample.id>` reproduces.
    sample: Finding,
}

/// v0.8.1 — aggregation key. Identifies a *logical* bug class
/// rather than a single (input, response) pair:
/// - tool name
/// - kind keyword (`crash`, `hang`, `protocol_error`, ...)
/// - for property/sequence findings, the invariant / sequence
///   name; otherwise empty
///
/// Coarser than `Finding::id` (which also hashes the input) but
/// matches what an operator actually wants to know: did the same
/// invariant fail across N runs, regardless of what payload
/// triggered it each time.
fn bucket_key(finding: &Finding) -> String {
    let kind_detail: &str = match &finding.kind {
        FindingKind::PropertyFailure { invariant } => invariant,
        FindingKind::SequenceFailure { sequence, .. } => sequence,
        _ => "",
    };
    format!(
        "{}|{}|{}",
        finding.tool,
        finding.kind.keyword(),
        kind_detail
    )
}

fn aggregate_findings(runs: u32, all: &[(u32, Finding)]) -> AggregateReport {
    // Group by `bucket_key` so the same logical bug across N runs
    // collapses to one entry — even when the input mutated. Track
    // which run indices saw each bucket and which distinct
    // Finding::ids fell into it.
    let mut groups: BTreeMap<
        String,
        (
            Finding,
            std::collections::BTreeSet<u32>,
            std::collections::BTreeSet<String>,
        ),
    > = BTreeMap::new();
    for (run_index, finding) in all {
        let key = bucket_key(finding);
        groups
            .entry(key)
            .and_modify(|(_, runs_seen, ids_seen)| {
                runs_seen.insert(*run_index);
                ids_seen.insert(finding.id.clone());
            })
            .or_insert_with(|| {
                let mut runs = std::collections::BTreeSet::new();
                runs.insert(*run_index);
                let mut ids = std::collections::BTreeSet::new();
                ids.insert(finding.id.clone());
                (finding.clone(), runs, ids)
            });
    }
    let mut entries: Vec<AggregateEntry> = groups
        .into_iter()
        .map(|(bucket, (sample, runs_seen, ids_seen))| {
            let occurrences = runs_seen.len() as u32;
            let label = if occurrences == runs {
                "stable"
            } else if occurrences == 1 {
                "one-shot"
            } else {
                "flaky"
            };
            AggregateEntry {
                bucket,
                tool: sample.tool.clone(),
                kind: sample.kind.keyword().to_string(),
                unique_inputs: ids_seen.len() as u32,
                occurrences,
                label,
                sample,
            }
        })
        .collect();
    // Sort: stable first, then flaky, then one-shot. Within each,
    // higher occurrences first, then by tool name for stability.
    entries.sort_by(|a, b| {
        let order = |label: &str| match label {
            "stable" => 0,
            "flaky" => 1,
            _ => 2,
        };
        order(a.label)
            .cmp(&order(b.label))
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| a.tool.cmp(&b.tool))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    AggregateReport {
        runs,
        aggregate: entries,
    }
}

fn print_aggregate_human(report: &AggregateReport) {
    println!("Flakiness aggregate over {} runs:", report.runs);
    if report.aggregate.is_empty() {
        println!("  (no findings)");
        return;
    }
    for entry in &report.aggregate {
        let inputs_note = if entry.unique_inputs > 1 {
            format!(", {} distinct inputs", entry.unique_inputs)
        } else {
            String::new()
        };
        println!(
            "  [{}] {} {} ({}/{} runs{}) \u{2014} sample id={}",
            entry.label,
            entry.tool,
            entry.kind,
            entry.occurrences,
            report.runs,
            inputs_note,
            entry.sample.id
        );
    }
}
