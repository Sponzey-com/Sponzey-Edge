use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use edge_memory_harness::{
    parse_macos_ps_rss_bytes, BaselineEvent, BaselineLifecycle, BaselineProfile, BaselineReport,
    HarnessError, MemorySample,
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("memory baseline failed: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), HarnessError> {
    let options = parse_options(&args)?;
    let mut lifecycle = BaselineLifecycle::new();
    lifecycle.transition(BaselineEvent::PreflightPassed)?;
    if std::env::consts::OS != "macos" {
        lifecycle.transition(BaselineEvent::Failed)?;
        return Err(HarnessError::new(
            "the Task 001 baseline sampler supports macOS only",
        ));
    }
    let process_start_identity = process_field(options.pid, "lstart=")?;
    lifecycle.transition(BaselineEvent::ChildReady)?;

    let started = Instant::now();
    let mut samples = Vec::with_capacity(options.sample_count);
    for index in 0..options.sample_count {
        let rss = process_field(options.pid, "rss=")?;
        samples.push(MemorySample {
            elapsed_ms: started
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| HarnessError::new("memory baseline elapsed time exceeds u64"))?,
            rss_bytes: parse_macos_ps_rss_bytes(&rss)?,
        });
        lifecycle.transition(BaselineEvent::SampleCollected)?;
        if index + 1 < options.sample_count {
            thread::sleep(Duration::from_millis(options.interval_ms));
        }
    }

    let report = BaselineReport::new(
        BaselineProfile {
            scenario: options.scenario,
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            build_identity: options.build_identity,
            process_start_identity,
        },
        options.connection_count,
        samples,
    )?;
    atomic_write(&options.output, report.to_canonical_json()?.as_bytes())?;
    lifecycle.transition(BaselineEvent::ReportWritten)?;
    Ok(())
}

struct Options {
    pid: u32,
    scenario: String,
    build_identity: String,
    connection_count: usize,
    output: PathBuf,
    sample_count: usize,
    interval_ms: u64,
}

fn parse_options(args: &[String]) -> Result<Options, HarnessError> {
    let mut values = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let name = args[index].as_str();
        if !matches!(
            name,
            "--pid"
                | "--scenario"
                | "--build-identity"
                | "--connections"
                | "--output"
                | "--samples"
                | "--interval-ms"
        ) || index + 1 >= args.len()
        {
            return Err(HarnessError::new("memory baseline arguments are invalid"));
        }
        if values
            .insert(name.to_string(), args[index + 1].clone())
            .is_some()
        {
            return Err(HarnessError::new("memory baseline argument is duplicated"));
        }
        index += 2;
    }
    let value = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| HarnessError::new(format!("missing {name}")))
    };
    let parse = |name: &str| -> Result<usize, HarnessError> {
        value(name)?
            .parse::<usize>()
            .map_err(|_| HarnessError::new(format!("invalid {name}")))
    };
    let sample_count = values
        .get("--samples")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| HarnessError::new("invalid --samples"))?
        .unwrap_or(3);
    if sample_count == 0 {
        return Err(HarnessError::new("--samples must be positive"));
    }
    let interval_ms = values
        .get("--interval-ms")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| HarnessError::new("invalid --interval-ms"))?
        .unwrap_or(1_000);
    Ok(Options {
        pid: parse("--pid")?
            .try_into()
            .map_err(|_| HarnessError::new("--pid exceeds u32"))?,
        scenario: value("--scenario")?,
        build_identity: value("--build-identity")?,
        connection_count: parse("--connections")?,
        output: PathBuf::from(value("--output")?),
        sample_count,
        interval_ms,
    })
}

fn process_field(pid: u32, field: &str) -> Result<String, HarnessError> {
    let output = Command::new("ps")
        .args(["-o", field, "-p", &pid.to_string()])
        .output()
        .map_err(|_| HarnessError::new("failed to execute macOS ps"))?;
    if !output.status.success() {
        return Err(HarnessError::new("target process is not available"));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| HarnessError::new("macOS ps output is not UTF-8"))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(HarnessError::new(
            "macOS ps returned an empty process field",
        ));
    }
    Ok(value)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), HarnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("memory baseline output has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| HarnessError::new("failed to create memory baseline output directory"))?;
    let temporary = path.with_extension("tmp");
    let mut file = File::create(&temporary)
        .map_err(|_| HarnessError::new("failed to create memory baseline temporary file"))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|_| HarnessError::new("failed to persist memory baseline report"))?;
    fs::rename(&temporary, path)
        .map_err(|_| HarnessError::new("failed to publish memory baseline report"))
}
