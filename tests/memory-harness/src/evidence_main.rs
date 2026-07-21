use edge_memory_harness::evidence_cli::{parse_evidence_command, run_evidence_command};

fn main() {
    let result = parse_evidence_command(&std::env::args().skip(1).collect::<Vec<_>>())
        .and_then(run_evidence_command);
    if let Err(error) = result {
        eprintln!("memory evidence failed: {error}");
        std::process::exit(1);
    }
    println!("memory evidence command passed");
}
