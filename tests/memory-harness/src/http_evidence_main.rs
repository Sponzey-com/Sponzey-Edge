use edge_memory_harness::http_evidence_cli::{
    parse_http_evidence_command, run_http_evidence_command,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = parse_http_evidence_command(&args).and_then(run_http_evidence_command);
    match result {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("HTTP memory evidence failed: {error}");
            std::process::exit(1);
        }
    }
}
