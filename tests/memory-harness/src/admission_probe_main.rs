use edge_memory_harness::admission_probe::{parse_admission_probe_options, run_admission_probe};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = parse_admission_probe_options(&args).and_then(run_admission_probe);
    match result {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("connection admission probe failed: {error}");
            std::process::exit(1);
        }
    }
}
