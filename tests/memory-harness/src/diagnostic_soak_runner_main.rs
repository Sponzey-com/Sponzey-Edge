use edge_memory_harness::diagnostic_soak_runner_cli::{
    parse_diagnostic_soak_runner_options, run_diagnostic_soak_runner,
};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_diagnostic_soak_runner_options(&arguments).and_then(run_diagnostic_soak_runner) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("diagnostic soak runner failed: {error}");
            std::process::exit(1);
        }
    }
}
