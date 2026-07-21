use edge_memory_harness::connection_churn_cli::{parse_churn_command, run_churn_command};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_churn_command(&args).and_then(run_churn_command) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("connection churn failed: {error}");
            std::process::exit(1);
        }
    }
}
