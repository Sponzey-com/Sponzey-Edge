use edge_memory_harness::slow_body::{parse_slow_body_options, run_slow_body};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_slow_body_options(&args).and_then(run_slow_body) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("slow body driver failed: {error}");
            std::process::exit(1);
        }
    }
}
