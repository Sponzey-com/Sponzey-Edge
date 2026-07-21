use edge_memory_harness::slow_response::{parse_slow_response_options, run_slow_response};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_slow_response_options(&args).and_then(run_slow_response) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("slow response failed: {error}");
            std::process::exit(1);
        }
    }
}
