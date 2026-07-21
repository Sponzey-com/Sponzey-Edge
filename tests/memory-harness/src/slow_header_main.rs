use edge_memory_harness::slow_header::{parse_slow_header_options, run_slow_header};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_slow_header_options(&args).and_then(run_slow_header) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("slow header driver failed: {error}");
            std::process::exit(1);
        }
    }
}
