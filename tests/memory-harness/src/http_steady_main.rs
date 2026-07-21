use edge_memory_harness::http_steady::{parse_steady_options, run_steady_options};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_steady_options(&args).and_then(run_steady_options) {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
