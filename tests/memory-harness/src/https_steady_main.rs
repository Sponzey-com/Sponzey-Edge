use edge_memory_harness::https_steady::{parse_https_steady_options, run_https_steady_options};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_https_steady_options(&args).and_then(run_https_steady_options) {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
