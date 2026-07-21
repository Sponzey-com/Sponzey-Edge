use edge_memory_harness::private_https::{evaluate_private_https, parse_private_https_options};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_private_https_options(&args).and_then(evaluate_private_https) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("private HTTPS evaluator failed: {error}");
            std::process::exit(1);
        }
    }
}
