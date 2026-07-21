use edge_memory_harness::release_http_cli::{
    parse_release_http_options, run_release_http_scenario,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = parse_release_http_options(&args).and_then(run_release_http_scenario);
    match result {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("release HTTP scenario failed: {error}");
            std::process::exit(1);
        }
    }
}
