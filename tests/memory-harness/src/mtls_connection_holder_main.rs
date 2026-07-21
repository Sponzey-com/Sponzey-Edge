use edge_memory_harness::mtls_connection_holder::{parse_mtls_holder_options, run_mtls_holder};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_mtls_holder_options(&args).and_then(run_mtls_holder) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("mTLS connection holder failed: {error}");
            std::process::exit(1);
        }
    }
}
