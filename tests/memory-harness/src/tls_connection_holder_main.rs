use edge_memory_harness::tls_connection_holder::{parse_tls_holder_options, run_tls_holder};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_tls_holder_options(&args).and_then(run_tls_holder) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("TLS connection holder failed: {error}");
            std::process::exit(1);
        }
    }
}
