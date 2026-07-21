use edge_memory_harness::connection_holder::{
    parse_connection_holder_options, run_connection_holder,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = parse_connection_holder_options(&args).and_then(run_connection_holder);
    match result {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("connection holder failed: {error}");
            std::process::exit(1);
        }
    }
}
