use edge_memory_harness::websocket_driver::{parse_websocket_options, run_websocket_driver};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_websocket_options(&args).and_then(run_websocket_driver) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("WebSocket driver failed: {error}");
            std::process::exit(1);
        }
    }
}
