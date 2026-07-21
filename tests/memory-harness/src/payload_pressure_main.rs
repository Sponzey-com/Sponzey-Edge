use edge_memory_harness::payload_pressure::{
    evaluate_payload_pressure, parse_payload_pressure_options,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_payload_pressure_options(&args).and_then(evaluate_payload_pressure) {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("payload pressure evaluator failed: {error}");
            std::process::exit(1);
        }
    }
}
