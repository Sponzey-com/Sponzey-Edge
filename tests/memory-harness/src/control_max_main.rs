use edge_memory_harness::control_max::{parse_control_max_command, run_control_max_command};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_control_max_command(&args).and_then(run_control_max_command) {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
