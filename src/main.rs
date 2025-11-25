use std::env;

mod pe;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: fdw <file_path>");
        return;
    }

    let file_path = &args[1];

    let pe = pe::parse_pe(file_path).unwrap_or_else(|err| {
        panic!("Error caught while trying to inspect file: {file_path} ({err})")
    });

    println!("Inspecting dependencies of file: {file_path}");

    match pe.get_architecture() {
        pe::PEArchitecture::PE32 => println!("PE type: 32-bit"),
        pe::PEArchitecture::PE64 => println!("PE type: 64-bit"),
    }
}
