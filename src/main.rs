mod cli;
mod pe;

fn main() {
    let mut arg_parser = cli::CLIParser::new();
    arg_parser.add_argument(
        "file",
        Some("f"),
        cli::CLIArgType::String,
        cli::CLIArgAction::Store,
    );
    arg_parser.add_argument(
        "search-paths",
        None,
        cli::CLIArgType::String,
        cli::CLIArgAction::Store,
    );

    let parse_res = arg_parser
        .parse()
        .expect("Error caught while parsing arguments");

    let file_path = arg_parser
        .get_argument_as_string("file")
        .expect("Argument file has not been passed");

    let pe = pe::parse_pe(file_path.as_str()).unwrap_or_else(|err| {
        panic!("Error caught while trying to inspect file: {file_path} ({err})")
    });

    println!("Inspecting dependencies of file: {file_path}");

    match pe.get_architecture() {
        pe::PEArchitecture::PE32 => println!("PE type: 32-bit"),
        pe::PEArchitecture::PE64 => println!("PE type: 64-bit"),
    }

    println!("DLLs: {:?}", pe.dll_names);
}
