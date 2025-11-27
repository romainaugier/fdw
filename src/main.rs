use std::{collections::HashMap, path::PathBuf, str::FromStr};

pub mod cli;
pub mod pe;
pub mod search;

fn main() {
    let mut arg_parser = cli::CLIParser::new();
    arg_parser
        .add_argument(
            "file",
            Some("f"),
            cli::CLIArgType::String,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");
    arg_parser
        .add_argument(
            "search-paths",
            None,
            cli::CLIArgType::String,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");

    arg_parser
        .parse()
        .expect("Error caught while parsing arguments");

    let file_path = arg_parser
        .get_argument_as_string("file")
        .expect("Argument file has not been passed");

    let pe = pe::parse_pe(file_path.as_str()).unwrap_or_else(|err| {
        panic!("Error caught while trying to inspect file: {file_path} ({err})")
    });

    let pe_type_string = match pe.get_architecture() {
        pe::PEArchitecture::PE32 => "PE type: 32-bit",
        pe::PEArchitecture::PE64 => "PE type: 64-bit",
    };

    println!("Inspecting dependencies of file: {file_path} (PE type: {pe_type_string})");

    let mut results: HashMap<String, Option<String>> = HashMap::new();

    for dll_name in &pe.dll_names {
        results.insert(dll_name.to_lowercase(), None);
    }

    let mut search_paths: Vec<PathBuf> = Vec::new();

    search_paths.push(
        PathBuf::from_str(file_path.as_str())
            .expect("Cannot convert path from --file into a PathBuf")
            .parent()
            .expect("Cannot find parent of --file")
            .to_path_buf(),
    );

    for path in std::env::split_paths(
        std::env::var("PATH")
            .expect("Cannot get the value of PATH environment variable")
            .as_str(),
    ) {
        if !path.exists() {
            println!(
                "Warning: Path \"{}\" not found, discarding it",
                path.display()
            );
            continue;
        }

        search_paths.push(path);
    }

    let user_search_paths = arg_parser.get_argument_as_string("search-paths").unwrap();

    if !user_search_paths.is_empty() {
        for path in user_search_paths.split(";") {
            let path_buf = PathBuf::from_str(path)
                .expect("Cannot convert a path from --search-path into a PathBuf");

            if !path_buf.exists() {
                println!(
                    "Warning: Path \"{}\" not found, discarding it",
                    path_buf.display()
                );
                continue;
            }

            search_paths.push(path_buf);
        }
    }

    search::search_dlls(&mut results, search_paths).expect("Error during dll search");

    for (key, value) in results.into_iter() {
        println!(
            "{}: {}",
            key,
            value.unwrap_or_else(|| "Not Found".to_string())
        );
    }
}
