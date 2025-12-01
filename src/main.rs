use log;
use std::{path::PathBuf, str::FromStr};

pub mod apiset;
pub mod cli;
pub mod pe;
pub mod search;

fn i64_to_level_filter(value: i64) -> log::LevelFilter {
    match value {
        0 => return log::LevelFilter::Off,
        1 => return log::LevelFilter::Error,
        2 => return log::LevelFilter::Warn,
        3 => return log::LevelFilter::Info,
        4 => return log::LevelFilter::Debug,
        5 => return log::LevelFilter::Trace,
        _ => return log::LevelFilter::Error,
    }
}

fn main() {
    let mut arg_parser = cli::CLIParser::new();
    arg_parser
        .add_argument(
            "loglevel",
            Some("v"),
            cli::CLIArgType::Int,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");
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
        .add_argument(
            "recurse",
            Some("-r"),
            cli::CLIArgType::Bool,
            cli::CLIArgAction::StoreTrue,
        )
        .expect("Error while adding argument to CLIParser");

    arg_parser
        .parse()
        .expect("Error caught while parsing arguments");

    match arg_parser.get_argument_as_i64("loglevel") {
        Ok(level) => log::set_max_level(i64_to_level_filter(level)),
        _ => log::set_max_level(log::LevelFilter::Error),
    };

    let apiset_schema_mapping =
        apiset::load_apisetschema_mapping().expect("Could not load apisetschema");

    log::debug!("Loaded apisetschema mapping");

    let file_path = arg_parser
        .get_argument_as_string("file")
        .expect("Argument file has not been passed");

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

    match search::resolve_dependencies(
        PathBuf::from_str(file_path.as_str()).expect("Cannot convert file path to PathBuf"),
        search_paths,
        apiset_schema_mapping,
        arg_parser.get_argument_as_bool_with_default("recurse", false),
    ) {
        Ok(dependencies) => println!("{:#}", dependencies),
        Err(err) => log::error!(
            "Error caught while trying to find dependencies for pe \"{file_path}\" ({err})"
        ),
    };
}
