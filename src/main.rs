use log;
use std::{path::PathBuf, str::FromStr};

pub mod apiset;
pub mod cli;
pub mod pe;
pub mod search;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arg_parser = cli::CLIParser::new();

    arg_parser
        .add_argument(
            "--loglevel",
            Some("-v"),
            cli::CLIArgType::Int,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");
    arg_parser
        .add_argument(
            "--file",
            Some("-f"),
            cli::CLIArgType::String,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");
    arg_parser
        .add_argument(
            "--search-paths",
            None,
            cli::CLIArgType::String,
            cli::CLIArgAction::Store,
        )
        .expect("Error while adding argument to CLIParser");
    arg_parser
        .add_argument(
            "--recurse",
            Some("-r"),
            cli::CLIArgType::Bool,
            cli::CLIArgAction::StoreTrue,
        )
        .expect("Error while adding argument to CLIParser");

    arg_parser
        .parse()
        .expect("Error caught while parsing arguments");

    let log_level = match arg_parser.get_argument_as_i64_with_default("loglevel", 1) {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        5 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Error,
    };

    env_logger::builder().filter_level(log_level).init();

    log::trace!("Starting fdw");

    let apiset_schema_mapping = apiset::load_apisetschema_mapping()?;

    let file_path = arg_parser
        .get_argument_as_string("file")
        .expect("Argument file has not been passed");

    log::trace!("Initializing search paths");

    let mut search_paths: Vec<PathBuf> = Vec::new();

    search_paths.push(
        PathBuf::from_str(file_path.as_str())
            .expect("Cannot convert path from --file into a PathBuf")
            .parent()
            .expect("Cannot find parent of --file")
            .to_path_buf(),
    );

    log::trace!("pe directory added to search paths: {:?}", search_paths);

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

    log::trace!("PATH paths added to search paths: {:?}", search_paths);

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

        log::trace!(
            "User provided paths added to search paths: {:?}",
            search_paths
        );
    }

    match search::resolve_dependencies(
        PathBuf::from_str(file_path.as_str()).expect("Cannot convert file path to PathBuf"),
        search_paths,
        apiset_schema_mapping,
        arg_parser.get_argument_as_bool_with_default("recurse", false),
    ) {
        Ok(dependencies) => println!("{:#}", dependencies),
        Err(err) => return Err(err),
    };

    return Ok(());
}
