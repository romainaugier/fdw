use json;
use log;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn find_dll(name: &str, search_paths: &[PathBuf]) -> Result<String, Box<dyn std::error::Error>> {
    log::trace!("find_dll(): Looking for dll: {name}");

    for path in search_paths.iter() {
        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(err) => {
                log::trace!(
                    "Cannot read entries of directory: {} ({})",
                    path.display(),
                    err
                );
                continue;
            }
        };

        for entry in entries {
            let file = match entry {
                Ok(f) => f,
                Err(err) => {
                    log::trace!(
                        "Cannot read entry in directory: {} ({})",
                        path.display(),
                        err
                    );
                    continue;
                }
            };

            if !file.file_type().unwrap().is_file() {
                continue;
            }

            if file
                .file_name()
                .to_str()
                .unwrap_or("<invalid utf-8>")
                .ends_with(name)
            {
                return Ok(file
                    .path()
                    .to_str()
                    .unwrap_or("<invalid utf-8>")
                    .to_string());
            }
        }
    }

    return Err("Cannot find dll file in provided search paths".into());
}

fn get_dll_dependencies(
    pe_path: &PathBuf,
    search_paths: &[PathBuf],
    apiset_schema: &super::apiset::APISet,
) -> Result<json::JsonValue, Box<dyn std::error::Error>> {
    let pe = super::pe::parse_pe(&pe_path)
        .map_err(|err| format!("Failed to parse PE \"{}\" ({})", pe_path.display(), err))?;

    let pe_name = pe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_ascii_lowercase();

    log::trace!("get_dll_dependencies(): Looking for dll dependencies: {pe_name}");

    let mut dependencies_array: Vec<json::JsonValue> = Vec::new();

    for dll_name in &pe.dll_names {
        let lower = dll_name.to_ascii_lowercase();

        let resolved_path = match super::apiset::is_dll_from_apiset_schema(&lower) {
            true => find_dll(
                &super::apiset::find_dll(&lower, apiset_schema).unwrap_or("<unknown>".to_string()),
                search_paths,
            )
            .unwrap_or("<unknown>".to_string()),
            false => find_dll(&lower, search_paths).unwrap_or("<unknown>".to_string()),
        };

        dependencies_array.push(json::object! {
            name: lower,
            path: resolved_path
        });
    }

    let result = json::object! {
        name: pe_name,
        path: pe_path.to_str().unwrap_or("<invalid utf-8>"),
        dependencies: json::JsonValue::Array(dependencies_array)
    };

    return Ok(result);
}

fn get_dll_dependencies_recursive(
    pe_path: &PathBuf,
    search_paths: &[PathBuf],
    apiset_schema: &super::apiset::APISet,
    cache: &mut HashMap<PathBuf, json::JsonValue>,
    visited: &mut HashSet<PathBuf>,
) -> Result<json::JsonValue, Box<dyn std::error::Error>> {
    if let Some(cached) = cache.get(pe_path) {
        return Ok(cached.clone());
    }

    if !visited.insert(pe_path.clone()) {
        return Err(format!("Circular dependency detected in dll: {}", pe_path.display()).into());
    }

    let pe = super::pe::parse_pe(&pe_path)
        .map_err(|err| format!("Failed to parse PE \"{}\" ({})", pe_path.display(), err))?;

    let pe_name = pe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_ascii_lowercase();

    log::trace!("get_dll_dependencies_recursive(): Looking for dll dependencies: {pe_name}");

    let mut dependencies: Vec<json::JsonValue> = Vec::new();

    for dll_name in &pe.dll_names {
        let lower = dll_name.to_ascii_lowercase();

        let actual_dll_name = if super::apiset::is_dll_from_apiset_schema(&lower) {
            match super::apiset::find_dll(&lower, apiset_schema) {
                Some(name) => name,
                None => lower.clone(),
            }
        } else {
            lower.clone()
        };

        match find_dll(&actual_dll_name, search_paths) {
            Ok(resolved_path) => {
                let resolved_pathbuf = PathBuf::from(&resolved_path);

                let dep_object = match get_dll_dependencies_recursive(
                    &resolved_pathbuf,
                    search_paths,
                    apiset_schema,
                    cache,
                    visited,
                ) {
                    Ok(deps) => deps,
                    Err(e) => json::object! {
                        name: lower.clone(),
                        path: resolved_path,
                        dependencies: format!("Failed to resolve dependencies: {e}")
                    },
                };

                dependencies.push(dep_object);
            }
            Err(_) => dependencies.push(json::object! {
                name: lower.clone(),
                path: "<unknown>",
            }),
        }
    }

    visited.remove(pe_path);

    let result = json::object! {
        name: pe_name,
        path: pe_path.to_str().unwrap_or("<invalid path>"),
        dependencies: json::JsonValue::Array(dependencies),
    };

    cache.insert(pe_path.clone(), result.clone());

    return Ok(result);
}

pub fn resolve_dependencies(
    pe_path: PathBuf,
    search_paths: Vec<PathBuf>,
    apiset_schema: super::apiset::APISet,
    recurse: bool,
) -> Result<json::JsonValue, Box<dyn std::error::Error>> {
    if recurse {
        let mut cache: HashMap<PathBuf, json::JsonValue> = HashMap::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();

        return get_dll_dependencies_recursive(
            &pe_path,
            &search_paths,
            &apiset_schema,
            &mut cache,
            &mut visited,
        );
    } else {
        return get_dll_dependencies(&pe_path, &search_paths, &apiset_schema);
    }
}
