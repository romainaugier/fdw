use json;
use log;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

fn find_dll(name: &str, search_paths: &[PathBuf]) -> Result<String, Box<dyn std::error::Error>> {
    for path in search_paths.iter() {
        let entries =
            std::fs::read_dir(path).expect("Cannot read directory content in search path");

        for entry in entries {
            let file = entry.expect("Cannot read directory entry");

            if !file.file_type().unwrap().is_file() {
                continue;
            }

            if file.file_name().to_str().unwrap().ends_with(name) {
                let dll_path: String = file.path().to_str().unwrap().to_string();

                return Ok(dll_path);
            }
        }
    }

    return Err("Cannot find dll in filesystem".into());
}

fn resolve_dependencies_recursive(
    pe_path: &PathBuf,
    search_paths: &[PathBuf],
    apiset_schema: &super::apiset::APISet,
    cache: &mut HashMap<PathBuf, json::JsonValue>,
    visited: &mut HashSet<PathBuf>,
) -> Result<json::JsonValue, Box<dyn std::error::Error>> {
    let pe_path = pe_path.canonicalize()?;

    if let Some(cached) = cache.get(&pe_path) {
        return Ok(cached.clone());
    }

    if !visited.insert(pe_path.clone()) {
        return Ok(json::object! {
            name: pe_path.file_name().and_then(|n| n.to_str()).unwrap_or("<unknown>"),
            path: pe_path.to_str().unwrap_or("<invalid utf-8>"),
            error: "circular dependency detected"
        });
    }

    let pe = super::pe::parse_pe(&pe_path)
        .map_err(|e| format!("Failed to parse PE {}: {}", pe_path.display(), e))?;

    let name = pe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_ascii_lowercase();

    log::debug!("Resolving dependencies for: {}", pe_path.display());

    let mut dependencies_array: Vec<json::JsonValue> = Vec::new();

    for dll_name in &pe.dll_names {
        let lower = dll_name.to_ascii_lowercase();

        if super::apiset::is_dll_from_apiset_schema(&lower) {
            let resolved_dll = match apiset_schema.map(&lower) {
                Some(dll) => dll,
                None => continue,
            };

            let dep_object = match find_dll(resolved_dll, search_paths).ok() {
                Some(resolved_path) => json::object! {
                    name: lower.clone(),
                    path: resolved_path,
                },

                None => json::object! {
                    name: lower.clone(),
                    path: json::Null,
                    error: "not found in search paths"
                },
            };

            dependencies_array.push(dep_object);
        } else {
            let dep_object = match find_dll(&lower, search_paths).ok() {
                Some(dll_path) => {
                    let dll_path_buf = PathBuf::from(&dll_path);

                    match resolve_dependencies_recursive(
                        &dll_path_buf,
                        search_paths,
                        apiset_schema,
                        cache,
                        visited,
                    ) {
                        Ok(dep_tree) => dep_tree,
                        Err(e) => json::object! {
                            name: dll_name.clone(),
                            path: dll_path,
                            error: format!("failed to resolve dependencies: {e}")
                        },
                    }
                }
                None => {
                    log::warn!("Could not find DLL on disk: {}", lower);
                    json::object! {
                        name: lower.clone(),
                        path: json::Null,
                        error: "not found in search paths"
                    }
                }
            };

            dependencies_array.push(dep_object);
        }
    }

    visited.remove(&pe_path);

    let result = json::object! {
        name: name,
        path: pe_path.to_str().unwrap_or("<invalid utf-8>"),
        dependencies: json::JsonValue::Array(dependencies_array)
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
    let mut cache = HashMap::new();
    let mut visited = HashSet::new();

    if recurse {
        return resolve_dependencies_recursive(
            &pe_path,
            &search_paths,
            &apiset_schema,
            &mut cache,
            &mut visited,
        );
    } else {
        return resolve_dependencies_recursive(
            &pe_path,
            &search_paths,
            &apiset_schema,
            &mut cache,
            &mut visited,
        );
    }
}
