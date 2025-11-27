use std::{collections::HashMap, path::PathBuf};

pub fn search_dlls(
    results: &mut HashMap<String, Option<String>>,
    search_paths: Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut keys: Vec<String> = results.keys().cloned().collect();

    for key in keys.iter() {
        if results.get(key).unwrap().is_some() {
            continue;
        }

        for path in search_paths.iter() {
            let entries =
                std::fs::read_dir(path).expect("Cannot read directory content in search path");

            for entry in entries {
                let file = entry.expect("Cannot read directory entry");

                if !file.file_type().unwrap().is_file() {
                    continue;
                }

                if file.file_name().to_str().unwrap().ends_with(key) {
                    let dll_path: String = file.path().to_str().unwrap().to_string();

                    *results.get_mut(key).unwrap() = Some(dll_path);
                }
            }
        }
    }

    return Ok(());
}
