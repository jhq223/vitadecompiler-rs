use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct DbRoot {
    modules: HashMap<String, DbModule>,
}

#[derive(Debug, Deserialize)]
struct DbModule {
    #[allow(dead_code)]
    nid: Option<String>,
    libraries: HashMap<String, DbLibrary>,
}

#[derive(Debug, Deserialize)]
struct DbLibrary {
    #[allow(dead_code)]
    nid: Option<String>,
    #[allow(dead_code)]
    kernel: Option<bool>,
    #[serde(default)]
    functions: HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    variables: HashMap<String, String>,
}

pub struct YamlDb {
    /// (module_name, lib_name, nid) -> function_name
    functions: HashMap<(String, u32), String>,
}

impl YamlDb {
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read db file: {}", path))?;
        let root: DbRoot =
            serde_yaml::from_str(&content).context("Failed to parse YAML db file")?;

        let mut functions = HashMap::new();

        for (module_name, module) in &root.modules {
            for (lib_name, lib) in &module.libraries {
                for (func_name, nid_str) in &lib.functions {
                    let nid = parse_nid(nid_str);
                    functions.insert((lib_name.clone(), nid), func_name.clone());
                    // Also index by module name (for exports lookup)
                    functions.insert((module_name.clone(), nid), func_name.clone());
                }
            }
        }

        Ok(YamlDb { functions })
    }

    pub fn lookup(&self, lib_name: &str, nid: u32) -> Option<&str> {
        self.functions
            .get(&(lib_name.to_string(), nid))
            .map(|s| s.as_str())
    }
}

fn parse_nid(s: &str) -> u32 {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).unwrap_or(0)
}
