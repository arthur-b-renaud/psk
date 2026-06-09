use serde::Deserialize;
use std::path::Path;

/// A pattern definition as loaded from a YAML file.
#[derive(Debug, Deserialize)]
pub struct PatternDefinition {
    pub name: String,
    pub entity: String,
    pub pattern: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_confidence() -> f64 {
    0.95
}

/// Load pattern definitions from a YAML file.
/// Each file contains a YAML array of pattern definitions.
pub fn load_pattern_file(path: &Path) -> anyhow::Result<Vec<PatternDefinition>> {
    let contents = std::fs::read_to_string(path)?;
    let defs: Vec<PatternDefinition> = serde_yaml::from_str(&contents)?;
    Ok(defs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pattern_yaml() {
        let yaml = r#"
- name: test_email
  entity: Email
  pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
  confidence: 0.95
  validator: null
  description: "Matches email addresses"
"#;
        let defs: Vec<PatternDefinition> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "test_email");
        assert_eq!(defs[0].entity, "Email");
    }
}
