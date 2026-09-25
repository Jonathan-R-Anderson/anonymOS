//! Parser for `ClamAV` `.ldb` logical signature files.
//!
//! LDB signatures combine multiple subsignatures with a logical (boolean)
//! expression. Each line has the format:
//!
//! ```text
//! SignatureName;TargetType;LogicalExpression;SubSig0;SubSig1;...
//! ```
//!
//! - **`LogicalExpression`**: e.g., `0&1`, `0|1&2`, `0&1|2`.
//! - **`SubSigN`**: hex patterns or other subsignature specifiers.

use anyhow::{Context, Result, bail};

/// A parsed LDB logical signature.
#[derive(Debug, Clone)]
pub struct LdbSignature {
    /// Malware family/variant name.
    pub name: String,
    /// Target file type (0 = any, 1 = PE, 2 = OLE2, etc.).
    pub target_type: u32,
    /// The logical expression combining subsignatures (e.g., `0&1|2`).
    pub logical_expression: String,
    /// The individual subsignature hex patterns or specifiers.
    pub subsignatures: Vec<String>,
}

/// Parse the content of an `.ldb` file into a list of logical signatures.
///
/// Blank lines and lines starting with `#` (comments) are skipped.
/// Fields are separated by semicolons.
pub fn parse_ldb(content: &str) -> Result<Vec<LdbSignature>> {
    let mut signatures = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() < 4 {
            bail!(
                "LDB line {}: expected at least 4 semicolon-separated fields, got {}",
                line_num + 1,
                parts.len()
            );
        }

        let name = parts.first().context("LDB: missing name field")?.to_string();

        let target_str = *parts.get(1).context("LDB: missing target type field")?;
        let target_type = target_str
            .parse::<u32>()
            .with_context(|| format!("LDB line {}: invalid target type '{target_str}'", line_num + 1,))?;

        let logical_expression = parts
            .get(2)
            .context("LDB: missing logical expression field")?
            .to_string();

        let subsignatures: Vec<String> = parts
            .get(3..)
            .unwrap_or_default()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        if subsignatures.is_empty() {
            bail!("LDB line {}: no subsignatures provided", line_num + 1);
        }

        signatures.push(LdbSignature {
            name,
            target_type,
            logical_expression,
            subsignatures,
        });
    }

    Ok(signatures)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ldb_basic() {
        let content = "Win.Trojan.Test-1;1;0&1;4d5a9000;cafebabe\n";
        let sigs = parse_ldb(content).unwrap();
        assert_eq!(sigs.len(), 1);

        let sig = &sigs[0];
        assert_eq!(sig.name, "Win.Trojan.Test-1");
        assert_eq!(sig.target_type, 1);
        assert_eq!(sig.logical_expression, "0&1");
        assert_eq!(sig.subsignatures, vec!["4d5a9000", "cafebabe"]);
    }

    #[test]
    fn test_parse_ldb_multiple() {
        let content = "\
# Comment line
Win.Malware.A;0;0&1&2;aabb;ccdd;eeff
Win.Malware.B;1;0|1;1122;3344

";
        let sigs = parse_ldb(content).unwrap();
        assert_eq!(sigs.len(), 2);

        assert_eq!(sigs[0].name, "Win.Malware.A");
        assert_eq!(sigs[0].subsignatures.len(), 3);
        assert_eq!(sigs[0].logical_expression, "0&1&2");

        assert_eq!(sigs[1].name, "Win.Malware.B");
        assert_eq!(sigs[1].subsignatures.len(), 2);
        assert_eq!(sigs[1].logical_expression, "0|1");
    }

    #[test]
    fn test_parse_ldb_single_subsig() {
        let content = "Test.Sig;0;0;deadbeef\n";
        let sigs = parse_ldb(content).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].subsignatures, vec!["deadbeef"]);
    }

    #[test]
    fn test_parse_ldb_too_few_fields() {
        let content = "Name;1;0&1\n";
        assert!(parse_ldb(content).is_err());
    }

    #[test]
    fn test_parse_ldb_invalid_target_type() {
        let content = "Name;abc;0;aabb\n";
        assert!(parse_ldb(content).is_err());
    }

    #[test]
    fn test_skip_comments_and_blanks() {
        let content = "\
# header comment

# another comment
Test.Sig;0;0;aabb
";
        let sigs = parse_ldb(content).unwrap();
        assert_eq!(sigs.len(), 1);
    }
}
