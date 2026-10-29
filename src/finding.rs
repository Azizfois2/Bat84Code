//! Normalized finding model, matching `schemas/findings-v1.schema.json`.

use crate::{json_string, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_semgrep(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_uppercase).as_deref() {
            Some("CRITICAL") => Self::Critical,
            Some("ERROR") | Some("HIGH") => Self::High,
            Some("WARNING") | Some("MEDIUM") => Self::Medium,
            Some("LOW") => Self::Low,
            Some("INFO") => Self::Info,
            _ => Self::Unknown,
        }
    }

    fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
            Self::Unknown => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_metadata(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_uppercase).as_deref() {
            Some("HIGH") => Self::High,
            Some("MEDIUM") => Self::Medium,
            Some("LOW") => Self::Low,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: String,
    pub line: Option<u64>,
    pub column: Option<u64>,
    pub message: String,
    pub tool_name: String,
    pub tool_version: String,
    evidence_digest: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: String,
        severity: Severity,
        confidence: Confidence,
        path: String,
        line: Option<u64>,
        column: Option<u64>,
        message: String,
        tool_name: String,
        tool_version: String,
    ) -> Self {
        let mut finding = Self {
            rule_id,
            severity,
            confidence,
            path,
            line,
            column,
            message,
            tool_name,
            tool_version,
            evidence_digest: String::new(),
        };
        finding.evidence_digest = finding.compute_digest();
        finding
    }

    fn compute_digest(&self) -> String {
        let material = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.rule_id,
            self.severity.as_str(),
            self.path,
            self.line.map(|line| line.to_string()).unwrap_or_default(),
            self.column
                .map(|column| column.to_string())
                .unwrap_or_default(),
            self.message
        );
        format!("sha256:{}", sha256::digest_hex(material.as_bytes()))
    }

    pub fn to_json(&self) -> String {
        let mut location = format!("{{\"path\":{}", json_string(&self.path));
        if let Some(line) = self.line {
            location.push_str(&format!(",\"line\":{line}"));
        }
        if let Some(column) = self.column {
            location.push_str(&format!(",\"column\":{column}"));
        }
        location.push('}');

        format!(
            "{{\"schema_version\":\"1.0\",\"rule_id\":{},\"severity\":{},\"confidence\":{},\
             \"status\":\"detected\",\"location\":{},\"message\":{},\
             \"evidence\":[{{\"kind\":\"tool_output\",\"digest\":{}}}],\
             \"tool\":{{\"name\":{},\"version\":{}}},\
             \"remediation\":{{\"available\":false,\"patch_digest\":null}}}}",
            json_string(&self.rule_id),
            json_string(self.severity.as_str()),
            json_string(self.confidence.as_str()),
            location,
            json_string(&self.message),
            json_string(&self.evidence_digest),
            json_string(&self.tool_name),
            json_string(&self.tool_version),
        )
    }

    pub fn to_sarif_result(&self) -> String {
        let mut region = String::new();
        if let Some(line) = self.line {
            region.push_str(&format!("\"startLine\":{line}"));
        }
        if let Some(column) = self.column {
            if !region.is_empty() {
                region.push(',');
            }
            region.push_str(&format!("\"startColumn\":{column}"));
        }
        let region = format!("{{{region}}}");

        format!(
            "{{\"ruleId\":{},\"level\":\"{}\",\"message\":{{\"text\":{}}},\
             \"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}},\
             \"region\":{}}}}}]}}",
            json_string(&self.rule_id),
            self.severity.sarif_level(),
            json_string(&self.message),
            json_string(&self.path),
            region,
        )
    }
}

/// Sorts findings deterministically and removes exact duplicates.
pub fn normalize(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|left, right| {
        (
            left.path.as_str(),
            left.line,
            left.column,
            left.rule_id.as_str(),
            left.message.as_str(),
        )
            .cmp(&(
                right.path.as_str(),
                right.line,
                right.column,
                right.rule_id.as_str(),
                right.message.as_str(),
            ))
    });
    findings.dedup_by(|left, right| {
        left.path == right.path
            && left.line == right.line
            && left.column == right.column
            && left.rule_id == right.rule_id
            && left.message == right.message
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, path: &str, line: u64, message: &str) -> Finding {
        Finding::new(
            rule.into(),
            Severity::High,
            Confidence::Unknown,
            path.into(),
            Some(line),
            Some(2),
            message.into(),
            "semgrep".into(),
            "1.95.0".into(),
        )
    }

    #[test]
    fn maps_semgrep_severities_and_confidences() {
        assert_eq!(Severity::from_semgrep(Some("ERROR")), Severity::High);
        assert_eq!(Severity::from_semgrep(Some("warning")), Severity::Medium);
        assert_eq!(Severity::from_semgrep(Some("INFO")), Severity::Info);
        assert_eq!(Severity::from_semgrep(Some("CRITICAL")), Severity::Critical);
        assert_eq!(Severity::from_semgrep(Some("weird")), Severity::Unknown);
        assert_eq!(Severity::from_semgrep(None), Severity::Unknown);
        assert_eq!(Confidence::from_metadata(Some("HIGH")), Confidence::High);
        assert_eq!(Confidence::from_metadata(Some("low")), Confidence::Low);
        assert_eq!(Confidence::from_metadata(None), Confidence::Unknown);
    }

    #[test]
    fn serializes_schema_required_fields() {
        let json = finding("rules.x", "src/a.rs", 7, "Avoid eval").to_json();
        for expected in [
            "\"schema_version\":\"1.0\"",
            "\"rule_id\":\"rules.x\"",
            "\"severity\":\"high\"",
            "\"confidence\":\"unknown\"",
            "\"status\":\"detected\"",
            "\"path\":\"src/a.rs\"",
            "\"line\":7",
            "\"column\":2",
            "\"message\":\"Avoid eval\"",
            "\"kind\":\"tool_output\"",
            "\"available\":false",
            "\"patch_digest\":null",
        ] {
            assert!(json.contains(expected), "missing {expected} in {json}");
        }
        assert!(!json.contains("\"line\":null"));
    }

    #[test]
    fn evidence_digest_is_stable_and_well_formed() {
        let first = finding("rules.x", "src/a.rs", 7, "Avoid eval");
        let second = finding("rules.x", "src/a.rs", 7, "Avoid eval");
        assert_eq!(first.evidence_digest, second.evidence_digest);
        assert_eq!(first.evidence_digest.len(), 71);
        assert!(first.evidence_digest.starts_with("sha256:"));
        assert!(first.evidence_digest[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit()));

        let different = finding("rules.x", "src/a.rs", 8, "Avoid eval");
        assert_ne!(first.evidence_digest, different.evidence_digest);
    }

    #[test]
    fn omits_missing_location_fields() {
        let mut value = finding("rules.x", "src/a.rs", 1, "message");
        value.line = None;
        value.column = None;
        let json = value.to_json();
        assert!(
            json.contains("\"location\":{\"path\":\"src/a.rs\"}"),
            "{json}"
        );
        let sarif = value.to_sarif_result();
        assert!(sarif.contains("\"region\":{}"), "{sarif}");
    }

    #[test]
    fn sarif_result_uses_level_and_uri() {
        let json = finding("rules.x", "src/a.rs", 7, "Avoid eval").to_sarif_result();
        assert!(json.contains("\"ruleId\":\"rules.x\""));
        assert!(json.contains("\"level\":\"error\""));
        assert!(json.contains("\"uri\":\"src/a.rs\""));
        assert!(json.contains("\"startLine\":7"));
    }

    #[test]
    fn normalize_sorts_and_deduplicates() {
        let sorted = normalize(vec![
            finding("b", "z.rs", 2, "second"),
            finding("a", "a.rs", 9, "third"),
            finding("a", "a.rs", 9, "third"),
        ]);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].path, "a.rs");
        assert_eq!(sorted[1].path, "z.rs");
    }
}
