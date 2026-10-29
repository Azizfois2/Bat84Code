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

    /// Ordering used by the blocking threshold. `Unknown` ranks lowest so an
    /// analyzer that could not classify a result cannot trip CI on its own.
    fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
            Self::Unknown => 0,
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

/// Maps a configured threshold to the rank it blocks at. `None` means nothing
/// blocks: that covers `never` and any unrecognized value.
pub fn threshold(value: &str) -> Option<u8> {
    match value {
        "info" => Some(1),
        "low" => Some(2),
        "medium" => Some(3),
        "high" => Some(4),
        "critical" => Some(5),
        _ => None,
    }
}

/// The blocking policy for one scan: a global `fail_on` threshold plus
/// optional per-rule and per-path overrides. For each finding the first
/// matching path override applies, otherwise the first matching rule
/// override, otherwise the global threshold, so a location exemption wins
/// over rule tuning, which wins over the default.
pub struct BlockPolicy<'a> {
    pub fail_on: &'a str,
    pub rule_overrides: &'a [(String, String)],
    pub path_overrides: &'a [(String, String)],
}

impl BlockPolicy<'_> {
    /// The threshold that applies to this finding after overrides.
    fn effective_threshold(&self, finding: &Finding) -> &str {
        if let Some((_, severity)) = self
            .path_overrides
            .iter()
            .find(|(pattern, _)| glob_match(pattern, &finding.path))
        {
            return severity;
        }
        if let Some((_, severity)) = self
            .rule_overrides
            .iter()
            .find(|(pattern, _)| glob_match(pattern, &finding.rule_id))
        {
            return severity;
        }
        self.fail_on
    }
}

/// Findings that meet their effective blocking threshold after per-rule and
/// per-path overrides are applied. Findings below their threshold, and any
/// finding whose effective threshold is `never` or unrecognized, are omitted.
pub fn blocking_findings<'a>(findings: &'a [Finding], policy: &BlockPolicy) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(
            |finding| match threshold(policy.effective_threshold(finding)) {
                Some(rank) => finding.severity.rank() >= rank,
                None => false,
            },
        )
        .collect()
}

/// Minimal glob used by threshold overrides: `*` matches within one path
/// segment, `**` crosses directories, `?` matches a single non-separator
/// character, everything else is literal. The whole string must match.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn matches(pattern: &[char], text: &[char]) -> bool {
        let Some(&first) = pattern.first() else {
            return text.is_empty();
        };
        if first == '*' {
            let stars = pattern
                .iter()
                .take_while(|character| **character == '*')
                .count();
            let rest = &pattern[stars..];
            if stars >= 2 && rest.first() == Some(&'/') {
                // `**/` matches zero or more whole directories.
                let tail = &rest[1..];
                if matches(tail, text) {
                    return true;
                }
                return (0..text.len())
                    .any(|index| text[index] == '/' && matches(tail, &text[index + 1..]));
            }
            if stars >= 2 {
                // A trailing or embedded `**` matches anything, separators included.
                return (0..=text.len()).any(|index| matches(rest, &text[index..]));
            }
            // A single `*` never crosses a path separator.
            for count in 0..=text.len() {
                if text[..count].contains(&'/') {
                    break;
                }
                if matches(rest, &text[count..]) {
                    return true;
                }
            }
            return false;
        }
        if text.is_empty() {
            return false;
        }
        let same = match first {
            // `?` matches any single character except the path separator.
            '?' => text[0] != '/',
            literal => text[0] == literal,
        };
        same && matches(&pattern[1..], &text[1..])
    }

    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    matches(&pattern, &text)
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

    fn with_severity(rule: &str, severity: Severity) -> Finding {
        Finding::new(
            rule.into(),
            severity,
            Confidence::Unknown,
            "src/a.rs".into(),
            Some(1),
            Some(1),
            "message".into(),
            "semgrep".into(),
            "1.0".into(),
        )
    }

    /// A policy with only a global threshold and no overrides.
    fn global(fail_on: &str) -> BlockPolicy<'_> {
        BlockPolicy {
            fail_on,
            rule_overrides: &[],
            path_overrides: &[],
        }
    }

    fn at(rule: &str, path: &str, severity: Severity) -> Finding {
        Finding::new(
            rule.into(),
            severity,
            Confidence::Unknown,
            path.into(),
            Some(1),
            Some(1),
            "message".into(),
            "semgrep".into(),
            "1.0".into(),
        )
    }

    fn blocked_ids(findings: &[Finding], policy: &BlockPolicy) -> Vec<String> {
        blocking_findings(findings, policy)
            .iter()
            .map(|finding| format!("{}@{}", finding.rule_id, finding.path))
            .collect()
    }

    #[test]
    fn blocking_threshold_gates_findings_by_severity() {
        let findings = vec![
            with_severity("c", Severity::Critical),
            with_severity("h", Severity::High),
            with_severity("m", Severity::Medium),
            with_severity("u", Severity::Unknown),
        ];

        let blocked: Vec<&str> = blocking_findings(&findings, &global("high"))
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert_eq!(blocked, ["c", "h"]);

        let blocked: Vec<&str> = blocking_findings(&findings, &global("medium"))
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert_eq!(blocked, ["c", "h", "m"]);

        // Unknown severity never blocks, whatever the threshold.
        assert!(blocking_findings(&findings, &global("info"))
            .iter()
            .all(|finding| { finding.severity != Severity::Unknown }));
        assert!(blocking_findings(&findings, &global("critical")).len() == 1);
        assert!(blocking_findings(&findings, &global("never")).is_empty());
        assert!(blocking_findings(&findings, &global("nonsense")).is_empty());
    }

    #[test]
    fn path_overrides_suppress_findings_under_the_matching_tree() {
        let findings = vec![
            at("rules.x", "tests/app.js", Severity::High),
            at("rules.x", "src/app.js", Severity::High),
        ];
        let paths = [("tests/**".to_string(), "never".to_string())];
        let policy = BlockPolicy {
            fail_on: "high",
            rule_overrides: &[],
            path_overrides: &paths,
        };
        assert_eq!(blocked_ids(&findings, &policy), ["rules.x@src/app.js"]);
    }

    #[test]
    fn rule_overrides_apply_where_no_path_override_matches() {
        let findings = vec![
            at("bat84.noisy", "src/a.rs", Severity::High),
            at("bat84.real", "src/b.rs", Severity::High),
        ];
        let rules = [("bat84.noisy".to_string(), "never".to_string())];
        let policy = BlockPolicy {
            fail_on: "high",
            rule_overrides: &rules,
            path_overrides: &[],
        };
        assert_eq!(blocked_ids(&findings, &policy), ["bat84.real@src/b.rs"]);
    }

    #[test]
    fn path_overrides_win_over_rule_overrides() {
        let findings = vec![
            at("rules.x", "tests/app.js", Severity::High),
            at("rules.x", "src/app.js", Severity::High),
        ];
        // The rule override would block everything at `info`, but the path
        // exemption for tests/ wins for the first finding.
        let rules = [("rules.x".to_string(), "info".to_string())];
        let paths = [("tests/**".to_string(), "never".to_string())];
        let policy = BlockPolicy {
            fail_on: "critical",
            rule_overrides: &rules,
            path_overrides: &paths,
        };
        assert_eq!(blocked_ids(&findings, &policy), ["rules.x@src/app.js"]);
    }

    #[test]
    fn explicit_overrides_apply_even_when_the_global_threshold_never_blocks() {
        let findings = vec![
            at("rules.x", "src/a.rs", Severity::Medium),
            at("rules.y", "src/b.rs", Severity::Critical),
        ];
        let rules = [("rules.x".to_string(), "medium".to_string())];
        let policy = BlockPolicy {
            fail_on: "never",
            rule_overrides: &rules,
            path_overrides: &[],
        };
        assert_eq!(blocked_ids(&findings, &policy), ["rules.x@src/a.rs"]);
    }

    #[test]
    fn glob_match_supports_star_double_star_and_question_mark() {
        assert!(glob_match("tests/**", "tests/a/b.js"));
        assert!(glob_match("tests/**", "tests/a.js"));
        assert!(!glob_match("tests/**", "test/a.js"));
        assert!(!glob_match("tests/**", "src/a.js"));

        // `**/` matches zero or more leading directories.
        assert!(glob_match("**/secrets.env", "secrets.env"));
        assert!(glob_match("**/secrets.env", "config/prod/secrets.env"));
        assert!(!glob_match("**/secrets.env", "secret.env"));

        // A single `*` and `?` stay within one path segment.
        assert!(glob_match("*.min.js", "app.min.js"));
        assert!(!glob_match("*.min.js", "src/app.min.js"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "a/c"));
        assert!(!glob_match("a?c", "ac"));

        // Rule-id patterns: `*` crosses dots because rule ids have no separator.
        assert!(glob_match("bat84.*", "bat84.eval-usage"));
        assert!(!glob_match("bat84.*", "other.rule"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
        assert!(!glob_match("", "x"));
        assert!(glob_match("", ""));
    }
}
