//! Semgrep adapter: builds the argv, parses its JSON report, and normalizes
//! results into findings.
//!
//! The report is untrusted input. Paths outside the scan root are rejected so a
//! compromised or buggy analyzer cannot make the tool read or report arbitrary
//! locations.

use crate::finding::{normalize, Confidence, Finding, Severity};
use crate::json::{self, Value};
use std::path::{Component, Path};

#[derive(Debug)]
pub struct Report {
    pub version: String,
    pub findings: Vec<Finding>,
    pub errors: usize,
}

/// Arguments for a bounded, network-free Semgrep run.
pub fn arguments(rules: &Path, root: &Path) -> Vec<std::ffi::OsString> {
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "scan".into(),
        "--json".into(),
        // Local-first policy: no metrics upload and no update checks.
        "--metrics=off".into(),
        "--disable-version-check".into(),
        "--config".into(),
    ];
    arguments.push(rules.as_os_str().to_owned());
    arguments.push(root.as_os_str().to_owned());
    arguments
}

pub fn parse_report(stdout: &str, root: &Path) -> Result<Report, String> {
    let document = json::parse(stdout).map_err(|error| format!("invalid JSON: {error}"))?;
    let version = document
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let results = document
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing 'results' array".to_string())?;
    let errors = match document.get("errors") {
        None | Some(Value::Null) => 0,
        Some(value) => value
            .as_array()
            .ok_or_else(|| "'errors' must be an array".to_string())?
            .len(),
    };

    let mut findings = Vec::with_capacity(results.len());
    for (index, result) in results.iter().enumerate() {
        findings.push(
            normalize_result(result, root, &version)
                .map_err(|error| format!("result {index} is invalid: {error}"))?,
        );
    }

    Ok(Report {
        version,
        findings: normalize(findings),
        errors,
    })
}

fn normalize_result(value: &Value, root: &Path, version: &str) -> Result<Finding, String> {
    let rule_id = value
        .get("check_id")
        .and_then(Value::as_str)
        .filter(|rule| !rule.is_empty())
        .ok_or_else(|| "missing 'check_id'".to_string())?;
    let raw_path = value
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing 'path'".to_string())?;
    let path = contained_path(raw_path, root)
        .ok_or_else(|| format!("path is outside the scan root: {raw_path}"))?;

    let start = value.get("start");
    let line = start
        .and_then(|start| start.get("line"))
        .and_then(Value::as_u64)
        .filter(|line| *line >= 1);
    let column = start
        .and_then(|start| start.get("col"))
        .and_then(Value::as_u64)
        .filter(|column| *column >= 1);

    let extra = value.get("extra");
    let message = extra
        .and_then(|extra| extra.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .unwrap_or(rule_id);
    let severity = Severity::from_semgrep(
        extra
            .and_then(|extra| extra.get("severity"))
            .and_then(Value::as_str),
    );
    let confidence = Confidence::from_metadata(
        extra
            .and_then(|extra| extra.get("metadata"))
            .and_then(|metadata| metadata.get("confidence"))
            .and_then(Value::as_str),
    );

    Ok(Finding::new(
        rule_id.to_owned(),
        severity,
        confidence,
        path,
        line,
        column,
        message.to_owned(),
        "semgrep".into(),
        version.to_owned(),
    ))
}

/// Converts an analyzer path into a root-relative, slash-separated path.
/// Returns `None` for absolute paths outside the root and for traversal.
fn contained_path(raw: &str, root: &Path) -> Option<String> {
    let path = Path::new(raw);
    let relative = if path.is_absolute() {
        path.strip_prefix(root).ok()?
    } else {
        path
    };

    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/repo")
    }

    use std::path::PathBuf;

    const REPORT: &str = r#"{
        "version": "1.95.0",
        "errors": [],
        "results": [
            {
                "check_id": "rules.b-rule",
                "path": "/repo/z.js",
                "start": {"line": 2, "col": 4},
                "extra": {"message": "second", "severity": "WARNING"}
            },
            {
                "check_id": "rules.a-rule",
                "path": "/repo/src/a.js",
                "start": {"line": 9, "col": 1},
                "extra": {
                    "message": "  first  ",
                    "severity": "ERROR",
                    "metadata": {"confidence": "HIGH"}
                }
            },
            {
                "check_id": "rules.a-rule",
                "path": "/repo/src/a.js",
                "start": {"line": 9, "col": 1},
                "extra": {"message": "first", "severity": "ERROR"}
            }
        ]
    }"#;

    #[test]
    fn builds_network_free_arguments() {
        let arguments: Vec<String> = arguments(Path::new("/rules"), Path::new("/repo"))
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            arguments,
            [
                "scan",
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--config",
                "/rules",
                "/repo"
            ]
        );
    }

    #[test]
    fn normalizes_sorts_and_deduplicates_results() {
        let report = parse_report(REPORT, &root()).unwrap();
        assert_eq!(report.version, "1.95.0");
        assert_eq!(report.errors, 0);
        assert_eq!(report.findings.len(), 2);

        assert_eq!(report.findings[0].path, "src/a.js");
        assert_eq!(report.findings[0].rule_id, "rules.a-rule");
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[0].confidence, Confidence::High);
        assert_eq!(report.findings[0].message, "first");
        assert_eq!(report.findings[0].line, Some(9));
        assert_eq!(report.findings[0].column, Some(1));

        assert_eq!(report.findings[1].path, "z.js");
        assert_eq!(report.findings[1].severity, Severity::Medium);
    }

    #[test]
    fn accepts_relative_paths() {
        let report = parse_report(
            r#"{"results":[{"check_id":"r","path":"src/a.js","start":{"line":1},"extra":{"message":"m"}}]}"#,
            &root(),
        )
        .unwrap();
        assert_eq!(report.findings[0].path, "src/a.js");
        assert_eq!(report.version, "unknown");
    }

    #[test]
    fn rejects_paths_outside_the_root() {
        for path in [
            "/etc/passwd",
            "/repo/../etc/passwd",
            "../outside.js",
            "/repo",
        ] {
            let report = format!(
                r#"{{"results":[{{"check_id":"r","path":"{path}","start":{{"line":1}},"extra":{{"message":"m"}}}}]}}"#
            );
            assert!(
                parse_report(&report, &root()).is_err(),
                "expected rejection for {path}"
            );
        }
    }

    #[test]
    fn rejects_missing_fields_and_invalid_structure() {
        for report in [
            "{}",
            r#"{"results":{}}"#,
            r#"{"results":[{"path":"/repo/a.js"}]}"#,
            r#"{"results":[{"check_id":"r"}]}"#,
            r#"{"results":[1]}"#,
            r#"{"results":[],"errors":"none"}"#,
        ] {
            assert!(parse_report(report, &root()).is_err(), "accepted {report}");
        }
    }

    #[test]
    fn empty_report_is_valid() {
        let report =
            parse_report(r#"{"version":"1.95.0","errors":[],"results":[]}"#, &root()).unwrap();
        assert!(report.findings.is_empty());
    }

    #[test]
    fn counts_recoverable_analyzer_errors() {
        let report = parse_report(
            r#"{"results":[],"errors":[{"message":"timeout"},{"message":"parse"}]}"#,
            &root(),
        )
        .unwrap();
        assert_eq!(report.errors, 2);
    }
}
