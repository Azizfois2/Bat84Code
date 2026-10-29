//! Integration tests that exercise the built `bat84` binary through its CLI.
//!
//! These tests cover the documented exit-code contract and the configuration
//! precedence chain (defaults -> config file -> BAT84_* environment -> flags).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Builds a command for the binary under test with ambient BAT84_* overrides removed,
/// so the developer's shell cannot influence the result.
fn bat84(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bat84"));
    command
        .env_remove("BAT84_REPORT_FORMAT")
        .env_remove("BAT84_NETWORK")
        .args(args);
    command
}

fn run(args: &[&str]) -> Output {
    bat84(args).output().expect("failed to run bat84")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process terminated by signal")
}

/// Minimal self-cleaning temporary directory (the crate has no dependencies).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let unique = format!(
            "bat84-test-{}-{}-{}",
            label,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let file = self.path.join(name);
        std::fs::write(&file, contents).expect("write temp file");
        file
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("test path is valid UTF-8")
}

#[test]
fn help_is_available_in_every_documented_form() {
    for args in [&[][..], &["--help"][..], &["-h"][..], &["help"][..]] {
        let output = run(args);
        assert_eq!(code(&output), 0, "args: {args:?}");
        let text = stdout(&output);
        assert!(text.contains("USAGE:"), "args: {args:?}");
        assert!(text.contains("BAT84CODE"), "args: {args:?}");
        assert!(stderr(&output).is_empty(), "args: {args:?}");
    }
}

#[test]
fn unknown_command_exits_two() {
    let output = run(&["bogus"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("unknown command 'bogus'"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn scan_reports_verification_incomplete() {
    let output = run(&["scan", MANIFEST_DIR]);
    assert_eq!(
        code(&output),
        4,
        "scan must never report an empty scan as clean"
    );
    let text = stdout(&output);
    assert!(text.contains("Findings: 0"), "{text}");
    assert!(text.contains("Checks: incomplete"), "{text}");
    assert!(text.contains("No files were modified"), "{text}");
}

#[test]
fn scan_json_and_sarif_are_fail_closed() {
    let json = run(&["scan", MANIFEST_DIR, "--format", "json"]);
    assert_eq!(code(&json), 4);
    let text = stdout(&json);
    assert!(text.contains("\"status\":\"not_verified\""), "{text}");
    assert!(text.contains("\"findings\":[]"), "{text}");
    assert!(
        text.starts_with('{') && text.trim_end().ends_with('}'),
        "{text}"
    );

    let sarif = run(&["scan", MANIFEST_DIR, "--format", "sarif"]);
    assert_eq!(code(&sarif), 4);
    let text = stdout(&sarif);
    assert!(text.contains("\"version\":\"2.1.0\""), "{text}");
    assert!(text.contains("\"executionSuccessful\":false"), "{text}");
    assert!(text.contains("\"results\":[]"), "{text}");
}

#[test]
fn scan_rejects_files_and_missing_paths() {
    let dir = TempDir::new("scan-path");
    let file = dir.write("not-a-directory.txt", "x");

    let file_output = run(&["scan", path_str(&file)]);
    assert_eq!(code(&file_output), 2);
    assert!(stderr(&file_output).contains("must be a directory"));

    let missing = dir.path().join("missing");
    let missing_output = run(&["scan", path_str(&missing)]);
    assert_eq!(code(&missing_output), 2);
    assert!(stderr(&missing_output).contains("cannot access scan path"));
}

#[test]
fn config_file_selects_the_report_format() {
    let dir = TempDir::new("config-format");
    let config = dir.write("bat84.toml", "[report]\nformat = \"json\"\n");

    let output = run(&["scan", MANIFEST_DIR, "--config", path_str(&config)]);
    assert_eq!(code(&output), 4);
    let text = stdout(&output);
    assert!(text.contains("\"schema_version\":\"1.0\""), "{text}");
    assert!(text.contains("\"command\":\"scan\""), "{text}");
}

#[test]
fn environment_overrides_the_config_file() {
    let dir = TempDir::new("env-overrides-file");
    let config = dir.write("bat84.toml", "[report]\nformat = \"text\"\n");

    let output = bat84(&["scan", MANIFEST_DIR, "--config", path_str(&config)])
        .env("BAT84_REPORT_FORMAT", "json")
        .output()
        .expect("run bat84");
    assert_eq!(code(&output), 4);
    let text = stdout(&output);
    assert!(text.starts_with('{'), "environment flag should win: {text}");
    assert!(text.contains("\"command\":\"scan\""), "{text}");
}

#[test]
fn command_line_flag_overrides_the_environment() {
    let output = bat84(&["scan", MANIFEST_DIR, "--format", "text"])
        .env("BAT84_REPORT_FORMAT", "sarif")
        .output()
        .expect("run bat84");
    assert_eq!(code(&output), 4);
    let text = stdout(&output);
    assert!(
        text.contains("BAT84CODE scan"),
        "--format flag should win: {text}"
    );
}

#[test]
fn invalid_config_values_exit_two() {
    let cases = [
        (
            "network",
            "[scan]\nnetwork = \"sometimes\"\n",
            "scan.network",
        ),
        (
            "limits",
            "[scan]\nmax_parallel = 0\n",
            "scan limits must be greater than zero",
        ),
        (
            "remediation",
            "[remediation]\nmode = \"apply\"\n",
            "remediation.mode must be plan-only",
        ),
        (
            "semgrep",
            "[tools.semgrep]\nenabled = false\nrequired = true\n",
            "required Semgrep cannot be disabled",
        ),
        (
            "unknown-section",
            "[nope]\nkey = \"value\"\n",
            "unknown section [nope]",
        ),
        (
            "unknown-key",
            "[scan]\nbogus = \"value\"\n",
            "unknown or invalid key 'bogus'",
        ),
    ];

    for (label, contents, expected) in cases {
        let dir = TempDir::new(label);
        let config = dir.write("bat84.toml", contents);
        let output = run(&["scan", MANIFEST_DIR, "--config", path_str(&config)]);
        assert_eq!(code(&output), 2, "case {label}");
        assert!(
            stderr(&output).contains(expected),
            "case {label}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).is_empty(), "case {label}");
    }
}

#[test]
fn config_flag_requires_a_path() {
    let output = run(&["scan", MANIFEST_DIR, "--config"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("--config requires a path"));
}

#[test]
fn doctor_reports_platform_and_skipped_tools() {
    let output = run(&["doctor", "--no-tools", "--format", "json"]);
    assert_eq!(code(&output), 0);
    let text = stdout(&output);
    assert!(text.contains("\"command\":\"doctor\""), "{text}");
    assert!(text.contains("\"os\":\""), "{text}");
    assert!(text.contains("\"status\":\"skipped\""), "{text}");
    assert!(text.contains("\"version\":null"), "{text}");

    let plain = run(&["doctor", "--no-tools"]);
    assert_eq!(code(&plain), 0);
    assert!(stdout(&plain).contains("not checked (--no-tools)"));
}

#[test]
fn doctor_and_self_test_reject_sarif() {
    let doctor = run(&["doctor", "--no-tools", "--format", "sarif"]);
    assert_eq!(code(&doctor), 2);
    assert!(stderr(&doctor).contains("doctor supports text or json output"));

    let self_test = run(&["self-test", "--format", "sarif"]);
    assert_eq!(code(&self_test), 2);
    assert!(stderr(&self_test).contains("self-test supports text or json output"));
}

#[test]
fn self_test_passes_in_text_and_json() {
    let text = run(&["self-test"]);
    assert_eq!(code(&text), 0);
    assert!(stdout(&text).contains("Self-test passed"));

    let json = run(&["self-test", "--format", "json"]);
    assert_eq!(code(&json), 0);
    let output = stdout(&json);
    assert!(output.contains("\"passed\":true"), "{output}");
    assert!(output.contains("json_escaping"), "{output}");
}

#[cfg(unix)]
#[test]
fn diff_without_git_exits_three() {
    // An empty PATH makes `git` unresolvable; the command reports a missing required tool.
    let output = bat84(&["diff"])
        .env("PATH", "")
        .output()
        .expect("run bat84");
    assert_eq!(code(&output), 3);
    assert!(
        stderr(&output).contains("git is unavailable"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn diff_rejects_an_unknown_revision() {
    let output = run(&["diff", "definitely-not-a-revision"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("git diff failed"));
}
