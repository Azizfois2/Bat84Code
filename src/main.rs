use std::env;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Version probes for analyzers such as Semgrep, which is a Python program and
/// needs several seconds of interpreter startup before it prints anything.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_OUTPUT_CAP: usize = 1024;

mod finding;
mod json;
mod semgrep;
mod sha256;

use finding::Finding;

const HELP: &str = "BAT84CODE - local-first defensive repository inspection\n\
\nUSAGE:\n\
    bat84 <COMMAND> [OPTIONS]\n\
\nCOMMANDS:\n\
    doctor [--no-tools]   Check platform and optional analyzer availability\n\
    scan [PATH]            Inspect a repository without modifying it\n\
    diff [BASE]             Show changed files (requires Git)\n\
    self-test               Run built-in integrity checks\n\
    help                    Show this help\n\
\nOPTIONS:\n\
    --format text|json|sarif Select report format (default: text)\n\
    --config PATH           Load configuration (default: ./bat84.toml)\n\
    -h, --help              Show command help\n";

/// Writes a line to stdout and ignores write errors, so a closed downstream
/// pipe (`bat84 ... | head`) ends quietly instead of panicking mid-run.
fn out(args: std::fmt::Arguments) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{args}");
}

/// Writes text without a trailing newline; also tolerates a closed pipe.
fn out_raw(args: std::fmt::Arguments) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    let _ = write!(stdout, "{args}");
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err((code, message)) => {
            eprintln!("bat84: {message}");
            ExitCode::from(code)
        }
    }
}

fn run(args: Vec<std::ffi::OsString>) -> Result<u8, (u8, String)> {
    let Some(command) = args.first().and_then(|s| s.to_str()) else {
        out_raw(format_args!("{HELP}"));
        return Ok(0);
    };
    if command == "-h" || command == "--help" || command == "help" {
        out_raw(format_args!("{HELP}"));
        return Ok(0);
    }
    match command {
        "doctor" => doctor(&args[1..]),
        "scan" => scan(&args[1..]),
        "diff" => diff(&args[1..]),
        "self-test" => self_test(&args[1..]),
        other => Err((2, format!("unknown command '{other}'. Run 'bat84 --help'."))),
    }
}

fn doctor(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &["--no-tools", "--format", "--config"])?;
    let config = load_config(args)?;
    let no_tools = option_slice(args).iter().any(|arg| arg == "--no-tools");
    let format = format_arg(args)?.unwrap_or(&config.report_format);
    if format == "sarif" {
        return Err((2, "doctor supports text or json output".into()));
    }
    reject_positionals(args, "doctor")?;
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let tools = ["semgrep", "cargo-audit", "gitleaks", "osv-scanner"];
    let discovered: Vec<(&str, ToolStatus)> = tools
        .iter()
        .map(|name| {
            let executable = if no_tools {
                None
            } else {
                find_executable(name)
            };
            let status = if no_tools {
                ToolStatus::Skipped
            } else if executable.is_none() {
                ToolStatus::Unavailable
            } else {
                match run_bounded(
                    executable
                        .as_ref()
                        .expect("resolved executable")
                        .as_os_str(),
                    &["--version"],
                    PROBE_TIMEOUT,
                    PROBE_OUTPUT_CAP,
                ) {
                    Ok(result) if result.timed_out => ToolStatus::Timeout,
                    Ok(result) if result.status == Some(0) => {
                        ToolStatus::Available(first_line(&result.stdout))
                    }
                    _ => ToolStatus::Unavailable,
                }
            };
            (*name, status)
        })
        .collect();
    if format == "json" {
        let entries = discovered
            .iter()
            .map(|(name, status)| {
                format!(
                    "{{\"name\":\"{name}\",\"status\":{},\"version\":{}}}",
                    json_string(status.label()),
                    status
                        .version()
                        .map(json_string)
                        .unwrap_or_else(|| "null".into())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        out(format_args!("{{\"schema_version\":\"1.0\",\"command\":\"doctor\",\"platform\":{{\"os\":\"{os}\",\"arch\":\"{arch}\"}},\"tools\":[{entries}]}}"));
    } else {
        out(format_args!("BAT84CODE doctor\nPlatform: {os}/{arch}"));
        for (name, status) in discovered {
            out(format_args!("  {name}: {}", status.display()));
        }
        out(format_args!("No repository files were modified."));
    }
    Ok(0)
}

fn scan(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &["--format", "--config"])?;
    let config = load_config(args)?;
    let format = format_arg(args)?.unwrap_or(&config.report_format);
    let path = single_positional(args, "scan")?
        .map(|value| PathBuf::from(value.as_os_str()))
        .unwrap_or(env::current_dir().map_err(internal)?);
    let canonical = path
        .canonicalize()
        .map_err(|e| (2, format!("cannot access scan path: {e}")))?;
    if !canonical.is_dir() {
        return Err((2, "scan path must be a directory".into()));
    }
    let metadata = std::fs::metadata(&canonical).map_err(internal)?;
    if !metadata.is_dir() {
        return Err((2, "scan path must be a directory".into()));
    }
    let git = canonical.join(".git").exists();

    let (status, findings, semgrep_status, semgrep_version, reason, execution_successful) =
        match run_semgrep(&config, &canonical)? {
            SemgrepOutcome::Completed(report) => {
                let semgrep::Report {
                    version,
                    findings,
                    errors,
                } = report;
                let reason = (errors > 0).then(|| {
                    format!(
                        "semgrep reported {errors} recoverable error(s); results may be incomplete"
                    )
                });
                (
                    "partial",
                    findings,
                    "completed",
                    Some(version),
                    reason,
                    true,
                )
            }
            SemgrepOutcome::NotRun { reason } => (
                "not_verified",
                Vec::new(),
                "unavailable",
                None,
                Some(reason),
                false,
            ),
            SemgrepOutcome::Failed { reason } => (
                "not_verified",
                Vec::new(),
                "failed",
                None,
                Some(reason),
                false,
            ),
        };

    let policy = finding::BlockPolicy {
        fail_on: &config.fail_on,
        rule_overrides: &config.fail_on_rules,
        path_overrides: &config.fail_on_paths,
    };
    let blocking = finding::blocking_findings(&findings, &policy);
    let summary = ScanSummary {
        root: &canonical,
        git,
        status,
        findings: &findings,
        semgrep_status,
        semgrep_version: semgrep_version.as_deref(),
        reason: reason.as_deref(),
        fail_on: &config.fail_on,
        rule_overrides: config.fail_on_rules.len(),
        path_overrides: config.fail_on_paths.len(),
        blocked: !blocking.is_empty(),
        blocking_count: blocking.len(),
        execution_successful,
    };

    match format {
        "sarif" => out(format_args!("{}", scan_sarif(&summary))),
        "json" => out(format_args!("{}", scan_json(&summary))),
        _ => print_scan_text(&summary),
    }

    // A policy-blocking finding takes exit code 1. Otherwise coverage is still
    // incomplete (only the Semgrep adapter exists), so the scan is not verified.
    Ok(if summary.blocked { 1 } else { 4 })
}

enum SemgrepOutcome {
    Completed(semgrep::Report),
    NotRun { reason: String },
    Failed { reason: String },
}

/// Bundled ruleset, resolved relative to the working directory so that a scan
/// in a checkout of this repository works without any configuration.
const DEFAULT_RULES_PATH: &str = "policies/semgrep";

/// Returns the rules path to use, or `None` when there are no rules at all.
/// An explicitly configured path must exist; the bundled fallback is optional.
fn resolve_rules(config: &Config) -> Result<Option<PathBuf>, (u8, String)> {
    if let Some(configured) = config.semgrep_rules.as_deref() {
        let path = PathBuf::from(configured);
        if !path.exists() {
            return Err((
                2,
                format!("Semgrep rules path does not exist: {}", path.display()),
            ));
        }
        return Ok(Some(path));
    }
    let bundled = PathBuf::from(DEFAULT_RULES_PATH);
    Ok(bundled.is_dir().then_some(bundled))
}

fn run_semgrep(config: &Config, root: &std::path::Path) -> Result<SemgrepOutcome, (u8, String)> {
    if !config.semgrep_enabled {
        return Ok(SemgrepOutcome::NotRun {
            reason: "Semgrep is disabled by policy".into(),
        });
    }
    let Some(rules) = resolve_rules(config)? else {
        return Ok(SemgrepOutcome::NotRun {
            reason: "no Semgrep rules configured and no policies/semgrep directory found".into(),
        });
    };
    let Some(executable) = find_executable("semgrep") else {
        if config.semgrep_required {
            return Err((3, "required analyzer 'semgrep' is unavailable".into()));
        }
        return Ok(SemgrepOutcome::NotRun {
            reason: "semgrep is not installed".into(),
        });
    };

    let arguments = semgrep::arguments(&rules, root);
    let output_cap = (config.max_output_mb as usize).saturating_mul(1024 * 1024);
    let result = run_bounded(
        executable.as_os_str(),
        &arguments,
        Duration::from_secs(u64::from(config.timeout_seconds)),
        output_cap,
    )
    .map_err(|error| (6, format!("failed to run semgrep: {error}")))?;

    if result.timed_out {
        return Ok(SemgrepOutcome::Failed {
            reason: format!("semgrep exceeded the {} s timeout", config.timeout_seconds),
        });
    }
    match result.status {
        Some(0) | Some(1) => {}
        Some(code) => {
            return Ok(SemgrepOutcome::Failed {
                reason: format!("semgrep exited with status {code}"),
            })
        }
        None => {
            return Ok(SemgrepOutcome::Failed {
                reason: "semgrep terminated without an exit status".into(),
            })
        }
    }

    match semgrep::parse_report(&result.stdout, root) {
        Ok(report) => Ok(SemgrepOutcome::Completed(report)),
        Err(error) => Ok(SemgrepOutcome::Failed {
            reason: format!("semgrep output was rejected: {error}"),
        }),
    }
}

fn display_location(finding: &Finding) -> String {
    match (finding.line, finding.column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", finding.path),
        (Some(line), None) => format!("{}:{line}", finding.path),
        _ => finding.path.clone(),
    }
}

/// Everything the three scan output formats need to render.
struct ScanSummary<'a> {
    root: &'a std::path::Path,
    git: bool,
    status: &'a str,
    findings: &'a [Finding],
    semgrep_status: &'a str,
    semgrep_version: Option<&'a str>,
    reason: Option<&'a str>,
    fail_on: &'a str,
    rule_overrides: usize,
    path_overrides: usize,
    blocked: bool,
    blocking_count: usize,
    execution_successful: bool,
}

fn print_scan_text(summary: &ScanSummary) {
    out(format_args!("BAT84CODE scan"));
    out(format_args!("Root: {}", summary.root.display()));
    out(format_args!(
        "Repository: {}",
        if summary.git { "Git" } else { "directory" }
    ));
    out(format_args!("Status: {}", summary.status));
    out(format_args!("Findings: {}", summary.findings.len()));
    for finding in summary.findings {
        out(format_args!(
            "  {:<8} {}  {}  {}",
            finding.severity.as_str(),
            finding.rule_id,
            display_location(finding),
            finding.message
        ));
    }
    if summary.blocked {
        if summary.rule_overrides == 0 && summary.path_overrides == 0 {
            out(format_args!(
                "Blocking: {} finding(s) at or above fail_on = {}",
                summary.blocking_count, summary.fail_on
            ));
        } else {
            // Overrides change the effective threshold per finding, so report
            // the configured policy instead of claiming one threshold.
            out(format_args!(
                "Blocking: {} finding(s) (fail_on = {}, {} rule override(s), {} path override(s))",
                summary.blocking_count,
                summary.fail_on,
                summary.rule_overrides,
                summary.path_overrides
            ));
        }
    }
    if summary.semgrep_status == "completed" {
        out(format_args!("Checks: partial (semgrep completed; dependency, secret, container, and native checks unavailable)"));
        if let Some(reason) = summary.reason {
            out(format_args!("Note: {reason}"));
        }
    } else {
        out(format_args!(
            "Checks: incomplete ({})",
            summary.reason.unwrap_or("the analyzer did not run")
        ));
    }
    out(format_args!("No files were modified."));
}

fn scan_json(summary: &ScanSummary) -> String {
    let entries = summary
        .findings
        .iter()
        .map(Finding::to_json)
        .collect::<Vec<_>>()
        .join(",");
    let mut semgrep_check = format!(
        "{{\"name\":\"semgrep\",\"status\":{}",
        json_string(summary.semgrep_status)
    );
    if let Some(version) = summary.semgrep_version {
        semgrep_check.push_str(&format!(",\"version\":{}", json_string(version)));
    }
    if let Some(reason) = summary.reason {
        semgrep_check.push_str(&format!(",\"reason\":{}", json_string(reason)));
    }
    semgrep_check.push('}');
    let mut checks = vec![semgrep_check];
    for name in ["dependency", "secret", "container", "native"] {
        checks.push(format!(
            "{{\"name\":\"{name}\",\"status\":\"unavailable\"}}"
        ));
    }
    format!(
        "{{\"schema_version\":\"1.0\",\"command\":\"scan\",\"status\":{},\"fail_on\":{},\"fail_on_overrides\":{{\"rules\":{},\"paths\":{}}},\"blocked\":{},\"root\":{},\"repository\":{},\"findings\":[{}],\"checks\":[{}]}}",
        json_string(summary.status),
        json_string(summary.fail_on),
        summary.rule_overrides,
        summary.path_overrides,
        summary.blocked,
        json_string(&summary.root.to_string_lossy()),
        summary.git,
        entries,
        checks.join(",")
    )
}

fn scan_sarif(summary: &ScanSummary) -> String {
    let results = summary
        .findings
        .iter()
        .map(Finding::to_sarif_result)
        .collect::<Vec<_>>()
        .join(",");
    let notification = format!(
        "{{\"level\":\"warning\",\"message\":{{\"text\":{}}}}}",
        json_string(&format!(
            "Verification incomplete: {}",
            summary.reason.unwrap_or(
                "semgrep completed but dependency, secret, container, and native checks are unavailable"
            )
        ))
    );
    format!(
        "{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"BAT84CODE\",\"version\":\"0.1.0\",\"rules\":[]}}}},\"invocations\":[{{\"executionSuccessful\":{},\"toolExecutionNotifications\":[{notification}]}}],\"results\":[{results}]}}]}}",
        summary.execution_successful
    )
}

fn diff(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &[])?;
    let base = single_positional(args, "diff")?
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "HEAD".into());
    let root = env::current_dir().map_err(internal)?;
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("diff")
        .arg("--name-only")
        .arg(&base)
        .arg("--")
        .output()
        .map_err(|_| (3, "git is unavailable".into()))?;
    if !output.status.success() {
        return Err((2, "git diff failed; verify the base revision".into()));
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        out(format_args!("{line}"));
    }
    Ok(0)
}

fn os_args(values: &[&str]) -> Vec<std::ffi::OsString> {
    values.iter().map(std::ffi::OsString::from).collect()
}

fn self_test(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &["--format"])?;
    let format = format_arg(args)?.unwrap_or("text");
    if format == "sarif" {
        return Err((2, "self-test supports text or json output".into()));
    }
    // Each check exercises the behavior it names, using argument lists that fail
    // before any report is printed.
    let checks = [
        (
            "cli_dispatch",
            matches!(
                run(os_args(&["definitely-not-a-command"])),
                Err((2, message)) if message.contains("unknown command")
            ),
        ),
        (
            "json_escaping",
            json_string("quote \" slash \\").contains("\\\""),
        ),
        (
            "exit_codes",
            matches!(run(os_args(&["scan", "--unknown-option"])), Err((2, _)))
                && matches!(run(os_args(&["scan", "--config"])), Err((2, _)))
                && matches!(run(os_args(&["scan", ".", "--format", "xml"])), Err((2, _))),
        ),
    ];
    if let Some((name, _)) = checks.iter().find(|(_, passed)| !*passed) {
        return Err((6, format!("built-in {name} check failed")));
    }
    let names = checks.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    if format == "json" {
        out(format_args!(
            "{{\"schema_version\":\"1.0\",\"command\":\"self-test\",\"passed\":true,\"checks\":[\"{}\",\"{}\",\"{}\"]}}",
            names[0], names[1], names[2]
        ));
    } else {
        out(format_args!("Self-test passed: {}", names.join(", ")));
    }
    Ok(0)
}

fn format_arg(args: &[std::ffi::OsString]) -> Result<Option<&str>, (u8, String)> {
    let mut iter = option_slice(args).iter();
    while let Some(arg) = iter.next() {
        if arg == "--format" {
            let value = iter
                .next()
                .and_then(|v| v.to_str())
                .ok_or((2, "--format requires text, json, or sarif".into()))?;
            if value != "text" && value != "json" && value != "sarif" {
                return Err((2, "--format must be text, json, or sarif".into()));
            }
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// Arguments before a `--` terminator; everything after it is positional data.
fn option_slice(args: &[std::ffi::OsString]) -> &[std::ffi::OsString] {
    let end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    &args[..end]
}

fn positionals(args: &[std::ffi::OsString]) -> Vec<&std::ffi::OsString> {
    let mut found = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            found.extend(iter.by_ref());
            break;
        }
        if arg == "--format" || arg == "--config" {
            iter.next();
            continue;
        }
        if !arg.to_string_lossy().starts_with('-') {
            found.push(arg);
        }
    }
    found
}

fn single_positional<'a>(
    args: &'a [std::ffi::OsString],
    command: &str,
) -> Result<Option<&'a std::ffi::OsString>, (u8, String)> {
    let values = positionals(args);
    if let Some(extra) = values.get(1) {
        return Err((
            2,
            format!(
                "unexpected argument '{}' for {command}",
                extra.to_string_lossy()
            ),
        ));
    }
    Ok(values.first().copied())
}

fn reject_positionals(args: &[std::ffi::OsString], command: &str) -> Result<(), (u8, String)> {
    if let Some(value) = positionals(args).first() {
        return Err((
            2,
            format!(
                "{command} does not accept positional arguments (found '{}')",
                value.to_string_lossy()
            ),
        ));
    }
    Ok(())
}

fn reject_unknown(args: &[std::ffi::OsString], allowed: &[&str]) -> Result<(), (u8, String)> {
    for arg in option_slice(args) {
        if arg.to_string_lossy().starts_with('-') && !allowed.iter().any(|value| arg == value) {
            return Err((2, format!("unknown option '{}'.", arg.to_string_lossy())));
        }
    }
    Ok(())
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for directory in env::split_paths(&paths) {
        #[cfg(windows)]
        let candidates = [
            directory.join(format!("{name}.exe")),
            directory.join(format!("{name}.com")),
        ];
        #[cfg(not(windows))]
        let candidates = [directory.join(name)];
        if let Some(candidate) = candidates.into_iter().find(|candidate| candidate.is_file()) {
            return Some(candidate);
        }
    }
    None
}

#[derive(Debug)]
struct BoundedResult {
    status: Option<i32>,
    stdout: String,
    timed_out: bool,
}

#[derive(Debug)]
enum ToolStatus {
    Available(String),
    Unavailable,
    Timeout,
    Skipped,
}

impl ToolStatus {
    fn label(&self) -> &'static str {
        match self {
            Self::Available(_) => "available",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
        }
    }
    fn version(&self) -> Option<&str> {
        match self {
            Self::Available(version) => Some(version),
            _ => None,
        }
    }
    fn display(&self) -> String {
        match self {
            Self::Available(version) => format!("available ({version})"),
            Self::Unavailable => "unavailable (optional)".into(),
            Self::Timeout => "timed out (optional)".into(),
            Self::Skipped => "not checked (--no-tools)".into(),
        }
    }
}

fn first_line(output: &str) -> String {
    output
        .lines()
        .next()
        .unwrap_or("version unknown")
        .chars()
        .take(160)
        .collect()
}

fn run_bounded<P: AsRef<std::ffi::OsStr>, A: AsRef<std::ffi::OsStr>>(
    program: P,
    args: &[A],
    timeout: Duration,
    output_cap: usize,
) -> std::io::Result<BoundedResult> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut reader = stdout;
        let mut retained = Vec::with_capacity(output_cap.min(1024));
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let remaining = output_cap.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..count.min(remaining)]);
                }
            }
        }
        let _ = sender.send(String::from_utf8_lossy(&retained).into_owned());
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status.code().unwrap_or(1));
        }
        if Instant::now() >= deadline {
            timed_out = true;
            terminate_process_tree(&mut child)?;
            break Some(child.wait()?.code().unwrap_or(1));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = receiver
        .recv_timeout(Duration::from_millis(250))
        .unwrap_or_default();
    Ok(BoundedResult {
        status,
        stdout,
        timed_out,
    })
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut std::process::Child) -> std::io::Result<()> {
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let group = -(child.id() as i32);
    // The child was started in a fresh process group above, so the negative PID targets that group.
    let result = unsafe { kill(group, 9) };
    if result == 0 || child.try_wait()?.is_some() {
        Ok(())
    } else {
        child.kill()
    }
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut std::process::Child) -> std::io::Result<()> {
    child.kill()
}

pub(crate) fn json_string(input: &str) -> String {
    let mut out = String::from("\"");
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn internal(error: std::io::Error) -> (u8, String) {
    (6, format!("internal error: {error}"))
}

#[derive(Debug)]
struct Config {
    report_format: String,
    network: String,
    max_parallel: u32,
    timeout_seconds: u32,
    max_output_mb: u32,
    follow_symlinks: bool,
    include_source_snippets: bool,
    redact_secrets: bool,
    remediation_mode: String,
    require_confirmation: bool,
    semgrep_enabled: bool,
    semgrep_required: bool,
    semgrep_rules: Option<String>,
    fail_on: String,
    fail_on_rules: Vec<(String, String)>,
    fail_on_paths: Vec<(String, String)>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            report_format: "text".into(),
            network: "deny".into(),
            max_parallel: 4,
            timeout_seconds: 300,
            max_output_mb: 32,
            follow_symlinks: false,
            include_source_snippets: false,
            redact_secrets: true,
            remediation_mode: "plan-only".into(),
            require_confirmation: true,
            semgrep_enabled: true,
            semgrep_required: false,
            semgrep_rules: None,
            fail_on: "high".into(),
            fail_on_rules: Vec::new(),
            fail_on_paths: Vec::new(),
        }
    }
}

fn load_config(args: &[std::ffi::OsString]) -> Result<Config, (u8, String)> {
    let options = option_slice(args);
    let path = match options.iter().position(|arg| arg == "--config") {
        Some(index) => {
            let value = options
                .get(index + 1)
                .ok_or((2, "--config requires a path".into()))?;
            if value.to_string_lossy().starts_with('-') {
                return Err((2, "--config requires a path".into()));
            }
            PathBuf::from(value.as_os_str())
        }
        None => PathBuf::from("bat84.toml"),
    };
    let mut config = Config::default();
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| (2, format!("cannot read config {}: {e}", path.display())))?;
        parse_config(&content, &mut config)
            .map_err(|e| (2, format!("invalid config {}: {e}", path.display())))?;
    }
    if let Ok(value) = env::var("BAT84_REPORT_FORMAT") {
        config.report_format = value;
    }
    if let Ok(value) = env::var("BAT84_NETWORK") {
        config.network = value;
    }
    if let Ok(value) = env::var("BAT84_FAIL_ON") {
        config.fail_on = value;
    }
    // The environment replaces the file's override list wholesale, following
    // the same defaults -> file -> environment -> flags chain as every other
    // setting; an empty value clears the list.
    if let Ok(value) = env::var("BAT84_FAIL_ON_RULES") {
        config.fail_on_rules = parse_override_list("BAT84_FAIL_ON_RULES", &value)?;
    }
    if let Ok(value) = env::var("BAT84_FAIL_ON_PATHS") {
        config.fail_on_paths = parse_override_list("BAT84_FAIL_ON_PATHS", &value)?;
    }
    validate_config(&config)?;
    Ok(config)
}

fn parse_config(input: &str, config: &mut Config) -> Result<(), String> {
    let mut section = String::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_owned();
            let known = [
                "scan",
                "report",
                "remediation",
                "tools.semgrep",
                "scan.fail_on_rule",
                "scan.fail_on_path",
            ];
            if !known.contains(&section.as_str()) {
                return Err(format!("line {line_number}: unknown section [{section}]"));
            }
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: expected key = value"))?;
        let key = key.trim();
        let value = raw_value.trim();
        let fail = || format!("line {line_number}: unknown or invalid key '{key}' in [{section}]");
        // Override sections map a quoted pattern to a threshold. The first
        // definition of a pattern wins, matching the first-match-wins rule
        // used when thresholds are applied to findings.
        if section == "scan.fail_on_rule" || section == "scan.fail_on_path" {
            let pattern = parse_string(key)
                .filter(|pattern| !pattern.is_empty())
                .ok_or_else(|| {
                    format!("line {line_number}: expected a quoted pattern key in [{section}]")
                })?;
            let severity = parse_string(value).ok_or_else(|| {
                format!("line {line_number}: expected a quoted severity in [{section}]")
            })?;
            let list = if section == "scan.fail_on_rule" {
                &mut config.fail_on_rules
            } else {
                &mut config.fail_on_paths
            };
            if !list.iter().any(|(existing, _)| *existing == pattern) {
                list.push((pattern, severity));
            }
            continue;
        }
        match (section.as_str(), key) {
            ("scan", "profile") => {
                let _ = parse_string(value).ok_or_else(fail)?;
            }
            ("scan", "network") => config.network = parse_string(value).ok_or_else(fail)?,
            ("scan", "max_parallel") => {
                config.max_parallel = parse_integer(value).ok_or_else(fail)?
            }
            ("scan", "timeout_seconds") => {
                config.timeout_seconds = parse_integer(value).ok_or_else(fail)?
            }
            ("scan", "max_output_mb") => {
                config.max_output_mb = parse_integer(value).ok_or_else(fail)?
            }
            ("scan", "follow_symlinks") => {
                config.follow_symlinks = parse_bool(value).ok_or_else(fail)?
            }
            ("scan", "fail_on") => config.fail_on = parse_string(value).ok_or_else(fail)?,
            ("report", "format") => config.report_format = parse_string(value).ok_or_else(fail)?,
            ("report", "include_source_snippets") => {
                config.include_source_snippets = parse_bool(value).ok_or_else(fail)?
            }
            ("report", "redact_secrets") => {
                config.redact_secrets = parse_bool(value).ok_or_else(fail)?
            }
            ("remediation", "mode") => {
                config.remediation_mode = parse_string(value).ok_or_else(fail)?
            }
            ("remediation", "require_confirmation") => {
                config.require_confirmation = parse_bool(value).ok_or_else(fail)?
            }
            ("tools.semgrep", "enabled") => {
                config.semgrep_enabled = parse_bool(value).ok_or_else(fail)?
            }
            ("tools.semgrep", "required") => {
                config.semgrep_required = parse_bool(value).ok_or_else(fail)?
            }
            ("tools.semgrep", "rules") => {
                config.semgrep_rules = Some(parse_string(value).ok_or_else(fail)?)
            }
            _ => return Err(fail()),
        }
    }
    Ok(())
}

fn parse_string(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut output = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            // An unescaped quote cannot appear inside a basic string.
            '"' => return None,
            '\\' => match characters.next()? {
                '\\' => output.push('\\'),
                '"' => output.push('"'),
                _ => return None,
            },
            other => output.push(other),
        }
    }
    Some(output)
}
fn parse_integer(value: &str) -> Option<u32> {
    value.parse().ok()
}
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Severity values accepted by `fail_on` and its overrides.
const THRESHOLDS: [&str; 6] = ["critical", "high", "medium", "low", "info", "never"];

/// Parses an override list from an environment variable: `pattern=severity`
/// entries separated by `;`, with optional whitespace. An empty value yields
/// an empty list. Errors name the variable so a bad value is easy to trace.
fn parse_override_list(variable: &str, value: &str) -> Result<Vec<(String, String)>, (u8, String)> {
    let mut overrides = Vec::new();
    for entry in value.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Split at the last `=`: severities never contain one, patterns may.
        let Some((pattern, severity)) = entry.rsplit_once('=') else {
            return Err((
                2,
                format!("{variable}: entry '{entry}' must have the form pattern=severity"),
            ));
        };
        let (pattern, severity) = (pattern.trim(), severity.trim());
        if pattern.is_empty() {
            return Err((
                2,
                format!("{variable}: entry '{entry}' has an empty pattern"),
            ));
        }
        if !THRESHOLDS.contains(&severity) {
            return Err((
                2,
                format!(
                    "{variable}: entry '{entry}' severity must be critical, high, medium, low, info, or never"
                ),
            ));
        }
        // The first definition of a pattern wins, as in the config file.
        if !overrides.iter().any(|(existing, _)| *existing == pattern) {
            overrides.push((pattern.to_string(), severity.to_string()));
        }
    }
    Ok(overrides)
}

fn validate_config(config: &Config) -> Result<(), (u8, String)> {
    if !["text", "json", "sarif"].contains(&config.report_format.as_str()) {
        return Err((2, "report.format must be text, json, or sarif".into()));
    }
    if !["deny", "allow"].contains(&config.network.as_str()) {
        return Err((2, "scan.network must be deny or allow".into()));
    }
    if config.max_parallel == 0 || config.timeout_seconds == 0 || config.max_output_mb == 0 {
        return Err((2, "scan limits must be greater than zero".into()));
    }
    if config.remediation_mode != "plan-only" {
        return Err((2, "remediation.mode must be plan-only in this build".into()));
    }
    if config.semgrep_required && !config.semgrep_enabled {
        return Err((2, "required Semgrep cannot be disabled".into()));
    }
    if config.semgrep_rules.as_deref() == Some("") {
        return Err((2, "tools.semgrep.rules must not be empty".into()));
    }
    if !THRESHOLDS.contains(&config.fail_on.as_str()) {
        return Err((
            2,
            "scan.fail_on must be critical, high, medium, low, info, or never".into(),
        ));
    }
    for (pattern, severity) in config
        .fail_on_rules
        .iter()
        .chain(config.fail_on_paths.iter())
    {
        if !THRESHOLDS.contains(&severity.as_str()) {
            return Err((
                2,
                format!(
                    "fail_on override for '{pattern}' must be critical, high, medium, low, info, or never"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn json_string_escapes_whitespace_controls() {
        assert_eq!(json_string("a\nb\rc\td"), r#""a\nb\rc\td""#);
    }

    #[test]
    fn json_string_escapes_other_control_characters() {
        assert_eq!(json_string("\u{1}"), r#""\u0001""#);
    }

    #[test]
    fn shipped_policy_parses_and_validates() {
        let mut config = Config::default();
        parse_config(include_str!("../policies/default.toml"), &mut config)
            .expect("policies/default.toml must parse");
        assert_eq!(config.report_format, "text");
        assert_eq!(config.network, "deny");
        assert_eq!(config.max_parallel, 4);
        assert_eq!(config.timeout_seconds, 300);
        assert_eq!(config.max_output_mb, 32);
        assert!(!config.follow_symlinks);
        assert!(!config.include_source_snippets);
        assert!(config.redact_secrets);
        assert_eq!(config.remediation_mode, "plan-only");
        assert!(config.require_confirmation);
        assert!(config.semgrep_enabled);
        assert!(!config.semgrep_required);
        assert_eq!(config.semgrep_rules.as_deref(), Some("policies/semgrep"));
        assert_eq!(config.fail_on, "high");
        // The shipped policy only documents overrides in comments.
        assert!(config.fail_on_rules.is_empty());
        assert!(config.fail_on_paths.is_empty());
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn bundled_ruleset_declares_complete_rules() {
        let rules = include_str!("../policies/semgrep/default.yml");
        let blocks: Vec<&str> = rules.split("\n  - id: ").skip(1).collect();
        assert!(
            blocks.len() >= 8,
            "expected the bundled ruleset to ship at least 8 rules, found {}",
            blocks.len()
        );
        for block in blocks {
            let id = block.lines().next().unwrap_or("").trim();
            assert!(id.starts_with("bat84."), "unexpected rule id {id}");
            for key in [
                "languages:",
                "severity:",
                "message:",
                "pattern",
                "confidence:",
            ] {
                assert!(block.contains(key), "rule {id} is missing {key}");
            }
        }
    }

    #[test]
    fn parses_fail_on_threshold() {
        let mut config = Config::default();
        parse_config("[scan]\nfail_on = \"critical\"\n", &mut config).unwrap();
        assert_eq!(config.fail_on, "critical");
        assert!(validate_config(&config).is_ok());

        // Any string parses here; the allowed values are enforced by validation.
        let mut config = Config::default();
        parse_config("[scan]\nfail_on = \"yes\"\n", &mut config).unwrap();
        assert_eq!(config.fail_on, "yes");
        assert_eq!(validate_config(&config).unwrap_err().0, 2);

        // A non-string value fails to parse, with a line number.
        let mut config = Config::default();
        let err = parse_config("[scan]\nfail_on = 3\n", &mut config).unwrap_err();
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn parses_fail_on_overrides() {
        let mut config = Config::default();
        parse_config(
            "[scan]\nfail_on = \"high\"\n\n\
             [scan.fail_on_rule]\n\"bat84.eval-usage\" = \"never\"\n\"bat84.*-password\" = \"critical\"\n\n\
             [scan.fail_on_path]\n\"tests/**\" = \"never\"\n\"vendor/**\" = \"low\"\n",
            &mut config,
        )
        .expect("override sections parse");
        assert_eq!(config.fail_on, "high");
        assert_eq!(
            config.fail_on_rules,
            [
                ("bat84.eval-usage".to_string(), "never".to_string()),
                ("bat84.*-password".to_string(), "critical".to_string()),
            ]
        );
        assert_eq!(
            config.fail_on_paths,
            [
                ("tests/**".to_string(), "never".to_string()),
                ("vendor/**".to_string(), "low".to_string()),
            ]
        );
        assert!(validate_config(&config).is_ok());

        // The first definition of a pattern wins.
        let mut config = Config::default();
        parse_config(
            "[scan.fail_on_rule]\n\"x\" = \"never\"\n\"x\" = \"critical\"\n",
            &mut config,
        )
        .expect("duplicate pattern is accepted");
        assert_eq!(
            config.fail_on_rules,
            [("x".to_string(), "never".to_string())]
        );

        // Keys must be quoted, non-empty patterns.
        let mut config = Config::default();
        let err =
            parse_config("[scan.fail_on_path]\ntests/** = \"never\"\n", &mut config).unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("quoted pattern key"), "{err}");
        let mut config = Config::default();
        let err = parse_config("[scan.fail_on_path]\n\"\" = \"never\"\n", &mut config).unwrap_err();
        assert!(err.contains("line 2"), "{err}");

        // Severities are enforced by validation, like `fail_on` itself.
        let mut config = Config::default();
        parse_config("[scan.fail_on_rule]\n\"x\" = \"sometimes\"\n", &mut config)
            .expect("any string parses");
        let (code, message) = validate_config(&config).unwrap_err();
        assert_eq!(code, 2);
        assert!(message.contains("'x'"), "{message}");
    }

    #[test]
    fn parses_override_lists_from_the_environment_syntax() {
        // Entries are `pattern=severity` separated by `;`, whitespace allowed.
        let list = parse_override_list(
            "BAT84_FAIL_ON_RULES",
            " bat84.eval-usage = never ; bat84.*-password=critical ; ",
        )
        .expect("valid list parses");
        assert_eq!(
            list,
            [
                ("bat84.eval-usage".to_string(), "never".to_string()),
                ("bat84.*-password".to_string(), "critical".to_string()),
            ]
        );

        // An empty value clears the list.
        assert!(parse_override_list("BAT84_FAIL_ON_PATHS", "")
            .expect("empty value is valid")
            .is_empty());

        // The first definition of a pattern wins, as in the config file.
        let list = parse_override_list("BAT84_FAIL_ON_RULES", "x=never;x=critical")
            .expect("duplicate parses");
        assert_eq!(list, [("x".to_string(), "never".to_string())]);

        // Patterns may contain `=`; the split happens at the last one.
        let list = parse_override_list("BAT84_FAIL_ON_PATHS", "a=b.js=never")
            .expect("pattern with equals parses");
        assert_eq!(list, [("a=b.js".to_string(), "never".to_string())]);

        // Malformed entries fail loudly, naming the variable.
        let (code, message) = parse_override_list("BAT84_FAIL_ON_RULES", "nonsense").unwrap_err();
        assert_eq!(code, 2);
        assert!(message.contains("BAT84_FAIL_ON_RULES"), "{message}");
        assert!(message.contains("pattern=severity"), "{message}");
        let (_, message) = parse_override_list("BAT84_FAIL_ON_PATHS", "=never").unwrap_err();
        assert!(message.contains("empty pattern"), "{message}");
        let (_, message) = parse_override_list("BAT84_FAIL_ON_RULES", "x=sometimes").unwrap_err();
        assert!(message.contains("severity must be"), "{message}");
    }

    #[test]
    fn parses_semgrep_rules_path() {
        let mut config = Config::default();
        parse_config(
            "[tools.semgrep]\nrules = \"policies/semgrep\"\n",
            &mut config,
        )
        .unwrap();
        assert_eq!(config.semgrep_rules.as_deref(), Some("policies/semgrep"));
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_empty_semgrep_rules_path() {
        let mut config = Config::default();
        parse_config("[tools.semgrep]\nrules = \"\"\n", &mut config).unwrap();
        assert_eq!(validate_config(&config).unwrap_err().0, 2);
    }

    #[test]
    fn parse_config_ignores_comments_and_blank_lines() {
        let mut config = Config::default();
        parse_config(
            "# leading comment\n\n[scan] # trailing comment\nmax_parallel = 8\n",
            &mut config,
        )
        .expect("comments and blank lines are allowed");
        assert_eq!(config.max_parallel, 8);
    }

    #[test]
    fn parse_config_rejects_unknown_section() {
        let mut config = Config::default();
        let err = parse_config("[nope]\n", &mut config).unwrap_err();
        assert!(err.contains("line 1"), "{err}");
        assert!(err.contains("unknown section [nope]"), "{err}");
    }

    #[test]
    fn parse_config_rejects_unknown_key() {
        let mut config = Config::default();
        let err = parse_config("[scan]\nbogus = \"x\"\n", &mut config).unwrap_err();
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("'bogus'"), "{err}");
    }

    #[test]
    fn parse_config_rejects_invalid_values() {
        let mut config = Config::default();
        assert!(parse_config("[scan]\nmax_parallel = \"four\"\n", &mut config).is_err());
        let mut config = Config::default();
        assert!(parse_config("[scan]\nfollow_symlinks = 1\n", &mut config).is_err());
        let mut config = Config::default();
        assert!(parse_config("[report]\nformat = \"json\n", &mut config).is_err());
        let mut config = Config::default();
        assert!(parse_config("[scan]\nmax_parallel 4\n", &mut config).is_err());
    }

    fn config_with(update: impl FnOnce(&mut Config)) -> Config {
        let mut config = Config::default();
        update(&mut config);
        config
    }

    #[test]
    fn validate_config_rejects_policy_violations() {
        let invalid = [
            config_with(|config| config.report_format = "xml".into()),
            config_with(|config| config.network = "sometimes".into()),
            config_with(|config| config.max_parallel = 0),
            config_with(|config| config.remediation_mode = "apply".into()),
            config_with(|config| {
                config.semgrep_enabled = false;
                config.semgrep_required = true;
            }),
            config_with(|config| config.fail_on = "sometimes".into()),
            config_with(|config| {
                config
                    .fail_on_paths
                    .push(("tests/**".into(), "sometimes".into()))
            }),
        ];
        for config in &invalid {
            assert_eq!(validate_config(config).unwrap_err().0, 2);
        }

        assert!(validate_config(&config_with(|config| config.network = "allow".into())).is_ok());
        assert!(validate_config(&config_with(|config| config.fail_on = "never".into())).is_ok());
        assert!(validate_config(&config_with(|config| config.fail_on = "critical".into())).is_ok());
    }

    #[test]
    fn scalar_parsers_accept_only_supported_syntax() {
        assert_eq!(parse_string("\"abc\""), Some("abc".into()));
        assert_eq!(parse_string("\"\""), Some(String::new()));
        assert_eq!(parse_string("abc"), None);
        assert_eq!(parse_string("\"a\\nb\""), None);
        assert_eq!(parse_string("\""), None);
        assert_eq!(parse_string(r#""a\\b""#), Some(r"a\b".into()));
        assert_eq!(parse_string(r#""a\"b""#), Some(r#"a"b"#.into()));
        assert_eq!(parse_string(r#""a\\""#), Some(r"a\".into()));
        assert_eq!(parse_integer("42"), Some(42));
        assert_eq!(parse_integer("-1"), None);
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("yes"), None);
    }

    #[test]
    fn positional_skips_option_values() {
        let values = args(&["--format", "json", "--config", "bat84.toml", "repo"]);
        let found = positionals(&values);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].to_string_lossy(), "repo");
        assert!(positionals(&args(&["--format", "json"])).is_empty());
        assert!(positionals(&args(&["--no-tools"])).is_empty());
    }

    #[test]
    fn terminator_allows_dash_prefixed_positionals() {
        let values = args(&["--format", "json", "--", "-dash-dir"]);
        let found = positionals(&values);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].to_string_lossy(), "-dash-dir");
        assert_eq!(format_arg(&values).unwrap(), Some("json"));
        assert!(reject_unknown(&values, &["--format"]).is_ok());
        assert_eq!(
            single_positional(&values, "scan")
                .unwrap()
                .map(|value| value.to_string_lossy().into_owned()),
            Some("-dash-dir".into())
        );
    }

    #[test]
    fn extra_positionals_are_rejected() {
        assert!(single_positional(&args(&["a", "b"]), "scan").is_err());
        assert!(single_positional(&args(&["a"]), "scan").unwrap().is_some());
        assert!(single_positional(&args(&["--format", "json"]), "scan")
            .unwrap()
            .is_none());
        assert!(reject_positionals(&args(&["extra"]), "doctor").is_err());
        assert!(reject_positionals(&args(&["--no-tools"]), "doctor").is_ok());
        assert!(reject_positionals(&args(&["--", "extra"]), "doctor").is_err());
    }

    #[test]
    fn reject_unknown_allows_listed_flags_only() {
        assert!(reject_unknown(&args(&["--format", "json", "some/path"]), &["--format"]).is_ok());
        let (code, message) = reject_unknown(&args(&["--bogus"]), &["--format"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(message.contains("--bogus"), "{message}");
        // Everything after the terminator is positional data, not an option.
        assert!(reject_unknown(&args(&["--", "--bogus"]), &[]).is_ok());
    }

    #[test]
    fn format_arg_accepts_known_formats_only() {
        assert_eq!(
            format_arg(&args(&["--format", "sarif"])).unwrap(),
            Some("sarif")
        );
        assert_eq!(format_arg(&args(&[])).unwrap(), None);
        assert_eq!(format_arg(&args(&["--", "--format", "xml"])).unwrap(), None);
        assert!(format_arg(&args(&["--format"])).is_err());
        assert!(format_arg(&args(&["--format", "xml"])).is_err());
    }

    #[test]
    fn first_line_takes_one_line_and_caps_length() {
        assert_eq!(first_line("one\ntwo"), "one");
        assert_eq!(first_line(""), "version unknown");
        assert_eq!(first_line(&"x".repeat(400)).chars().count(), 160);
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_captures_output_without_timeout() {
        let result = run_bounded(
            std::ffi::OsStr::new("sh"),
            &["-c", "printf hello"],
            Duration::from_secs(5),
            1024,
        )
        .expect("spawn sh");
        assert_eq!(result.status, Some(0));
        assert_eq!(result.stdout, "hello");
        assert!(!result.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_times_out_and_caps_output() {
        let start = Instant::now();
        let result = run_bounded(
            std::ffi::OsStr::new("sh"),
            &["-c", "yes"],
            Duration::from_millis(200),
            512,
        )
        .expect("spawn sh");
        assert!(result.timed_out, "expected the probe to time out");
        assert_eq!(result.stdout.len(), 512);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "timeout enforcement took too long"
        );
    }
}
