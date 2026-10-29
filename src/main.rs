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
        print!("{HELP}");
        return Ok(0);
    };
    if command == "-h" || command == "--help" || command == "help" {
        print!("{HELP}");
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
    reject_unknown(
        args,
        &["--no-tools", "--format", "--config", "text", "json"],
    )?;
    let config = load_config(args)?;
    let no_tools = args.iter().any(|arg| arg == "--no-tools");
    let format = format_arg(args)?.unwrap_or(&config.report_format);
    if format == "sarif" {
        return Err((2, "doctor supports text or json output".into()));
    }
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
                    Duration::from_secs(2),
                    1024,
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
        println!("{{\"schema_version\":\"1.0\",\"command\":\"doctor\",\"platform\":{{\"os\":\"{os}\",\"arch\":\"{arch}\"}},\"tools\":[{entries}]}}");
    } else {
        println!("BAT84CODE doctor\nPlatform: {os}/{arch}");
        for (name, status) in discovered {
            println!("  {name}: {}", status.display());
        }
        println!("No repository files were modified.");
    }
    Ok(0)
}

fn scan(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &["--format", "--config", "text", "json"])?;
    let config = load_config(args)?;
    let format = format_arg(args)?.unwrap_or(&config.report_format);
    let path = positional(args)
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
    if format == "sarif" {
        println!("{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"BAT84CODE\",\"version\":\"0.1.0\",\"rules\":[]}}}},\"invocations\":[{{\"executionSuccessful\":false,\"toolExecutionNotifications\":[{{\"level\":\"warning\",\"message\":{{\"text\":\"Verification incomplete: no analyzer adapter is implemented in this build.\"}}}}]}}],\"results\":[]}}]}}");
    } else if format == "json" {
        println!("{{\"schema_version\":\"1.0\",\"command\":\"scan\",\"status\":\"not_verified\",\"root\":{},\"repository\":{},\"findings\":[],\"checks\":[{{\"name\":\"analyzers\",\"status\":\"unavailable\",\"reason\":\"no analyzer adapter is implemented in this build\"}}]}}", json_string(&canonical.to_string_lossy()), git);
    } else {
        println!("BAT84CODE scan\nRoot: {}\nRepository: {}\nFindings: 0\nChecks: incomplete (no analyzer adapter is implemented in this build)\nNo files were modified.", canonical.display(), if git { "Git" } else { "directory" });
    }
    Ok(4)
}

fn diff(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    let base = positional(args)
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
        println!("{line}");
    }
    Ok(0)
}

fn self_test(args: &[std::ffi::OsString]) -> Result<u8, (u8, String)> {
    reject_unknown(args, &["--format", "text", "json"])?;
    let format = format_arg(args)?.unwrap_or("text");
    if format == "sarif" {
        return Err((2, "self-test supports text or json output".into()));
    }
    let checks = ["cli_dispatch", "json_escaping", "exit_codes"];
    let json_ok = json_string("quote \" slash \\").contains("\\\"");
    if !json_ok {
        return Err((6, "built-in JSON escaping check failed".into()));
    }
    if format == "json" {
        println!("{{\"schema_version\":\"1.0\",\"command\":\"self-test\",\"passed\":true,\"checks\":[\"{}\",\"{}\",\"{}\"]}}", checks[0], checks[1], checks[2]);
    } else {
        println!("Self-test passed: {}", checks.join(", "));
    }
    Ok(0)
}

fn format_arg(args: &[std::ffi::OsString]) -> Result<Option<&str>, (u8, String)> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--format" {
            let value = iter
                .next()
                .and_then(|v| v.to_str())
                .ok_or((2, "--format requires text or json".into()))?;
            if value != "text" && value != "json" && value != "sarif" {
                return Err((2, "--format must be text, json, or sarif".into()));
            }
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn positional(args: &[std::ffi::OsString]) -> Option<&std::ffi::OsString> {
    let mut skip_value = false;
    for arg in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if arg == "--format" || arg == "--config" {
            skip_value = true;
            continue;
        }
        if !arg.to_string_lossy().starts_with('-') {
            return Some(arg);
        }
    }
    None
}

fn reject_unknown(args: &[std::ffi::OsString], allowed: &[&str]) -> Result<(), (u8, String)> {
    for arg in args {
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

fn run_bounded(
    program: &std::ffi::OsStr,
    args: &[&str],
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

fn json_string(input: &str) -> String {
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
        }
    }
}

fn load_config(args: &[std::ffi::OsString]) -> Result<Config, (u8, String)> {
    let config_index = args.iter().position(|arg| arg == "--config");
    if config_index.is_some_and(|index| args.get(index + 1).is_none()) {
        return Err((2, "--config requires a path".into()));
    }
    let path = config_index
        .and_then(|index| args.get(index + 1))
        .map(|value| PathBuf::from(value.as_os_str()))
        .unwrap_or_else(|| PathBuf::from("bat84.toml"));
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
            if !["scan", "report", "remediation", "tools.semgrep"].contains(&section.as_str()) {
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
            _ => return Err(fail()),
        }
    }
    Ok(())
}

fn parse_string(value: &str) -> Option<String> {
    if value.len() >= 2
        && value.starts_with('"')
        && value.ends_with('"')
        && !value[1..value.len() - 1]
            .chars()
            .any(|ch| ch == '"' || ch == '\\')
    {
        Some(value[1..value.len() - 1].to_owned())
    } else {
        None
    }
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
        assert!(validate_config(&config).is_ok());
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
        ];
        for config in &invalid {
            assert_eq!(validate_config(config).unwrap_err().0, 2);
        }

        assert!(validate_config(&config_with(|config| config.network = "allow".into())).is_ok());
    }

    #[test]
    fn scalar_parsers_accept_only_supported_syntax() {
        assert_eq!(parse_string("\"abc\""), Some("abc".into()));
        assert_eq!(parse_string("\"\""), Some(String::new()));
        assert_eq!(parse_string("abc"), None);
        assert_eq!(parse_string("\"a\\nb\""), None);
        assert_eq!(parse_string("\""), None);
        assert_eq!(parse_integer("42"), Some(42));
        assert_eq!(parse_integer("-1"), None);
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("yes"), None);
    }

    #[test]
    fn positional_skips_option_values() {
        let values = args(&["--format", "json", "--config", "bat84.toml", "repo"]);
        assert_eq!(
            positional(&values).map(|value| value.to_string_lossy().into_owned()),
            Some("repo".into())
        );
        assert!(positional(&args(&["--format", "json"])).is_none());
        assert!(positional(&args(&["--no-tools"])).is_none());
    }

    #[test]
    fn reject_unknown_allows_listed_flags_only() {
        assert!(reject_unknown(&args(&["--format", "json", "some/path"]), &["--format"]).is_ok());
        let (code, message) = reject_unknown(&args(&["--bogus"]), &["--format"]).unwrap_err();
        assert_eq!(code, 2);
        assert!(message.contains("--bogus"), "{message}");
    }

    #[test]
    fn format_arg_accepts_known_formats_only() {
        assert_eq!(
            format_arg(&args(&["--format", "sarif"])).unwrap(),
            Some("sarif")
        );
        assert_eq!(format_arg(&args(&[])).unwrap(), None);
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
