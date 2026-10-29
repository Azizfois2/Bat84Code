# BAT84CODE

BAT84CODE is a local-first defensive repository inspection CLI. This repository contains the M1 command-line scaffold from the V1 technical specification plus a Semgrep analyzer adapter. The Rust CLI is designed to build on Linux, macOS, and Windows; strong sandbox guarantees remain Linux-only future work.

## Build

Install the stable Rust toolchain on Linux, macOS, or Windows, then run:

```sh
cargo build --locked
cargo run -- --help
```

## Development checks

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs these on every push to `main` and every pull request:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
```

## Commands

- `bat84 doctor [--no-tools] [--format text|json]` reports the host platform and probes optional analyzer versions with a 10-second timeout and 1 KiB output cap. `--no-tools` skips subprocess probes.
- `bat84 scan [PATH] [--format text|json|sarif] [--config PATH]` validates and canonicalizes a directory without writing to it. Local Semgrep rules are used (the bundled `policies/semgrep` directory by default, or `[tools.semgrep] rules`); when Semgrep is installed it runs with metrics and version checks disabled, normalizes findings with SHA-256 evidence digests, and reports `partial`. Dependency, secret, container, and native checks are not implemented, so a scan exits 4 unless findings meet the blocking threshold (`[scan] fail_on`, default `high`), in which case it exits 1. A required-but-missing Semgrep exits 3, and unusable analyzer output is reported as `not_verified`.
- `bat84 diff [BASE]` lists tracked changed paths against a Git revision, using argv without a shell.
- `bat84 self-test [--format text|json]` performs built-in integrity checks.

The implementation uses only the Rust standard library. `doctor` resolves native executables on `PATH` (`.exe`/`.com` on Windows) and invokes them without a shell. On timeout, Unix platforms terminate the spawned process group; Windows currently terminates only the direct child process. Semgrep is the only analyzer adapter; it is optional and runs only with configured local rules. The CLI does not yet create an isolation sandbox, run build or test commands, or produce remediation. See [docs/limitations.md](docs/limitations.md).

Configuration defaults to `./bat84.toml`; `--config PATH` selects a different file. `BAT84_REPORT_FORMAT` and `BAT84_NETWORK` override file values, and CLI flags override both. The current dependency-free parser accepts the BAT84CODE schema's simple string, boolean, and integer values. `\\` and `\"` escapes are supported (needed for Windows paths); other TOML string escapes are rejected.

`[scan] fail_on` sets the severity at or above which findings block (`critical`, `high`, `medium`, `low`, `info`, `never`; default `high`), returning exit code 1 instead of 4; findings with `unknown` severity never block. `BAT84_FAIL_ON` overrides the file value, which matters in CI:

```sh
BAT84_FAIL_ON=high bat84 scan . --format json || echo "policy violation or incomplete scan"
```

`[scan.fail_on_rule]` and `[scan.fail_on_path]` set thresholds for individual rules or path prefixes, so a noisy rule or a test tree can be exempted or tightened:

```toml
[scan.fail_on_rule]
"bat84.hardcoded-password" = "never"

[scan.fail_on_path]
"tests/**" = "critical"
```

Patterns are globs (`*` stays within one path segment, `**` crosses directories, `?` matches a single character) and must be quoted. For each finding the first matching path override applies, then the first matching rule override, then `fail_on`, so a location exemption wins over rule tuning; the first definition of a duplicate pattern wins.

`BAT84_FAIL_ON_RULES` and `BAT84_FAIL_ON_PATHS` provide the same overrides from the environment as `pattern=severity` entries separated by `;`. A variable replaces the file's list entirely (an empty value clears it), which suits CI:

```sh
BAT84_FAIL_ON_RULES='bat84.eval-usage=critical;bat84.hardcoded-password=never' bat84 scan .
BAT84_FAIL_ON_PATHS='tests/**=never;vendor/**=never' bat84 scan .
```

`[tools.semgrep] rules` points at a local rules file or directory. When it is unset, `scan` falls back to the bundled `policies/semgrep` directory relative to the working directory, so a scan in this checkout needs no configuration at all; that ruleset covers eval, hardcoded passwords, shell invocation, and unsafe deserialization (pickle, yaml.load, marshal, unserialize). With no rules anywhere (or `enabled = false`), scans report `not_verified`; an explicitly configured path that does not exist exits 2. Setting `required = true` makes a missing Semgrep installation exit 3.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed; no policy-blocking condition was found. |
| 1 | Policy-defined blocking finding detected (`[scan] fail_on`, default `high`). |
| 2 | Invalid arguments, configuration, or path. |
| 3 | Required tool missing or incompatible. |
| 4 | Verification incomplete or inconclusive. |
| 5 | Security policy violation or required isolation unavailable. |
| 6 | Internal error. |
| 130 | Interrupted by user. |

