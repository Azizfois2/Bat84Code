# BAT84CODE

BAT84CODE is a local-first defensive repository inspection CLI. This repository currently contains the initial M1 command-line scaffold from the V1 technical specification. The Rust CLI is designed to build on Linux, macOS, and Windows; strong sandbox guarantees remain Linux-only future work.

## Build

Install the stable Rust toolchain on Linux, macOS, or Windows, then run:

```sh
cargo build --locked
cargo run -- --help
```

## Commands

- `bat84 doctor [--no-tools] [--format text|json]` reports the host platform and probes optional analyzer versions with a 2-second timeout and 1 KiB output cap. `--no-tools` skips subprocess probes.
- `bat84 scan [PATH] [--format text|json|sarif] [--config PATH]` validates and canonicalizes a directory without writing to it. Since analyzer adapters are not implemented yet, it reports `not_verified` and exits with code 4; it never reports an empty scan as clean. SARIF output sets `executionSuccessful` to false and includes an incomplete-verification notification.
- `bat84 diff [BASE]` lists tracked changed paths against a Git revision, using argv without a shell.
- `bat84 self-test [--format text|json]` performs built-in integrity checks.

The initial implementation uses only the Rust standard library. `doctor` resolves native executables on `PATH` (`.exe`/`.com` on Windows) and invokes them without a shell. On timeout, Unix platforms terminate the spawned process group; Windows currently terminates only the direct child process. The CLI does not yet run analyzers, create an isolation sandbox, normalize findings, emit SARIF, or support remediation. See [docs/limitations.md](docs/limitations.md).

Configuration defaults to `./bat84.toml`; `--config PATH` selects a different file. `BAT84_REPORT_FORMAT` and `BAT84_NETWORK` override file values, and CLI flags override both. The current dependency-free parser accepts the BAT84CODE schema's simple string, boolean, and integer values; unsupported TOML string escapes are rejected.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed; no policy-blocking condition was found. |
| 1 | Policy-defined blocking finding detected. |
| 2 | Invalid arguments, configuration, or path. |
| 3 | Required tool missing or incompatible. |
| 4 | Verification incomplete or inconclusive. |
| 5 | Security policy violation or required isolation unavailable. |
| 6 | Internal error. |
| 130 | Interrupted by user. |

