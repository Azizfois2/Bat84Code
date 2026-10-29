# Current limitations

This repository is the M1 CLI scaffold with an optional Semgrep adapter and a working test suite. The following V1 requirements are not yet implemented:

- Full TOML 1.0 parsing (the current dependency-free parser accepts only the simple scalar subset used by `policies/default.toml`) and complete configuration/environment/CLI precedence for every setting.
- Dependency, secret, container, and native-code checks. Only the optional Semgrep adapter exists, so a scan is at best `partial` and always exits 4.
- Policy-based blocking. No severity threshold is defined yet, so findings never produce exit code 1.
- Cancellation and per-rule analysis limits. Semgrep receives the configured whole-run timeout and output cap; there is no cancellation or incremental reporting.
- Platform-specific process cleanup applies to both `doctor` probes and Semgrep runs: Unix children start in a fresh process group that is killed on timeout, while Windows kills only the direct child.
- Report files. Reports go to stdout only; there is no JSON/SARIF file output, no SARIF rule metadata, and no SARIF fingerprints.
- Linux namespaces/seccomp/cgroups sandbox and network denial for untrusted builds. Strong process sandboxing is not implemented on any platform, including for analyzer execution.
- Patch planning, explicit apply, stale-plan checks, and isolated verification.
- Secret redaction, SBOM, signing, fuzzing, fixture evaluation, and performance benchmarks.
- Automated acceptance coverage for the SEC-01 through SEC-12 requirements.

## Semgrep adapter notes

- Semgrep runs only when `[tools.semgrep] rules` points at an existing local rules file or directory. There is no registry download and no `--config auto`, so scans stay local-first.
- Invocation is `semgrep scan --json --metrics=off --disable-version-check --config <rules> <root>`, with argv and no shell.
- `enabled = false` reports `not_verified`. With `required = true`, a missing Semgrep installation exits 3. A missing rules path exits 2.
- Analyzer output is untrusted: malformed JSON, missing fields, and paths outside the scan root make the scan `not_verified` with no findings.

## Verification status

- Built and tested on Linux x86_64 with the stable Rust toolchain (verified with 1.99.1). The suite has 41 unit tests (JSON parser, SHA-256, normalization, config) and 28 CLI integration tests, including a fake `semgrep` binary covering findings, SARIF results, malformed output, path escape, and required-tool behavior.
- `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` pass on that toolchain.
- CI (`.github/workflows/ci.yml`) runs formatting, Clippy, tests, and a release build on Ubuntu, macOS, and Windows for every push to `main` and every pull request.
- The adapter has not been exercised against a real Semgrep installation here, and the fake-analyzer tests are Unix-only. The Windows-only process termination path and SARIF consumers are not covered by tests.

Do not use this build to claim that a repository has passed a security scan. Scan coverage is partial: one analyzer runs at most, findings do not gate the exit code, and analyzer execution is not isolated.
