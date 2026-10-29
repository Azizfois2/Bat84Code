# Current limitations

This repository is the M1 CLI scaffold with an optional Semgrep adapter and a working test suite. The following V1 requirements are not yet implemented:

- Full TOML 1.0 parsing (the current dependency-free parser accepts only the simple scalar subset used by `policies/default.toml`) and complete configuration/environment/CLI precedence for every setting.
- Dependency, secret, container, and native-code checks. Only the optional Semgrep adapter exists, so a scan is at best `partial` and always exits 4.
- Policy-based blocking uses `[scan] fail_on` (default `high`): findings at or above it return exit 1, otherwise the scan returns 4. Findings with `unknown` severity never block, and there is no per-rule or per-path override yet.
- Cancellation and per-rule analysis limits. Semgrep receives the configured whole-run timeout and output cap; there is no cancellation or incremental reporting.
- Platform-specific process cleanup applies to both `doctor` probes and Semgrep runs: Unix children start in a fresh process group that is killed on timeout, while Windows kills only the direct child.
- Report files. Reports go to stdout only; there is no JSON/SARIF file output, no SARIF rule metadata, and no SARIF fingerprints.
- Linux namespaces/seccomp/cgroups sandbox and network denial for untrusted builds. Strong process sandboxing is not implemented on any platform, including for analyzer execution.
- Patch planning, explicit apply, stale-plan checks, and isolated verification.
- Secret redaction, SBOM, signing, fuzzing, fixture evaluation, and performance benchmarks.
- Automated acceptance coverage for the SEC-01 through SEC-12 requirements.

## Semgrep adapter notes

- Semgrep runs only with local rules: an explicit `[tools.semgrep] rules` file or directory, or the bundled `policies/semgrep` directory when that setting is omitted and the directory exists relative to the working directory. There is no registry download and no `--config auto`, so scans stay local-first. The bundled path is resolved from the working directory, not from the binary, so scanning another repository requires setting `rules` explicitly.
- Invocation is `semgrep scan --json --metrics=off --disable-version-check --no-rewrite-rule-ids --config <rules> <root>`, with argv and no shell. Rule identifiers are not rewritten, so findings and their digests do not depend on the rules file location.
- The bundled `policies/semgrep` ruleset is a starting point, not a complete rules library: it covers eval, hardcoded passwords, shell invocation (`os.system`, `os.popen`, `subprocess(shell=True)`, `child_process.exec`), and unsafe deserialization (`pickle`, `yaml.load`, `marshal`, `unserialize`). It is deliberately precision-first, so narrower cases such as dynamically imported shell helpers will be missed.
- `enabled = false`, or no rules anywhere, reports `not_verified`. With `required = true`, a missing Semgrep installation exits 3. An explicitly configured rules path that does not exist exits 2.
- Analyzer output is untrusted: malformed JSON, missing fields, and paths outside the scan root make the scan `not_verified` with no findings.

## Verification status

- Built and tested on Linux x86_64 with the stable Rust toolchain (verified with 1.99.1). The suite has 41 unit tests (JSON parser, SHA-256, normalization, config) and 28 CLI integration tests, including a fake `semgrep` binary covering findings, SARIF results, malformed output, path escape, and required-tool behavior.
- `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` pass on that toolchain.
- CI (`.github/workflows/ci.yml`) runs formatting, Clippy, tests, and a release build on Ubuntu, macOS, and Windows for every push to `main` and every pull request.
- The adapter was exercised against a real Semgrep (1.182.1) run with a local ruleset, covering severity and confidence mapping, relative paths, and stable rule identifiers across working directories. The fake-analyzer tests are Unix-only, and the Windows-only process termination path and SARIF consumers are not covered by tests.

Do not use this build to claim that a repository has passed a security scan. Scan coverage is partial: one analyzer runs at most, findings do not gate the exit code, and analyzer execution is not isolated.
