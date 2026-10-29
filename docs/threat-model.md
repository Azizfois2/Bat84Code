# Threat model

## Assets

Repository source and history, credentials reachable to the process, build artifacts, findings, and user trust.

## Adversaries

Malicious repositories, compromised dependencies, crafted paths and analyzer output, malicious build scripts, prompt injection, excessive privileges, and supply-chain compromise.

## Trust assumptions and limits

The host kernel, analyzers on `PATH`, and the release process are not already compromised. BAT84CODE does not defend against a hostile host administrator, a compromised kernel, or a malicious analyzer binary. Repository content and tool output are untrusted data and cannot alter policy.

## Initial implementation controls

- `scan` canonicalizes the requested root and writes no repository files.
- When local rules are configured (explicitly or through the bundled `policies/semgrep` directory), `scan` runs Semgrep with argv (no shell), `--metrics=off`, and `--disable-version-check`, bounded by `scan.timeout_seconds` and `scan.max_output_mb`. Unix runs get a separate process group that is killed on timeout; Windows terminates only the direct process.
- Analyzer output is untrusted: it is parsed with a depth-limited JSON parser, required fields are validated, and paths outside the scan root or containing traversal are rejected. Any such result makes the scan `not_verified` instead of being reported.
- `diff` invokes Git with a fixed executable and separate arguments; it does not interpolate through a shell.
- Analyzer availability is not treated as a successful security check. Only Semgrep can run, so completed scans report `partial` and exit 4; missing required tools exit 3.
- `doctor` invokes only optional tools' `--version` command with argv (no shell), a 10-second deadline, and a 1 KiB retained-output cap.
- BAT84CODE makes no network calls, telemetry, model calls, build execution, or remediation. Semgrep is asked not to send metrics or check for updates, but analyzer behavior itself is not sandboxed.

## Required future controls

Every subprocess needs a timeout, bounded output and process-group cleanup. Analyzers and any high-risk build/test execution must run in a fail-closed Linux sandbox with network denied. Path containment, symlink handling, secret redaction, cancellation, and sandbox behavior require automated security coverage before those capabilities are enabled.
