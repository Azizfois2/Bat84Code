# Threat model

## Assets

Repository source and history, credentials reachable to the process, build artifacts, findings, and user trust.

## Adversaries

Malicious repositories, compromised dependencies, crafted paths and analyzer output, malicious build scripts, prompt injection, excessive privileges, and supply-chain compromise.

## Trust assumptions and limits

The host kernel and release process are not already compromised. BAT84CODE does not defend against a hostile host administrator or compromised kernel. Repository content and tool output are untrusted data and cannot alter policy.

## Initial implementation controls

- `scan` canonicalizes the requested root, performs no subprocess execution, and writes no repository files.
- `diff` invokes Git with a fixed executable and separate arguments; it does not interpolate through a shell.
- Analyzer availability is not treated as a successful security check. The current scan exits 4 (`not_verified`).
- `doctor` invokes only optional tools' `--version` command with argv (no shell), a 2-second deadline, and a 1 KiB retained-output cap. Unix probes use a separate process group and terminate the group on timeout; Windows currently terminates only the direct process. This probe is not used for repository scans.
- No network access, telemetry, model calls, build execution, or remediation is implemented.

## Required future controls

Every subprocess needs a timeout, bounded output and process-group cleanup. High-risk build/test execution must use a fail-closed Linux sandbox with network denied. Path containment, symlink handling, secret redaction, cancellation, and sandbox behavior require automated security coverage before those capabilities are enabled.

