# Current limitations

This repository is the M1 CLI scaffold only. The following V1 requirements are not yet implemented:

- Full TOML 1.0 parsing (the current dependency-free parser accepts only the simple scalar subset used by `policies/default.toml`) and complete configuration/environment/CLI precedence for every setting.
- Bounded subprocess runner, cancellation, resource caps, and analyzer adapters.
- Platform-specific process cleanup: Unix probes run in a fresh process group and that group is killed on timeout. Windows currently kills only the direct probe process. This probe runner is not used for repository analysis.
- The portable CLI has not been compiled on Linux, macOS, or Windows in this environment because the Rust toolchain is unavailable. Strong process sandboxing is not implemented on any platform.
- SAST, dependency, secret, container, or native-code checks.
- Finding normalization/deduplication, evidence digests, JSON report file writing, and SARIF.
- Linux namespaces/seccomp/cgroups sandbox and network denial for untrusted builds.
- Patch planning, explicit apply, stale-plan checks, and isolated verification.
- Secret redaction, SBOM, signing, fuzzing, fixture evaluation, and performance benchmarks.
- Automated acceptance coverage for the SEC-01 through SEC-12 requirements.

Do not use this build to claim that a repository has passed a security scan. The scan command intentionally reports verification incomplete until analyzer execution and result validation are available.

