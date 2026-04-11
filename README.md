# EscapeWatch

**Defensive container escape risk assessment framework**

EscapeWatch is a security assessment tool that detects container escape paths, dangerous runtime configurations, and hardening gaps in Docker, Kubernetes and containerd environments. It produces reports with actionable remediation guidance.

> **Safety:** EscapeWatch is a purely defensive tool. It performs read-only enumeration and risk scoring — it never attempts breakouts, delivers payloads, or compromises hosts.

## Features

- **Environment Detection** — Automatically identifies Docker containers, Kubernetes pods, containerd workloads, and host systems
- **20+ Security Checks** across 7 categories:
  - Runtime privileges (capabilities, seccomp, AppArmor, SELinux)
  - Filesystem and mounts (runtime sockets, host paths, writable cgroups)
  - Namespace isolation (hostPID, hostNetwork, hostIPC)
  - Kubernetes (service account tokens, API reachability, kubeconfig)
  - Cloud metadata endpoint exposure
  - Secrets in environment variables and process environments
  - Runtime socket and dangerous port discovery
- **Risk Scoring** — Weighted severity/confidence scoring with letter grades (A–F)
- **Multiple Output Formats** — Rich terminal, compact, JSON, SARIF v2.1.0
- **CI/CD Integration** — Non-interactive mode with configurable failure thresholds
- **Plugin Architecture** — Easily add custom checks

## Quick Start

### Run

```bash
# Full terminal report
escapewatch

# JSON output
escapewatch --format json

# SARIF for CI/CD tools
escapewatch --format sarif --output report.sarif

# CI mode — exit 1 if any HIGH or CRITICAL findings
escapewatch --ci --fail-on high

# Compact terminal report
escapewatch --format compact

# Filter to specific categories
escapewatch -c runtime-privileges -c filesystem-mounts
```

### Run Inside a Container

```bash
docker cp $(which escapewatch) mycontainer:/usr/local/bin/
docker exec mycontainer escapewatch --format json
```

## Output Formats

### Terminal (default)

Colored output with severity-coded findings, category breakdowns and remediation guidance.

### JSON

Structured output suitable for programmatic consumption:

```json
{
  "version": "0.1.0",
  "environment": { ... },
  "summary": {
    "total_score": 109.1,
    "grade": "F",
    "finding_count": 6
  },
  "findings": [ ... ]
}
```

### SARIF v2.1.0

Standard static analysis format for integration with GitHub Code Scanning, Azure DevOps, and other CI/CD platforms.

### CI Mode

```bash
escapewatch --ci --fail-on medium --format json --output report.json
```

Exit codes:
- `0` — No findings at or above the threshold
- `1` — Findings at or above the threshold detected

## Check Categories

| Category | ID Prefix | Description |
|---|---|---|
| Runtime Privileges | `EW-PRIV-*` | Capabilities, seccomp, AppArmor, SELinux, root user |
| Filesystem & Mounts | `EW-FS-*` | Docker sockets, host mounts, writable cgroups, devices |
| Namespaces | `EW-NS-*` | hostPID, hostNetwork, hostIPC indicators |
| Kubernetes | `EW-K8S-*` | Service account tokens, API access, kubeconfig |
| Cloud & Metadata | `EW-CLOUD-*` | Cloud metadata endpoint reachability |
| Secrets Exposure | `EW-SECRET-*` | Environment variables, mounted secrets, /proc/environ |
| Runtime Sockets | `EW-SOCK-*` | UNIX sockets, dangerous management ports |

See [docs/checks.md](docs/checks.md) for detailed check descriptions.

## Risk Scoring

Each finding has:
- **Severity** — CRITICAL (40), HIGH (20), MEDIUM (10), LOW (3), INFO (0)
- **Confidence** — HIGH (1.0x), MEDIUM (0.7x), LOW (0.4x)
- **Weighted Score** = severity weight × confidence multiplier

Overall grade:
| Score | Grade |
|---|---|
| 0 | A |
| 1–19 | B |
| 20–49 | C |
| 50–99 | D |
| 100+ | F |
