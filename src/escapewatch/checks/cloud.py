from __future__ import annotations

import os
import re
import socket
from pathlib import Path

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity

# Keywords that suggest sensitive content in environment variables
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "aws_secret", "auth", "credential",
    "database_url", "db_pass", "connection_string", "jwt",
    "encryption_key", "signing_key", "client_secret",
]

# Cloud metadata endpoint IPs
METADATA_ENDPOINTS = {
    "169.254.169.254": "AWS/GCP/Azure metadata service",
    "100.100.100.200": "Alibaba Cloud metadata service",
    "169.254.170.2": "AWS ECS task metadata",
}


def redact_value(value: str) -> str:
    """Redact a sensitive value, showing only first/last 2 chars."""
    if len(value) <= 6:
        return "***REDACTED***"
    return f"{value[:2]}***REDACTED***{value[-2:]}"


def is_sensitive_key(key: str) -> bool:
    """Check if an environment variable key suggests sensitive content."""
    key_lower = key.lower()
    return any(kw in key_lower for kw in SENSITIVE_KEYWORDS)


@register_check
class CloudMetadataCheck(BaseCheck):
    """Check reachability of cloud metadata endpoints."""

    name = "cloud-metadata"
    description = "Checks cloud metadata endpoint reachability"
    category = Category.CLOUD

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for ip, desc in METADATA_ENDPOINTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, 80))
                sock.close()

                if result == 0:
                    findings.append(Finding(
                        id="EW-CLOUD-001",
                        title=f"Cloud metadata endpoint reachable: {ip}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.CLOUD,
                        evidence=f"{desc} at {ip}:80 is reachable",
                        why_it_matters=(
                            "Cloud metadata endpoints can expose instance credentials, "
                            "IAM roles, and sensitive configuration data."
                        ),
                        remediation=(
                            "Block metadata endpoint access with network policies or "
                            "use IMDSv2 (AWS) to require session tokens."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                        ],
                    ))
            except OSError:
                pass

        return findings


@register_check
class EnvironmentSecretsCheck(BaseCheck):
    """Check for sensitive values in environment variables."""

    name = "env-secrets"
    description = "Checks for secrets in environment variables"
    category = Category.SECRETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        sensitive_vars = []
        for key, value in os.environ.items():
            if is_sensitive_key(key) and value:
                sensitive_vars.append(f"{key}={redact_value(value)}")

        if sensitive_vars:
            # Cap the evidence to avoid excessively long output
            evidence = "; ".join(sensitive_vars[:20])
            if len(sensitive_vars) > 20:
                evidence += f" ... and {len(sensitive_vars) - 20} more"

            findings.append(Finding(
                id="EW-SECRET-001",
                title=f"Sensitive environment variables detected ({len(sensitive_vars)})",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SECRETS,
                evidence=evidence,
                why_it_matters=(
                    "Secrets in environment variables are visible to any process in "
                    "the container and may leak through logs or debug endpoints."
                ),
                remediation=(
                    "Use mounted secrets files or a secrets manager instead of "
                    "environment variables for sensitive data."
                ),
                references=[
                    "https://kubernetes.io/docs/concepts/configuration/secret/",
                ],
            ))

        return findings


@register_check
class MountedSecretsCheck(BaseCheck):
    """Check for mounted secret files."""

    name = "mounted-secrets"
    description = "Checks for mounted secret files"
    category = Category.SECRETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        secret_paths = [
            "/var/run/secrets",
            "/etc/kubernetes/pki",
            "/etc/ssl/private",
            "/root/.ssh",
            "/root/.aws/credentials",
            "/root/.docker/config.json",
            "/root/.kube/config",
        ]

        found = []
        for sp in secret_paths:
            if self._path_exists(sp):
                found.append(sp)

        if found:
            findings.append(Finding(
                id="EW-SECRET-002",
                title=f"Secret files/directories accessible ({len(found)})",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SECRETS,
                evidence=f"Accessible secret paths: {', '.join(found)}",
                why_it_matters=(
                    "Mounted secret files may contain credentials, certificates, "
                    "or tokens that enable lateral movement."
                ),
                remediation=(
                    "Minimize mounted secrets. Use projected volumes with expiration "
                    "where possible."
                ),
                references=[],
            ))

        return findings


@register_check
class ProcessEnvironCheck(BaseCheck):
    """Check accessible process /proc/*/environ for secrets."""

    name = "proc-environ-secrets"
    description = "Checks /proc/*/environ for secrets (redacted)"
    category = Category.SECRETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        exposed_pids: list[str] = []
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit() or entry == "1":
                    continue
                environ_path = f"/proc/{entry}/environ"
                content = self._read_file(environ_path)
                if content:
                    env_pairs = content.split("\x00")
                    for pair in env_pairs:
                        if "=" in pair:
                            key = pair.split("=", 1)[0]
                            if is_sensitive_key(key):
                                exposed_pids.append(entry)
                                break
                # Only check first 20 processes to keep runtime reasonable
                if len(exposed_pids) >= 5:
                    break
        except OSError:
            pass

        if exposed_pids:
            findings.append(Finding(
                id="EW-SECRET-003",
                title="Secrets visible in other process environments",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category=Category.SECRETS,
                evidence=f"PIDs with sensitive env vars: {', '.join(exposed_pids[:10])}",
                why_it_matters=(
                    "Access to other processes' environment variables can leak secrets "
                    "from sidecar containers or init containers."
                ),
                remediation=(
                    "Use hostPID: false and avoid sharing PID namespace. "
                    "Prefer file-based secrets over environment variables."
                ),
                references=[],
            ))

        return findings
