from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity

# Common UNIX socket directories to scan
SOCKET_SEARCH_DIRS = [
    "/var/run",
    "/run",
    "/tmp",
]

# Known runtime and management socket names
KNOWN_SOCKETS = {
    "docker.sock": ("Docker", Severity.CRITICAL),
    "dockershim.sock": ("Docker shim", Severity.CRITICAL),
    "containerd.sock": ("containerd", Severity.CRITICAL),
    "crio.sock": ("CRI-O", Severity.CRITICAL),
    "frakti.sock": ("Frakti", Severity.HIGH),
    "kubelet": ("Kubelet", Severity.HIGH),
}

# Ports commonly associated with container runtime or management services
DANGEROUS_PORTS = {
    2375: "Docker (unencrypted)",
    2376: "Docker (TLS)",
    10250: "Kubelet API",
    10255: "Kubelet read-only",
    10256: "Kube-proxy health",
    6443: "Kubernetes API server",
    8080: "Kubernetes API (insecure)",
    4243: "Docker (legacy)",
    2379: "etcd client",
    2380: "etcd peer",
}


def find_unix_sockets(search_dirs: list[str]) -> list[str]:
    """Find UNIX socket files in specified directories."""
    sockets = []
    for d in search_dirs:
        try:
            for root, _dirs, files in os.walk(d):
                for f in files:
                    full_path = os.path.join(root, f)
                    try:
                        st = os.stat(full_path)
                        if stat.S_ISSOCK(st.st_mode):
                            sockets.append(full_path)
                    except OSError:
                        pass
                # Don't recurse too deep
                if root.count(os.sep) - d.count(os.sep) > 3:
                    break
        except OSError:
            pass
    return sockets


@register_check
class UnixSocketDiscoveryCheck(BaseCheck):
    """Discover UNIX sockets and identify known runtime sockets."""

    name = "unix-socket-discovery"
    description = "Discovers UNIX sockets and identifies runtime sockets"
    category = Category.SOCKETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        sockets = find_unix_sockets(SOCKET_SEARCH_DIRS)

        # Check each socket against known patterns
        runtime_sockets = []
        other_sockets = []

        for sock_path in sockets:
            basename = os.path.basename(sock_path)
            matched = False
            for name_pattern, (runtime_name, severity) in KNOWN_SOCKETS.items():
                if name_pattern in basename:
                    runtime_sockets.append((sock_path, runtime_name, severity))
                    matched = True
                    break
            if not matched:
                other_sockets.append(sock_path)

        for idx, (sock_path, runtime_name, severity) in enumerate(runtime_sockets, start=1):
            findings.append(Finding(
                id=f"EW-SOCK-001.{idx}",
                title=f"{runtime_name} socket found: {sock_path}",
                severity=severity,
                confidence=Confidence.HIGH,
                category=Category.SOCKETS,
                evidence=f"Runtime socket: {sock_path}",
                why_it_matters=(
                    f"Access to the {runtime_name} socket may allow controlling "
                    "the container runtime and escaping the container."
                ),
                remediation=f"Remove the {runtime_name} socket mount from the container.",
                references=[],
            ))

        if other_sockets:
            findings.append(Finding(
                id="EW-SOCK-002",
                title=f"Other UNIX sockets found ({len(other_sockets)})",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                category=Category.SOCKETS,
                evidence=f"Sockets: {', '.join(other_sockets[:10])}",
                why_it_matters="Unknown sockets may expose management interfaces.",
                remediation="Audit UNIX sockets accessible from the container.",
                references=[],
            ))

        return findings


@register_check
class DangerousPortsCheck(BaseCheck):
    """Check for localhost-exposed management ports."""

    name = "dangerous-ports"
    description = "Checks for dangerous localhost-exposed ports"
    category = Category.SOCKETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        open_ports = []
        for port, desc in DANGEROUS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()
                if result == 0:
                    open_ports.append((port, desc))
            except OSError:
                pass

        for port, desc in open_ports:
            severity = Severity.HIGH if port in (2375, 10250, 8080, 4243, 2379) else Severity.MEDIUM
            findings.append(Finding(
                id="EW-SOCK-003",
                title=f"Management port open: {port} ({desc})",
                severity=severity,
                confidence=Confidence.HIGH,
                category=Category.SOCKETS,
                evidence=f"Port {port} ({desc}) is listening on localhost",
                why_it_matters=(
                    f"Port {port} is associated with {desc}. Access to this service "
                    "may enable container escape or cluster compromise."
                ),
                remediation=(
                    f"Restrict access to port {port} with network policies. "
                    "Use authentication and TLS where supported."
                ),
                references=[],
            ))

        return findings
