from __future__ import annotations

import os
import re

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.checks.namespaces import read_ns_inode
from escapewatch.models import Category, Confidence, Finding, Severity

_VERSION_RE = re.compile(rb"(\d+\.\d+\.\d+(?:-rc\.\d+)?)")
_RUNC_RE = re.compile(rb"runc[\s-]?version[\s\":]+(\d+\.\d+\.\d+(?:-rc\.\d+)?)", re.IGNORECASE)
_GENERIC_VER_RE = re.compile(
    rb"version[\s\":=]+(\d+\.\d+\.\d+(?:-rc\.\d+)?)", re.IGNORECASE
)


def _scan_binary_for_version(path: str, max_bytes: int = 8192) -> str | None:
    """Scan the start of a binary for a SemVer-like version string."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return None
    for regex in (_RUNC_RE, _GENERIC_VER_RE, _VERSION_RE):
        m = regex.search(data)
        if m:
            try:
                return m.group(1).decode("ascii", "replace")
            except (UnicodeDecodeError, AttributeError):
                continue
    return None


def _read_runtime_version(binary_names: list[str]) -> tuple[str | None, str | None]:
    """Find a runtime binary version by inspecting /proc/<pid>/exe symlinks.

    Returns (version, binary_path) — either may be None.
    """
    binary_path: str | None = None
    try:
        entries = os.listdir("/proc")
    except OSError:
        return (None, None)

    for entry in entries:
        if not entry.isdigit():
            continue
        exe_path = f"/proc/{entry}/exe"
        try:
            target = os.readlink(exe_path)
        except OSError:
            continue
        target_lower = target.lower()
        if not any(name in target_lower for name in binary_names):
            continue
        binary_path = target
        # Try cmdline arg-based scan first
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
            for regex in (_RUNC_RE, _GENERIC_VER_RE, _VERSION_RE):
                m = regex.search(cmdline.encode("utf-8"))
                if m:
                    return (m.group(1).decode("ascii", "replace"), binary_path)
        except OSError:
            pass
        # Read the binary itself
        try:
            version = _scan_binary_for_version(exe_path)
        except OSError:
            version = None
        if version:
            return (version, binary_path)

    # Fallback: look at common install paths
    common_paths = [
        "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/usr/libexec", "/sbin", "/bin",
    ]
    for d in common_paths:
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        for f in entries:
            f_lower = f.lower()
            if f_lower in binary_names:
                full = os.path.join(d, f)
                binary_path = full
                ver = _scan_binary_for_version(full)
                if ver:
                    return (ver, full)

    return (None, binary_path)


def _parse_semver(version: str) -> tuple[int, int, int, int] | None:
    """Parse a SemVer (with optional -rc.N) into (maj, min, patch, rc).

    rc=0 means stable release; rc=N (1..) means rc.N (sorts before stable).
    Returns None on parse failure.
    """
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version.strip())
    if not m:
        return None
    try:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3))
        rc = int(m.group(4)) if m.group(4) else 0
    except ValueError:
        return None
    return (major, minor, patch, rc)


def _ver_lt(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    """Strict less-than for parsed semver tuples. rc < stable for same M.m.p."""
    am, an, ap, arc = a
    bm, bn, bp, brc = b
    if (am, an, ap) != (bm, bn, bp):
        return (am, an, ap) < (bm, bn, bp)
    # same triplet: rc=0 (stable) is greater than any rc>0
    a_key = (1, 0) if arc == 0 else (0, arc)
    b_key = (1, 0) if brc == 0 else (0, brc)
    return a_key < b_key


def _ver_in_range(version: tuple[int, int, int, int],
                  min_inclusive: tuple[int, int, int, int],
                  max_exclusive: tuple[int, int, int, int]) -> bool:
    """version >= min_inclusive AND version < max_exclusive."""
    return (not _ver_lt(version, min_inclusive)) and _ver_lt(version, max_exclusive)


@register_check
class RuncVersionCVE2024Check(BaseCheck):
    """runc < 1.1.12 — CVE-2024-21626 (working-directory breakout)."""

    name = "runc-cve-2024-21626"
    description = "Checks for runc < 1.1.12 (CVE-2024-21626)"
    category = Category.RUNTIME

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version, binary_path = _read_runtime_version(["runc"])
        if not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None

        if parsed is not None:
            vulnerable = _ver_lt(parsed, (1, 1, 12, 0))
            if not vulnerable:
                return findings
            findings.append(Finding(
                id="EW-RT-001",
                title=f"runc {version} vulnerable to CVE-2024-21626",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.RUNTIME,
                evidence=(
                    f"runc version {version} — vulnerable to CVE-2024-21626 "
                    "(fixed in 1.1.12)"
                ),
                why_it_matters=(
                    "CVE-2024-21626 (CVSS 8.6) — runc leaks a file descriptor "
                    "referencing the host cgroup filesystem (/proc/self/fd/7 → "
                    "/sys/fs/cgroup on the host). Setting WORKDIR to this fd path "
                    "in a Dockerfile, or using `docker exec -w /proc/self/fd/7`, "
                    "causes the container process working directory to point "
                    "directly at the host filesystem, bypassing the container "
                    "chroot. An attacker can then overwrite host binaries such "
                    "as /usr/bin/bash to achieve persistent root code execution "
                    "on the host node. Exploitation requires only the ability "
                    "to run a container with a custom image or exec a command "
                    "with a custom working directory — no special privileges "
                    "are needed beyond container execution rights."
                ),
                remediation=(
                    "Upgrade runc to >= 1.1.12. For Docker: upgrade to >= "
                    "25.0.2 or 24.0.9. For containerd standalone: upgrade to "
                    ">= 1.6.28 or >= 1.7.13. For Kubernetes managed clusters: "
                    "update the node's container runtime package and "
                    "drain/restart nodes one at a time."
                ),
                references=[
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv",
                    "https://labs.withsecure.com/publications/runc-working-directory-breakout--cve-2024-21626",
                    "https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout/",
                ],
            ))
        elif binary_path:
            findings.append(Finding(
                id="EW-RT-001",
                title="runc detected but version unreadable (assume vulnerable)",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category=Category.RUNTIME,
                evidence=(
                    f"runc binary detected at {binary_path} but version could "
                    "not be read (assume vulnerable to CVE-2024-21626)"
                ),
                why_it_matters=(
                    "runc was detected on this host but its version could not "
                    "be determined. CVE-2024-21626 is exploitable on all runc "
                    "versions before 1.1.12. Verify the runtime version manually."
                ),
                remediation=(
                    "Determine the runc version with `runc --version` and "
                    "upgrade to >= 1.1.12 if needed."
                ),
                references=[
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv",
                ],
            ))

        return findings


@register_check
class RuncVersion2025Check(BaseCheck):
    """runc 2025 trinity — CVE-2025-31133 / 52565 / 52881."""

    name = "runc-cve-2025-trinity"
    description = "Checks for runc vulnerable to CVE-2025-31133 / 52565 / 52881"
    category = Category.RUNTIME

    VULN_RANGES = [
        ((1, 2, 0, 0), (1, 2, 8, 0)),
        ((1, 3, 0, 0), (1, 3, 3, 0)),
        ((1, 4, 0, 0), (1, 4, 0, 3)),  # 1.4.0-rc.0 .. 1.4.0-rc.3 exclusive
    ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version, binary_path = _read_runtime_version(["runc"])
        if not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None

        if parsed is None:
            if binary_path:
                findings.append(Finding(
                    id="EW-RT-002",
                    title="runc detected but version unreadable (cannot rule out 2025 trinity)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    category=Category.RUNTIME,
                    evidence=(
                        f"runc binary at {binary_path} — version could not be parsed."
                    ),
                    why_it_matters=(
                        "CVE-2025-31133, CVE-2025-52565, and CVE-2025-52881 affect "
                        "runc 1.2.0–1.2.7, 1.3.0–1.3.2, and 1.4.0-rc.0–rc.2. Verify "
                        "the runc version manually."
                    ),
                    remediation="Upgrade runc to 1.2.8+, 1.3.3+, or 1.4.0-rc.3+.",
                    references=[
                        "https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm",
                    ],
                ))
            return findings

        vulnerable = any(
            _ver_in_range(parsed, lo, hi) for lo, hi in self.VULN_RANGES
        )
        if not vulnerable:
            return findings

        findings.append(Finding(
            id="EW-RT-002",
            title=(
                f"runc {version} vulnerable to CVE-2025-31133 / 52565 / 52881"
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.RUNTIME,
            evidence=(
                f"runc {version} — vulnerable to CVE-2025-31133 (maskedPaths "
                "/dev/null race), CVE-2025-52565 (/dev/console mount race), "
                "CVE-2025-52881 (procfs write redirect). Fixed in runc 1.2.8 / "
                "1.3.3 / 1.4.0-rc.3."
            ),
            why_it_matters=(
                "Three race-condition vulnerabilities disclosed November 2025 in "
                "runc's mount handling. CVE-2025-31133: replacing /dev/null with "
                "a symlink tricks runc into bind-mounting an attacker-controlled "
                "path read-write, enabling writes to /proc/sys/kernel/core_pattern "
                "and subsequent host shell execution. CVE-2025-52565: a race "
                "during /dev/pts mount setup grants write access to protected "
                "procfs entries, bypassing maskedPaths and readonlyPaths. "
                "CVE-2025-52881: a general procfs write redirect gadget allows "
                "misdirecting writes to arbitrary /proc files via symlinks in a "
                "shared tmpfs. All three require the ability to start containers "
                "with custom mount configurations (e.g. a malicious image or "
                "Dockerfile) but need no special runtime privileges."
            ),
            remediation=(
                "Upgrade runc to 1.2.8+, 1.3.3+, or 1.4.0-rc.3+. Use `runc "
                "--version` or `docker version` on each node to confirm. In "
                "managed K8s environments (EKS, GKE, AKS) check the managed "
                "node group runtime version release notes."
            ),
            references=[
                "https://quor.dev/en/blog/runc-cve2025",
                "https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm",
                "https://fortiguard.fortinet.com/threat-signal-report/6248",
            ],
        ))

        return findings


@register_check
class ContainerdAbstractSocketCheck(BaseCheck):
    """containerd 1.3.0–1.3.8 / 1.4.0–1.4.2 — CVE-2020-15257."""

    name = "containerd-cve-2020-15257"
    description = "Checks for containerd vulnerable to CVE-2020-15257"
    category = Category.RUNTIME

    VULN_RANGES = [
        ((1, 3, 0, 0), (1, 3, 9, 0)),
        ((1, 4, 0, 0), (1, 4, 3, 0)),
    ]

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version, binary_path = _read_runtime_version(["containerd"])
        if not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None
        vulnerable_version = False
        if parsed is not None:
            vulnerable_version = any(
                _ver_in_range(parsed, lo, hi) for lo, hi in self.VULN_RANGES
            )

        # Detect host net ns sharing for severity escalation
        net_ns_1 = read_ns_inode(1, "net")
        net_ns_2 = read_ns_inode(2, "net")
        host_net = bool(net_ns_1 and net_ns_2 and net_ns_1 == net_ns_2)

        if not vulnerable_version and parsed is not None:
            return findings

        if vulnerable_version:
            severity = Severity.CRITICAL if host_net else Severity.HIGH
            confidence = Confidence.HIGH
            evidence = (
                f"containerd {version} — vulnerable to CVE-2020-15257 (fixed in "
                "1.3.9 / 1.4.3)."
                + (" containerd-shim API abstract socket accessible from host "
                   "network namespace." if host_net else "")
            )
            findings.append(Finding(
                id="EW-RT-003",
                title=f"containerd {version} vulnerable to CVE-2020-15257",
                severity=severity,
                confidence=confidence,
                category=Category.RUNTIME,
                evidence=evidence,
                why_it_matters=(
                    "CVE-2020-15257: the containerd-shim API is exposed over an "
                    "abstract Unix domain socket in the root network namespace. "
                    "Abstract sockets are not filesystem-visible but are "
                    "accessible to any process sharing the same network "
                    "namespace. A container running with hostNetwork: true (or "
                    "--net=host) and UID 0 can connect to the shim API socket "
                    "at @/containerd-shim/<pid> and instruct it to spawn "
                    "arbitrary containers with any security configuration, "
                    "including privileged containers with host mounts, achieving "
                    "full host compromise."
                ),
                remediation=(
                    "Upgrade containerd to >= 1.3.9 or >= 1.4.3. These versions "
                    "move the shim socket to a path inaccessible to containers. "
                    "Additionally, never run containers with hostNetwork: true "
                    "unless strictly required."
                ),
                references=[
                    "https://www.sentinelone.com/vulnerability-database/cve-2020-15257/",
                    "https://www.nccgroup.com/research/technical-advisory-containerd-containerd-shim-api-exposed-to-host-network-containers-cve-2020-15257/",
                ],
            ))
        elif binary_path:
            findings.append(Finding(
                id="EW-RT-003",
                title="containerd detected but version unreadable",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                category=Category.RUNTIME,
                evidence=(
                    f"containerd binary at {binary_path} — version could not be "
                    "determined. Cannot rule out CVE-2020-15257."
                ),
                why_it_matters=(
                    "containerd versions 1.3.0–1.3.8 and 1.4.0–1.4.2 are "
                    "vulnerable to CVE-2020-15257 abstract socket abuse."
                ),
                remediation=(
                    "Verify containerd version with `containerd --version` and "
                    "upgrade to >= 1.3.9 or >= 1.4.3 if needed."
                ),
                references=[
                    "https://www.sentinelone.com/vulnerability-database/cve-2020-15257/",
                ],
            ))

        return findings


@register_check
class CRIOVersionCheck(BaseCheck):
    """CRI-O — CVE-2022-0811 (cr8escape)."""

    name = "crio-cve-2022-0811"
    description = "Checks for CRI-O vulnerable to CVE-2022-0811 (cr8escape)"
    category = Category.RUNTIME

    VULN_RANGES = [
        ((1, 19, 0, 0), (1, 19, 6, 0)),
        ((1, 20, 0, 0), (1, 20, 7, 0)),
        ((1, 21, 0, 0), (1, 21, 6, 0)),
        ((1, 22, 0, 0), (1, 22, 3, 0)),
        ((1, 23, 0, 0), (1, 23, 2, 0)),
    ]
    PINNS_PATHS = ("/usr/libexec/crio/pinns", "/usr/bin/pinns")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        crio_present = self._path_exists("/run/crio/crio.sock") or self._path_exists(
            "/var/run/crio/crio.sock"
        )
        version, binary_path = _read_runtime_version(["crio", "cri-o"])
        if version or binary_path:
            crio_present = True

        if not crio_present:
            return findings

        pinns_path = next((p for p in self.PINNS_PATHS if self._path_exists(p)), None)
        parsed = _parse_semver(version) if version else None

        if parsed is not None:
            vulnerable = any(
                _ver_in_range(parsed, lo, hi) for lo, hi in self.VULN_RANGES
            )
            if not vulnerable:
                return findings
            findings.append(Finding(
                id="EW-RT-004",
                title=f"CRI-O {version} vulnerable to CVE-2022-0811 (cr8escape)",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.RUNTIME,
                evidence=(
                    f"CRI-O version {version} — vulnerable to CVE-2022-0811 "
                    f"(cr8escape). pinns binary found at "
                    f"{pinns_path or 'unknown path'}. Fixed in CRI-O 1.19.6 / "
                    "1.20.7 / 1.21.6 / 1.22.3 / 1.23.2."
                ),
                why_it_matters=(
                    "CVE-2022-0811 (CVSS 8.8, nicknamed cr8escape): CRI-O's pinns "
                    "utility sets kernel parameters specified in pod sysctl "
                    "annotations without sanitizing special characters. A "
                    "Kubernetes user with pod deployment rights can inject "
                    "arbitrary sysctl values (including kernel.core_pattern) by "
                    "including '+' or '=' characters in the sysctl value string. "
                    "Setting kernel.core_pattern to a SUID helper script causes "
                    "any subsequent core dump in the namespace to execute the "
                    "attacker's binary as root on the host. No special "
                    "capabilities are required — only the ability to create "
                    "pods in a CRI-O cluster."
                ),
                remediation=(
                    "Upgrade CRI-O to a patched version (see references). "
                    "Enforce PodSecurity `restricted` admission policy to block "
                    "pods with unsafe sysctl annotations. Audit pod specs for "
                    "sysctl annotations containing special characters."
                ),
                references=[
                    "https://www.sentinelone.com/vulnerability-database/cve-2022-0811/",
                    "https://www.sysdig.com/blog/cve-2022-0811-cri-o",
                ],
            ))
        else:
            findings.append(Finding(
                id="EW-RT-004",
                title="CRI-O present but version unreadable",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.RUNTIME,
                evidence=(
                    f"CRI-O detected (binary={binary_path or 'socket only'}, "
                    f"pinns={pinns_path or 'absent'}) but version could not be "
                    "parsed. Cannot rule out CVE-2022-0811."
                ),
                why_it_matters=(
                    "CRI-O versions 1.19–1.23 (before patch) are vulnerable to "
                    "CVE-2022-0811 cr8escape kernel.core_pattern injection."
                ),
                remediation=(
                    "Verify the CRI-O version with `crio --version` and patch "
                    "if needed."
                ),
                references=[
                    "https://www.sentinelone.com/vulnerability-database/cve-2022-0811/",
                ],
            ))

        return findings


@register_check
class BuildKitVersionCheck(BaseCheck):
    """BuildKit < 0.12.5 — Leaky Vessels (CVE-2024-23651/52/53)."""

    name = "buildkit-leaky-vessels"
    description = "Checks for BuildKit < 0.12.5 (Leaky Vessels)"
    category = Category.RUNTIME

    SOCKET_PATHS = ("/run/buildkit/buildkitd.sock", "/var/run/buildkit/buildkitd.sock")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        socket_present = any(self._path_exists(p) for p in self.SOCKET_PATHS)
        version, binary_path = _read_runtime_version(["buildkitd", "buildctl"])
        if not socket_present and not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None

        if parsed is not None:
            vulnerable = _ver_lt(parsed, (0, 12, 5, 0))
            if not vulnerable:
                return findings
            findings.append(Finding(
                id="EW-RT-005",
                title=f"BuildKit {version} vulnerable to Leaky Vessels",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.RUNTIME,
                evidence=(
                    f"BuildKit version {version} — vulnerable to CVE-2024-23651 "
                    "(TOCTOU mount cache), CVE-2024-23652 (teardown symlink "
                    "delete), CVE-2024-23653 (auth bypass for privileged "
                    "containers). Fixed in BuildKit 0.12.5."
                ),
                why_it_matters=(
                    "Three vulnerabilities in BuildKit's build pipeline "
                    "(collectively Leaky Vessels): CVE-2024-23651: a TOCTOU race "
                    "on mount cache source allows a malicious Dockerfile to "
                    "swap the mount source between validation and mount time, "
                    "gaining read/write access to host filesystem paths. "
                    "CVE-2024-23652: during container teardown, swapping a "
                    "directory with a symlink causes BuildKit to follow the "
                    "symlink and delete arbitrary host files. CVE-2024-23653: "
                    "missing authorization check allows running build "
                    "containers with `security.insecure` privileges (effectively "
                    "--privileged) without the required explicit entitlement. "
                    "All three are exploitable by a malicious base image or "
                    "Dockerfile ONBUILD trigger."
                ),
                remediation=(
                    "Upgrade BuildKit to >= 0.12.5. For Docker Desktop: upgrade "
                    "to >= 4.28.0. For standalone buildkitd: update the package "
                    "and restart the daemon. Avoid using `--allow "
                    "security.insecure` in build pipelines."
                ),
                references=[
                    "https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities",
                    "https://labs.snyk.io/resources/cve-2024-23652-buildkit-build-time-container-teardown-arbitrary-delete/",
                    "https://www.sentinelone.com/vulnerability-database/cve-2024-23653/",
                ],
            ))
        else:
            findings.append(Finding(
                id="EW-RT-005",
                title="BuildKit detected but version unreadable",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.RUNTIME,
                evidence=(
                    f"BuildKit detected (socket={socket_present}, "
                    f"binary={binary_path or 'unknown'}). Version could not be "
                    "parsed; cannot rule out Leaky Vessels."
                ),
                why_it_matters=(
                    "BuildKit < 0.12.5 is vulnerable to three Leaky Vessels CVEs."
                ),
                remediation="Upgrade BuildKit to >= 0.12.5.",
                references=[
                    "https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities",
                ],
            ))

        return findings


@register_check
class RuncCVE20195736Check(BaseCheck):
    """runc < 1.0.0-rc7 — CVE-2019-5736 (/proc/self/exe overwrite breakout)."""

    name = "runc-cve-2019-5736"
    description = "Checks for runc < 1.0.0-rc7 (CVE-2019-5736)"
    category = Category.RUNTIME

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version, binary_path = _read_runtime_version(["runc"])
        if not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None

        if parsed is not None:
            # Fixed in runc 1.0.0-rc7 (released 2019-02-12).
            # In our semver tuple: rc=7 → (1, 0, 0, 7); stable → (1, 0, 0, 0).
            # Stable 1.0.0 was released long after rc7, so _ver_lt(stable, rc7)
            # is False — only genuine pre-rc7 versions are flagged.
            vulnerable = _ver_lt(parsed, (1, 0, 0, 7))
            if not vulnerable:
                return findings
            findings.append(Finding(
                id="EW-RT-006",
                title=f"runc {version} vulnerable to CVE-2019-5736 (/proc/self/exe overwrite)",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.RUNTIME,
                evidence=(
                    f"runc version {version} — vulnerable to CVE-2019-5736 "
                    "(fixed in runc 1.0.0-rc7, Docker 18.09.2)"
                ),
                why_it_matters=(
                    "CVE-2019-5736 (CVSS 8.6) allows a malicious container to "
                    "overwrite the runc binary on the host, achieving arbitrary "
                    "code execution as root on the host node. The attack exploits "
                    "a race between container process startup and runc's access to "
                    "/proc/self/exe (which points to the runc binary itself while "
                    "it executes inside the container namespace). A container "
                    "process can repeatedly open /proc/self/exe for writing and "
                    "win the race to replace the runc binary with a payload before "
                    "runc exits. The next `docker exec` or container start on any "
                    "container on the host will then execute the attacker's binary "
                    "as root on the host. This vulnerability requires only the "
                    "ability to run a container with a custom entrypoint — no "
                    "special runtime privileges are needed."
                ),
                remediation=(
                    "Upgrade runc to >= 1.0.0-rc7. For Docker: upgrade to "
                    ">= 18.09.2. This vulnerability is historical but any runc "
                    "binary predating rc7 on a production host is critically "
                    "exposed and must be replaced immediately."
                ),
                references=[
                    "https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/",
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
                ],
            ))
        elif binary_path:
            findings.append(Finding(
                id="EW-RT-006",
                title="runc detected but version unreadable (cannot rule out CVE-2019-5736)",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category=Category.RUNTIME,
                evidence=(
                    f"runc binary at {binary_path} — version could not be read. "
                    "Cannot rule out CVE-2019-5736 (/proc/self/exe overwrite)."
                ),
                why_it_matters=(
                    "runc versions before 1.0.0-rc7 are vulnerable to "
                    "CVE-2019-5736, which allows container-to-host binary "
                    "overwrite. Verify the runc version manually."
                ),
                remediation=(
                    "Run `runc --version` to confirm the version and upgrade "
                    "to >= 1.0.0-rc7 / Docker >= 18.09.2 if needed."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
                ],
            ))

        return findings


@register_check
class RuncCVE202130465Check(BaseCheck):
    """runc < 1.0.1 — CVE-2021-30465 (symlink-exchange mount attack)."""

    name = "runc-cve-2021-30465"
    description = "Checks for runc < 1.0.1 (CVE-2021-30465)"
    category = Category.RUNTIME

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version, binary_path = _read_runtime_version(["runc"])
        if not binary_path and not version:
            return findings

        parsed = _parse_semver(version) if version else None

        if parsed is not None:
            # Fixed in runc 1.0.1 (released 2021-05-05).
            # Stable 1.0.0 (rc=0 → (1,0,0,0)) is < (1,0,1,0) → vulnerable.
            # All rc releases are also < (1,0,1,0).
            vulnerable = _ver_lt(parsed, (1, 0, 1, 0))
            if not vulnerable:
                return findings
            findings.append(Finding(
                id="EW-RT-007",
                title=f"runc {version} vulnerable to CVE-2021-30465 (symlink-exchange mount)",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.RUNTIME,
                evidence=(
                    f"runc version {version} — vulnerable to CVE-2021-30465 "
                    "(fixed in runc 1.0.1)"
                ),
                why_it_matters=(
                    "CVE-2021-30465 (CVSS 8.2) exploits a TOCTOU race in runc's "
                    "volume mount handling. When runc binds a host directory into "
                    "a container, it resolves the host path at validation time and "
                    "uses it at mount time — with a window between the two. A "
                    "malicious container image can repeatedly swap a directory with "
                    "a symlink pointing to a sensitive host path (e.g. /etc, "
                    "/var/lib/kubelet) and win the race, causing runc to "
                    "bind-mount the symlink target instead of the intended "
                    "directory. The container then gains read/write access to "
                    "arbitrary host directories. This can be used to read host "
                    "credentials, overwrite host binaries, or plant backdoors. "
                    "Exploitation requires only the ability to start a container "
                    "with a bind-mount — no special capabilities are needed."
                ),
                remediation=(
                    "Upgrade runc to >= 1.0.1. For Docker: upgrade to >= 20.10.6. "
                    "Audit all containers using bind mounts of directories that "
                    "could be swapped with symlinks before the upgrade."
                ),
                references=[
                    "https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r",
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-30465",
                ],
            ))
        elif binary_path:
            findings.append(Finding(
                id="EW-RT-007",
                title="runc detected but version unreadable (cannot rule out CVE-2021-30465)",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category=Category.RUNTIME,
                evidence=(
                    f"runc binary at {binary_path} — version could not be read. "
                    "Cannot rule out CVE-2021-30465 (symlink-exchange mount attack)."
                ),
                why_it_matters=(
                    "runc < 1.0.1 is vulnerable to CVE-2021-30465, a TOCTOU race "
                    "in bind-mount handling that allows reading/writing arbitrary "
                    "host directories. Verify the runc version manually."
                ),
                remediation=(
                    "Run `runc --version` to confirm the version and upgrade "
                    "to >= 1.0.1 / Docker >= 20.10.6 if needed."
                ),
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-30465",
                ],
            ))

        return findings
