from __future__ import annotations

import os
import re
from pathlib import Path

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity

# Linux capabilities that are considered dangerous for container escape
DANGEROUS_CAPS = {
    "cap_sys_admin": "Broad admin access — mount, namespace, bpf, and more",
    "cap_sys_ptrace": "Trace/inspect any process — can read secrets from memory",
    "cap_sys_module": "Load kernel modules — direct kernel code execution",
    "cap_sys_rawio": "Raw I/O access — can modify kernel memory via /dev/mem",
    "cap_net_admin": "Full network config — can sniff traffic and modify routing",
    "cap_net_raw": "Raw sockets — can craft arbitrary packets",
    "cap_dac_override": "Bypass file permission checks — read/write any file",
    "cap_dac_read_search": "Bypass file read permissions",
    "cap_fowner": "Bypass permission checks on file owner operations",
    "cap_setuid": "Set arbitrary UIDs — privilege escalation",
    "cap_setgid": "Set arbitrary GIDs — privilege escalation",
    "cap_sys_chroot": "Change root directory — container escape aid",
    "cap_mknod": "Create device special files",
    "cap_sys_boot": "Reboot the system",
    "cap_syslog": "Access kernel logs — information disclosure",
    "cap_bpf": "eBPF programs — kernel-level observation and manipulation",
    "cap_perfmon": "Performance monitoring — kernel information disclosure",
}

# Subset that are especially critical
CRITICAL_CAPS = {
    "cap_sys_admin", "cap_sys_module", "cap_sys_rawio", "cap_sys_ptrace",
    "cap_dac_read_search", "cap_bpf",
}


def _read_cap_last_cap() -> int:
    """Return the kernel's CAP_LAST_CAP, falling back to 40 (Linux 6.3)."""
    try:
        with open("/proc/sys/kernel/cap_last_cap", "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 40


def parse_cap_hex(hex_str: str) -> set[str]:
    """Convert a hex capability bitmask to a set of capability names."""
    cap_names = [
        "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
        "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid",
        "cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
        "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
        "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
        "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
        "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
        "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
        "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
        "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
        "cap_checkpoint_restore",
    ]
    try:
        bitmask = int(hex_str.strip(), 16)
    except ValueError:
        return set()
    result = set()
    for i, name in enumerate(cap_names):
        if bitmask & (1 << i):
            result.add(name)
    return result


@register_check
class PrivilegedContainerCheck(BaseCheck):
    """Detect if the container is running in privileged mode."""

    name = "privileged-container"
    description = "Checks for privileged container indicators"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Read effective capabilities
        status = self._read_file("/proc/1/status")
        if status:
            match = re.search(r"CapEff:\s+([0-9a-fA-F]+)", status)
            if match:
                caps = parse_cap_hex(match.group(1))
                # Full caps = privileged. CAP_LAST_CAP is 40 on kernels
                # ≤ 6.3 (41 bits) but may grow. Check whether *all* known
                # capability bits are set — any value where at least the
                # first 41 bits are on is considered "all capabilities".
                try:
                    eff_val = int(match.group(1).strip(), 16)
                except ValueError:
                    eff_val = 0

                last_cap = _read_cap_last_cap()
                all_cap_bits = (1 << (last_cap + 1)) - 1
                if eff_val & all_cap_bits == all_cap_bits:
                    findings.append(Finding(
                        id="EW-PRIV-001",
                        title="Privileged container detected",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.PRIVILEGES,
                        evidence=f"CapEff={match.group(1).strip()} (all capabilities)",
                        why_it_matters=(
                            "A privileged container has full access to host devices "
                            "and can trivially escape to the host."
                        ),
                        remediation=(
                            "Remove --privileged flag. Grant only the specific "
                            "capabilities needed with --cap-add."
                        ),
                        references=[
                            "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
                        ],
                    ))
                else:
                    # Check for dangerous individual caps
                    dangerous_found = caps & set(DANGEROUS_CAPS.keys())
                    critical_found = dangerous_found & CRITICAL_CAPS
                    if critical_found:
                        findings.append(Finding(
                            id="EW-PRIV-002",
                            title="Critical Linux capabilities granted",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=Category.PRIVILEGES,
                            evidence=f"Critical caps: {', '.join(sorted(critical_found))}",
                            why_it_matters=(
                                "These capabilities can enable container escape or "
                                "host compromise."
                            ),
                            remediation="Drop unnecessary capabilities with --cap-drop ALL --cap-add <needed>.",
                            references=[
                                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                            ],
                        ))
                    non_critical_dangerous = dangerous_found - CRITICAL_CAPS
                    if non_critical_dangerous:
                        findings.append(Finding(
                            id="EW-PRIV-003",
                            title="Dangerous Linux capabilities granted",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=Category.PRIVILEGES,
                            evidence=f"Dangerous caps: {', '.join(sorted(non_critical_dangerous))}",
                            why_it_matters=(
                                "These capabilities expand the container's attack surface "
                                "beyond the default set."
                            ),
                            remediation="Drop unnecessary capabilities with --cap-drop.",
                            references=[
                                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                            ],
                        ))

            capeff_hex = match.group(1).strip()
            if "cap_dac_read_search" in caps:
                findings.append(Finding(
                    id="EW-PRIV-011",
                    title="CAP_DAC_READ_SEARCH — Shocker open_by_handle_at escape vector",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.PRIVILEGES,
                    evidence=f"cap_dac_read_search in CapEff ({capeff_hex})",
                    why_it_matters=(
                        "CAP_DAC_READ_SEARCH bypasses file read-permission and "
                        "directory search-permission checks across mount namespaces. "
                        "Combined with the open_by_handle_at(2) syscall (the Shocker "
                        "technique), an attacker can open any file on the host "
                        "filesystem by raw inode number without traversing the "
                        "container's chroot or mount namespace. This gives a "
                        "full read (and often write) primitive over host files — "
                        "/etc/shadow, /root/.ssh/id_rsa, kubeconfig, cloud credentials "
                        "— without CAP_SYS_ADMIN or any kernel exploit. Shocker was "
                        "the first documented container escape via capabilities alone "
                        "(2014) and remains exploitable on unpatched configurations."
                    ),
                    remediation=(
                        "Drop CAP_DAC_READ_SEARCH with --cap-drop CAP_DAC_READ_SEARCH. "
                        "Block open_by_handle_at via seccomp (it is denied by the "
                        "default Docker seccomp profile). Never grant this capability "
                        "to untrusted workloads."
                    ),
                    references=[
                        "https://tbhaxor.com/container-breakout-part-2/",
                        "https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html",
                    ],
                ))
            if "cap_bpf" in caps:
                findings.append(Finding(
                    id="EW-PRIV-012",
                    title="CAP_BPF — eBPF verifier bug container escape vector",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category=Category.PRIVILEGES,
                    evidence=f"cap_bpf in CapEff ({capeff_hex})",
                    why_it_matters=(
                        "CAP_BPF (introduced in Linux 5.8) grants the ability to load "
                        "eBPF programs without CAP_SYS_ADMIN. The eBPF verifier "
                        "validates programs before execution, but has a history of "
                        "exploitable bugs: pointer arithmetic confusion, register "
                        "type confusion, and speculative execution side-channels have "
                        "all enabled privilege escalation to kernel code execution "
                        "from CAP_BPF alone. Additionally, CAP_BPF permits loading "
                        "socket-filter programs that can intercept host network "
                        "traffic and — via bpf_probe_write_user() in certain helper "
                        "contexts — write to host process memory. As eBPF adoption "
                        "grows across observability and networking stacks, the "
                        "verifier attack surface continues to expand."
                    ),
                    remediation=(
                        "Drop CAP_BPF unless strictly required. Block the bpf() "
                        "syscall via seccomp. Set "
                        "kernel.unprivileged_bpf_disabled=2 on the host. Keep "
                        "the host kernel patched and monitor eBPF verifier CVEs."
                    ),
                    references=[
                        "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled",
                        "https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story",
                    ],
                ))

            amb_match = re.search(r"CapAmb:\s+([0-9a-fA-F]+)", status)
            if amb_match:
                amb_hex = amb_match.group(1).strip()
                try:
                    amb_val = int(amb_hex, 16)
                except ValueError:
                    amb_val = 0
                if amb_val != 0:
                    amb_caps = parse_cap_hex(amb_hex)
                    dangerous_amb = amb_caps & set(DANGEROUS_CAPS.keys())
                    if dangerous_amb:
                        findings.append(Finding(
                            id="EW-PRIV-010",
                            title="Dangerous ambient capabilities set",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category=Category.PRIVILEGES,
                            evidence=(
                                f"CapAmb={amb_hex} — dangerous: "
                                f"{', '.join(sorted(dangerous_amb))}"
                            ),
                            why_it_matters=(
                                "Ambient capabilities are automatically inherited by child "
                                "processes across execve() even for non-privileged "
                                "executables (no SUID/file caps required). Any process "
                                "spawned in this container inherits these capabilities, "
                                "expanding the attack surface to all child processes."
                            ),
                            remediation=(
                                "Remove ambient capabilities with `capsh --drop=cap_xxx` or "
                                "ensure the container spec does not set ambientCapabilities. "
                                "Use --cap-drop ALL in Docker."
                            ),
                            references=[
                                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                            ],
                        ))
                    else:
                        findings.append(Finding(
                            id="EW-PRIV-010",
                            title="Non-zero ambient capabilities (non-dangerous set)",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category=Category.PRIVILEGES,
                            evidence=(
                                f"CapAmb={amb_hex} — caps: "
                                f"{', '.join(sorted(amb_caps))}"
                            ),
                            why_it_matters=(
                                "Non-dangerous ambient caps still expand child process "
                                "privilege surface."
                            ),
                            remediation=(
                                "Review whether ambient capabilities are required. Drop if "
                                "not needed."
                            ),
                            references=[],
                        ))

        return findings


@register_check
class SeccompCheck(BaseCheck):
    """Check if seccomp is disabled or unconfined."""

    name = "seccomp-profile"
    description = "Checks seccomp filtering status"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        status = self._read_file("/proc/1/status")
        if status:
            match = re.search(r"Seccomp:\s+(\d)", status)
            if match:
                mode = int(match.group(1))
                if mode == 0:
                    findings.append(Finding(
                        id="EW-PRIV-004",
                        title="Seccomp disabled",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.PRIVILEGES,
                        evidence="Seccomp mode: 0 (disabled)",
                        why_it_matters=(
                            "Without seccomp filtering, the container can invoke any "
                            "syscall, greatly increasing the kernel attack surface."
                        ),
                        remediation=(
                            "Use the default Docker seccomp profile or apply a custom "
                            "profile with --security-opt seccomp=<profile>."
                        ),
                        references=[
                            "https://docs.docker.com/engine/security/seccomp/",
                        ],
                    ))
                elif mode == 1:
                    findings.append(Finding(
                        id="EW-PRIV-005",
                        title="Seccomp in strict mode",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category=Category.PRIVILEGES,
                        evidence="Seccomp mode: 1 (strict)",
                        why_it_matters="Strict seccomp allows only read/write/exit/sigreturn.",
                        remediation="No action needed — this is a very restricted profile.",
                        references=[],
                    ))
                # mode 2 = filter — typically the default

        return findings


@register_check
class AppArmorCheck(BaseCheck):
    """Check AppArmor enforcement status."""

    name = "apparmor-profile"
    description = "Checks AppArmor profile enforcement"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        attr_path = "/proc/1/attr/current"
        content = self._read_file(attr_path)
        if content:
            profile = content.strip().rstrip("\x00")
            if profile in ("unconfined", ""):
                findings.append(Finding(
                    id="EW-PRIV-006",
                    title="AppArmor unconfined",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=Category.PRIVILEGES,
                    evidence=f"AppArmor profile: {profile or '(empty)'}",
                    why_it_matters=(
                        "Without an AppArmor profile, the container lacks mandatory "
                        "access control restrictions on file and network operations."
                    ),
                    remediation="Apply the default Docker AppArmor profile or a custom profile.",
                    references=[
                        "https://docs.docker.com/engine/security/apparmor/",
                    ],
                ))

        return findings


@register_check
class SELinuxCheck(BaseCheck):
    """Check SELinux status indicators."""

    name = "selinux-status"
    description = "Checks SELinux enforcement indicators"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        selinux_path = "/sys/fs/selinux/enforce"
        content = self._read_file(selinux_path)
        if content is not None:
            val = content.strip()
            if val == "0":
                findings.append(Finding(
                    id="EW-PRIV-007",
                    title="SELinux in permissive mode",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=Category.PRIVILEGES,
                    evidence="SELinux enforce=0 (permissive)",
                    why_it_matters=(
                        "SELinux in permissive mode logs policy violations but does "
                        "not enforce them, reducing defense-in-depth."
                    ),
                    remediation="Set SELinux to enforcing mode where supported.",
                    references=[],
                ))

        return findings


@register_check
class RootUserCheck(BaseCheck):
    """Check if running as root inside the container."""

    name = "root-user"
    description = "Checks if running as root (UID 0)"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        if os.getuid() == 0:
            findings.append(Finding(
                id="EW-PRIV-008",
                title="Running as root (UID 0)",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.PRIVILEGES,
                evidence=f"UID={os.getuid()}, GID={os.getgid()}",
                why_it_matters=(
                    "Running as root inside a container increases the impact of any "
                    "escape vulnerability, as the attacker gains root on the host "
                    "if user namespaces are not in use."
                ),
                remediation="Add a USER directive to the Dockerfile to run as non-root.",
                references=[
                    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                ],
            ))

        return findings


@register_check
class NoNewPrivilegesCheck(BaseCheck):
    """Check if no_new_privs is set."""

    name = "no-new-privileges"
    description = "Checks no_new_privs flag"
    category = Category.PRIVILEGES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        status = self._read_file("/proc/1/status")
        if status:
            match = re.search(r"NoNewPrivs:\s+(\d)", status)
            if match and match.group(1) == "0":
                findings.append(Finding(
                    id="EW-PRIV-009",
                    title="no_new_privs not set",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category=Category.PRIVILEGES,
                    evidence="NoNewPrivs: 0",
                    why_it_matters=(
                        "Without no_new_privs, processes can gain additional privileges "
                        "through setuid binaries or capability-aware programs."
                    ),
                    remediation="Set --security-opt no-new-privileges:true in Docker.",
                    references=[
                        "https://docs.docker.com/engine/reference/run/#security-configuration",
                    ],
                ))

        return findings
