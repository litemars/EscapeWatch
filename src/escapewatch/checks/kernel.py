from __future__ import annotations

import re

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity


def _parse_kernel_version(version_str: str) -> tuple[int, int, int] | None:
    """Parse a kernel version string into (major, minor, patch)."""
    if not version_str:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if not m:
        return None
    try:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


class _KernelBase(BaseCheck):
    def _kernel_version_string(self) -> str:
        if getattr(self.environment, "kernel_version", ""):
            return self.environment.kernel_version
        proc_version = self._read_file("/proc/version") or ""
        m = re.match(r"Linux version (\S+)", proc_version)
        if m:
            return m.group(1)
        return proc_version.strip()


@register_check
class DirtyPipeCheck(_KernelBase):
    """Detect kernels vulnerable to CVE-2022-0847 (Dirty Pipe)."""

    name = "kernel-dirty-pipe"
    description = "Checks for kernel vulnerable to CVE-2022-0847 (Dirty Pipe)"
    category = Category.KERNEL

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version_str = self._kernel_version_string()
        parsed = _parse_kernel_version(version_str)

        if parsed is None:
            if version_str:
                findings.append(Finding(
                    id="EW-KERN-001",
                    title="Kernel version unparseable for Dirty Pipe check",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=Category.KERNEL,
                    evidence=f"Kernel version string: {version_str!r}",
                    why_it_matters=(
                        "Could not determine kernel version; cannot rule out "
                        "CVE-2022-0847 (Dirty Pipe). Manual verification required."
                    ),
                    remediation=(
                        "Verify kernel version with `uname -r` and confirm it is "
                        ">= 5.10.102, 5.15.25, 5.16.11, or 5.17."
                    ),
                    references=[
                        "https://www.picussecurity.com/resource/linux-dirty-pipe-cve-2022-0847-vulnerability-exploitation-explained",
                    ],
                ))
            return findings

        maj, minor, patch = parsed

        # Patched in 5.10.102, 5.15.25, 5.16.11, and 5.17+
        if maj > 5 or (maj == 5 and minor > 16):
            if maj == 5 and minor == 17:
                # >= 5.17 not vulnerable
                return findings
            if maj > 5:
                return findings

        vulnerable = False
        if maj == 5:
            if 8 <= minor <= 9:
                vulnerable = True
            elif minor == 10 and patch < 102:
                vulnerable = True
            elif 11 <= minor <= 14:
                vulnerable = True
            elif minor == 15 and patch < 25:
                vulnerable = True
            elif minor == 16 and patch < 11:
                vulnerable = True

        if not vulnerable:
            return findings

        findings.append(Finding(
            id="EW-KERN-001",
            title=f"Kernel {version_str} vulnerable to Dirty Pipe (CVE-2022-0847)",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.KERNEL,
            evidence=(
                f"Kernel {version_str} — vulnerable to CVE-2022-0847 (Dirty Pipe). "
                "Patched in 5.10.102 / 5.15.25 / 5.16.11."
            ),
            why_it_matters=(
                "CVE-2022-0847 (Dirty Pipe) allows any local process — including an "
                "unprivileged process inside a container — to overwrite the content "
                "of read-only memory-mapped files backed by the kernel page cache. "
                "This includes SUID binaries (e.g. /bin/su, /usr/bin/passwd) on the "
                "container's overlay filesystem. By overwriting a SUID binary with "
                "shellcode, an unprivileged container user can gain UID 0 within the "
                "container namespace. Combined with any of the escape vectors in "
                "EW-FS-* or EW-NS-*, this enables full host compromise from a "
                "non-root container process. Unlike Dirty COW (CVE-2016-5195), "
                "exploitation is deterministic and requires no race condition."
            ),
            remediation=(
                "Upgrade the host kernel to >= 5.10.102, >= 5.15.25, >= 5.16.11, or "
                ">= 5.17. On Ubuntu: `apt-get update && apt-get upgrade "
                "linux-image-generic`. On RHEL/CentOS 8+: `dnf update kernel`. "
                "Reboot required."
            ),
            references=[
                "https://www.picussecurity.com/resource/linux-dirty-pipe-cve-2022-0847-vulnerability-exploitation-explained",
                "https://snyk.io/blog/dirty-pipe-vulnerability-cve-2022-0847-containerized-applications/",
            ],
        ))

        return findings


@register_check
class OverlayFSCheck(_KernelBase):
    """Detect kernels vulnerable to GameOver(lay) / CVE-2023-0386."""

    name = "kernel-overlayfs-gameover"
    description = "Checks for kernel vulnerable to GameOver(lay) / CVE-2023-0386"
    category = Category.KERNEL

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version_str = self._kernel_version_string()
        parsed = _parse_kernel_version(version_str)

        os_release = self._read_file("/etc/os-release") or ""
        is_ubuntu = re.search(r"^ID=ubuntu\b", os_release, re.MULTILINE) is not None
        ubuntu_version = ""
        m = re.search(r'^VERSION_ID="?([\d.]+)"?', os_release, re.MULTILINE)
        if m:
            ubuntu_version = m.group(1)

        # Determine if vulnerable
        vulnerable = False
        if parsed is not None:
            maj, minor, _patch = parsed
            # Mainline CVE-2023-0386: kernel 5.11..6.1 (fixed 6.2)
            if maj == 5 and minor >= 11:
                vulnerable = True
            elif maj == 6 and minor < 2:
                vulnerable = True

        # Check overlay mount status
        mountinfo = self._read_file("/proc/self/mountinfo") or ""
        overlay_mounted = " - overlay " in mountinfo or "\toverlay " in mountinfo
        if not overlay_mounted:
            mounts = self._read_file("/proc/mounts") or ""
            for line in mounts.splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[2] == "overlay":
                    overlay_mounted = True
                    break

        max_uns_str = self._read_file("/proc/sys/user/max_user_namespaces") or ""
        try:
            max_uns = int(max_uns_str.strip()) if max_uns_str.strip() else 0
        except ValueError:
            max_uns = 0

        if not vulnerable:
            return findings

        confidence = Confidence.HIGH if (is_ubuntu and parsed) else Confidence.MEDIUM

        ubuntu_descriptor = f"Ubuntu {ubuntu_version}, " if is_ubuntu else ""
        evidence = (
            f"{ubuntu_descriptor}kernel {version_str} — vulnerable to "
            "GameOver(lay) (CVE-2023-2640 + CVE-2023-32629). Overlay filesystem "
            f"is {'active' if overlay_mounted else 'not currently mounted'}. "
            f"user namespaces: max_user_namespaces={max_uns}."
        )

        findings.append(Finding(
            id="EW-KERN-002",
            title=f"Kernel {version_str} vulnerable to GameOver(lay) / CVE-2023-0386",
            severity=Severity.HIGH,
            confidence=confidence,
            category=Category.KERNEL,
            evidence=evidence,
            why_it_matters=(
                "CVE-2023-0386 (mainline) and the Ubuntu-specific pair "
                "CVE-2023-2640/CVE-2023-32629 (GameOver(lay), discovered by "
                "CrowdStrike) exploit a flaw in OverlayFS copy-up logic. When a "
                "file in the lower directory carries extended attributes (xattrs) "
                "encoding capabilities or SUID bits, the kernel fails to verify "
                "UID/GID namespace mappings before copying it to the upper layer. "
                "An unprivileged container user can create a crafted overlayfs "
                "lower directory with a SUID-root binary, mount it inside the "
                "container's user namespace, copy-up the binary to the upper "
                "layer, and execute it to gain UID 0 inside the container. "
                "Container root via this path then enables all classical escape "
                "vectors: cgroup release_agent, SUID planting on writable bind "
                "mounts, ptrace of host processes if hostPID is shared, etc."
            ),
            remediation=(
                "For Ubuntu: apply kernel updates from Ubuntu Security Notices "
                "USN-6250-1 and USN-6252-1. For mainline: upgrade to kernel >= "
                "6.2. As a temporary mitigation, set "
                "`user.max_user_namespaces=0` to disable unprivileged user "
                "namespace mounts (`sysctl -w user.max_user_namespaces=0`), "
                "though this breaks rootless containers."
            ),
            references=[
                "https://www.crowdstrike.com/en-us/blog/crowdstrike-discovers-new-container-exploit/",
                "https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/",
            ],
        ))

        return findings


@register_check
class UnprivilegedBPFCheck(BaseCheck):
    """Detect unprivileged eBPF availability."""

    name = "kernel-unprivileged-bpf"
    description = "Checks unprivileged_bpf_disabled sysctl"
    category = Category.KERNEL

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        content = self._read_file("/proc/sys/kernel/unprivileged_bpf_disabled")
        if content is None:
            return findings

        value = content.strip()
        if value == "0":
            findings.append(Finding(
                id="EW-KERN-003",
                title="Unprivileged eBPF available to all users",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.KERNEL,
                evidence=(
                    "/proc/sys/kernel/unprivileged_bpf_disabled = 0 — any user "
                    "can load eBPF programs"
                ),
                why_it_matters=(
                    "When unprivileged_bpf_disabled=0, any unprivileged process "
                    "inside the container can load eBPF programs (socket filters, "
                    "tracepoints, kprobes) without any capabilities. eBPF programs "
                    "using the bpf_probe_write_user() helper can write to the "
                    "memory of any user-space process on the host, enabling code "
                    "injection into host daemons (sshd, cron, bash) to spawn "
                    "reverse shells with host process privileges. Additionally, "
                    "eBPF socket programs can intercept and manipulate network "
                    "traffic for any socket on the same network namespace, and "
                    "eBPF maps can be used for cross-container data exfiltration."
                ),
                remediation=(
                    "Set kernel.unprivileged_bpf_disabled=1 or 2 via sysctl. Add "
                    "to /etc/sysctl.conf: `kernel.unprivileged_bpf_disabled = 1`. "
                    "Value 2 is recommended for production and cannot be changed "
                    "at runtime without a reboot."
                ),
                references=[
                    "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled",
                ],
            ))
        elif value == "1":
            findings.append(Finding(
                id="EW-KERN-003",
                title="eBPF restricted to privileged users (CAP_BPF / CAP_SYS_ADMIN)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category=Category.KERNEL,
                evidence=(
                    "/proc/sys/kernel/unprivileged_bpf_disabled = 1 — eBPF "
                    "restricted to privileged users"
                ),
                why_it_matters=(
                    "eBPF is restricted to processes with CAP_BPF or "
                    "CAP_SYS_ADMIN. Note that CAP_BPF alone is still dangerous "
                    "in containers — cross-reference with EW-PRIV-012 findings."
                ),
                remediation=(
                    "Consider setting unprivileged_bpf_disabled=2 to fully "
                    "disable eBPF until reboot."
                ),
                references=[
                    "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled",
                ],
            ))

        return findings


@register_check
class IoUringUAFCheck(_KernelBase):
    """Detect kernels vulnerable to io_uring use-after-free (CVE-2023-6817 / CVE-2024-0582)."""

    name = "kernel-io-uring-uaf"
    description = "Checks for kernel vulnerable to io_uring UAF (CVE-2023-6817 / CVE-2024-0582)"
    category = Category.KERNEL

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        version_str = self._kernel_version_string()
        parsed = _parse_kernel_version(version_str)

        if parsed is None:
            return findings

        maj, minor, patch = parsed

        # CVE-2023-6817: io_uring UAF, fixed in 6.6.3.
        # CVE-2024-0582: io_uring buffer-ring UAF, affects 6.4.0–6.6.13, fixed in 6.6.14.
        # Combined vulnerable range: 6.4.0 <= kernel < 6.6.14.
        vulnerable = False
        if maj == 6:
            if minor in (4, 5):
                vulnerable = True
            elif minor == 6 and patch < 14:
                vulnerable = True

        if not vulnerable:
            return findings

        findings.append(Finding(
            id="EW-KERN-004",
            title=f"Kernel {version_str} vulnerable to io_uring UAF (CVE-2023-6817 / CVE-2024-0582)",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=Category.KERNEL,
            evidence=(
                f"Kernel {version_str} — vulnerable to io_uring use-after-free. "
                "CVE-2023-6817 fixed in 6.6.3; CVE-2024-0582 fixed in 6.6.14."
            ),
            why_it_matters=(
                "Two use-after-free vulnerabilities in the io_uring subsystem affect "
                "kernels 6.4 through 6.6.13. CVE-2023-6817: a UAF in io_uring's "
                "registered-buffer management allows an unprivileged local process "
                "to read and write freed kernel memory, enabling privilege escalation "
                "to root. CVE-2024-0582: a UAF in the io_uring buffer-ring "
                "implementation (IORING_REGISTER_PBUF_RING) allows an attacker to "
                "corrupt kernel heap structures and achieve kernel code execution. "
                "Both are exploitable without any special capabilities from within "
                "a container that has access to the io_uring syscall, and public "
                "proof-of-concept exploits exist for CVE-2024-0582. A successful "
                "exploit grants the container process root on the host kernel, "
                "defeating all namespace and capability isolation."
            ),
            remediation=(
                "Upgrade the host kernel to >= 6.6.14 or >= 6.7. On Ubuntu: "
                "`apt-get update && apt-get upgrade linux-image-generic`. "
                "On RHEL 9: `dnf update kernel`. As a temporary mitigation, "
                "block the io_uring syscall via seccomp "
                "(add SCMP_SYS(io_uring_setup), io_uring_enter, io_uring_register "
                "to the deny list). Docker's default seccomp profile blocks "
                "io_uring — ensure it is not disabled with --security-opt seccomp=unconfined."
            ),
            references=[
                "https://www.cvedetails.com/cve/CVE-2023-6817/",
                "https://www.cvedetails.com/cve/CVE-2024-0582/",
                "https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582",
            ],
        ))

        return findings
