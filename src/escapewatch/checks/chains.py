from __future__ import annotations

import glob
import os
import re

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.checks.namespaces import (
    _is_kernel_thread,
    _read_comm,
    read_ns_inode,
)
from escapewatch.checks.privileges import parse_cap_hex
from escapewatch.models import Category, Confidence, Finding, Severity


def _read_capeff() -> tuple[str, set[str]] | None:
    """Read CapEff from /proc/1/status. Returns (hex_string, capability_set)."""
    try:
        with open("/proc/1/status") as f:
            status = f.read()
    except OSError:
        return None
    m = re.search(r"CapEff:\s+([0-9a-fA-F]+)", status)
    if not m:
        return None
    hex_val = m.group(1).strip()
    return (hex_val, parse_cap_hex(hex_val))


def _find_kernel_thread() -> tuple[int, str] | None:
    """Locate one kernel thread visible via /proc."""
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    for entry in sorted(entries, key=lambda x: int(x) if x.isdigit() else 1 << 30):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if _is_kernel_thread(pid):
            return (pid, _read_comm(pid) or "?")
    return None


@register_check
class PtraceHostPIDChainCheck(BaseCheck):
    """CAP_SYS_PTRACE + hostPID → process injection chain."""

    name = "chain-ptrace-hostpid"
    description = "Detects CAP_SYS_PTRACE + hostPID combination"
    category = Category.CHAIN

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        capeff = _read_capeff()
        if not capeff:
            return findings
        capeff_hex, caps = capeff
        if "cap_sys_ptrace" not in caps:
            return findings

        kthread = _find_kernel_thread()
        if not kthread:
            return findings

        pid, comm = kthread
        findings.append(Finding(
            id="EW-CHAIN-001",
            title="CAP_SYS_PTRACE + hostPID — full process-injection chain",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.CHAIN,
            evidence=(
                f"cap_sys_ptrace in CapEff ({capeff_hex}) AND kernel threads "
                f"visible in /proc (e.g. PID {pid}=[{comm}]) — full ptrace "
                "process injection chain confirmed."
            ),
            why_it_matters=(
                "This combination enables a complete, trivially-exploitable "
                "container escape via ptrace process injection. With "
                "CAP_SYS_PTRACE and visibility into the host PID namespace, an "
                "attacker can: (1) enumerate all host processes via /proc, (2) "
                "select a high-privilege target (e.g. PID 1/systemd, sshd, "
                "kubelet), (3) attach to it with ptrace(PTRACE_ATTACH), (4) "
                "write shellcode into its memory with PTRACE_POKEDATA, (5) "
                "redirect execution with PTRACE_SETREGS. The shellcode runs "
                "with the target process's UID and capabilities — typically "
                "root on the host. This is equivalent to arbitrary code "
                "execution on the host node. Individually, CAP_SYS_PTRACE and "
                "hostPID each warrant HIGH severity; together they form a "
                "one-step, no-exploit escape."
            ),
            remediation=(
                "Remove CAP_SYS_PTRACE from the container capability set "
                "(--cap-drop CAP_SYS_PTRACE). Set hostPID: false. Neither is "
                "required for the vast majority of workloads. If ptrace is "
                "needed for a debugger sidecar, scope it to a dedicated pod "
                "with no network access and no sensitive mounts rather than "
                "production workloads."
            ),
            references=[
                "https://some-natalie.dev/container-escapes-ptrace/",
                "https://www.cybereason.com/blog/container-escape-all-you-need-is-cap-capabilities",
            ],
        ))

        return findings


@register_check
class SysAdminCgroupV1ChainCheck(BaseCheck):
    """CAP_SYS_ADMIN + cgroup v1 release_agent chain."""

    name = "chain-sysadmin-cgroupv1-release-agent"
    description = "Detects CAP_SYS_ADMIN + writable cgroup v1 release_agent"
    category = Category.CHAIN

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        capeff = _read_capeff()
        if not capeff:
            return findings
        capeff_hex, caps = capeff
        if "cap_sys_admin" not in caps:
            return findings

        # cgroup v2 indicator
        if self._path_exists("/sys/fs/cgroup/cgroup.controllers"):
            return findings

        # Confirm cgroup v1 is in use
        mounts_text = self._read_file("/proc/mounts") or ""
        cgroup_v1_mounted = False
        for line in mounts_text.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[2] == "cgroup":
                cgroup_v1_mounted = True
                break
        if not cgroup_v1_mounted:
            return findings

        agent_paths = glob.glob("/sys/fs/cgroup/*/release_agent")
        if not agent_paths:
            return findings

        findings.append(Finding(
            id="EW-CHAIN-002",
            title="CAP_SYS_ADMIN + cgroup v1 release_agent — full escape chain",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.CHAIN,
            evidence=(
                f"cap_sys_admin in CapEff ({capeff_hex}), cgroup v1 mounted, "
                f"release_agent at {agent_paths}. Full cgroup escape chain "
                "confirmed."
            ),
            why_it_matters=(
                "This combination is a complete, one-step container escape. "
                "CAP_SYS_ADMIN grants the ability to mount new filesystems and "
                "create cgroup namespaces. With a writable cgroup v1 "
                "release_agent, the attacker: (1) creates a new cgroup "
                "namespace, (2) finds the container's cgroup path in "
                "/proc/self/cgroup, (3) writes an arbitrary script path to "
                "/sys/fs/cgroup/<subsystem>/release_agent, (4) enables "
                "notify_on_release, (5) triggers a cgroup release by killing "
                "the last process in a child cgroup. The kernel executes the "
                "release_agent script as root in the host's initial namespace. "
                "This technique has been public since at least 2019 and is "
                "reliably exploitable on any kernel with cgroup v1 and these "
                "preconditions."
            ),
            remediation=(
                "Do not grant CAP_SYS_ADMIN to containers. Migrate to cgroup v2 "
                "(set systemd.unified_cgroup_hierarchy=1 on the kernel cmdline), "
                "which eliminates release_agent. As an interim measure, mount "
                "/sys/fs/cgroup read-only."
            ),
            references=[
                "https://www.aquasec.com/blog/new-linux-kernel-vulnerability-escaping-containers-by-abusing-cgroups/",
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
        ))

        return findings


@register_check
class HostNetworkRootAbstractSocketChainCheck(BaseCheck):
    """hostNetwork=true + UID 0 → CVE-2020-15257 abstract socket chain."""

    name = "chain-hostnet-root-abstract-socket"
    description = "Detects hostNetwork + UID 0 + containerd-shim abstract socket"
    category = Category.CHAIN

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        net_ns_1 = read_ns_inode(1, "net")
        net_ns_2 = read_ns_inode(2, "net")
        if not (net_ns_1 and net_ns_2 and net_ns_1 == net_ns_2):
            return findings

        if os.getuid() != 0:
            return findings

        abstract_sock = "(not visible)"
        confidence = Confidence.MEDIUM
        proc_unix = self._read_file("/proc/net/unix") or ""
        for line in proc_unix.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 8:
                continue
            name = parts[7]
            if name.startswith("@") and "containerd-shim" in name:
                abstract_sock = name
                confidence = Confidence.HIGH
                break

        findings.append(Finding(
            id="EW-CHAIN-003",
            title="hostNetwork + UID 0 — CVE-2020-15257 abstract-socket chain",
            severity=Severity.CRITICAL,
            confidence=confidence,
            category=Category.CHAIN,
            evidence=(
                f"Host network namespace shared (PID 1 net ns == PID 2/kthreadd "
                f"net ns), running as UID 0. Abstract socket '{abstract_sock}' "
                "found in /proc/net/unix. CVE-2020-15257 exploitation "
                "preconditions confirmed."
            ),
            why_it_matters=(
                "The containerd-shim API is exposed over an abstract Unix domain "
                "socket in the root network namespace. Abstract sockets are not "
                "filesystem-bound — they are visible only within the same "
                "network namespace. A container running with hostNetwork: true "
                "shares the root network namespace and can therefore reach the "
                "shim API socket without any filesystem mount. With UID 0 inside "
                "the container, an attacker can connect to the shim socket "
                "using the TTRPC protocol and issue container management "
                "commands, including spawning a new container with: hostPID: "
                "true, privileged: true, and a bind mount of the host root "
                "filesystem. This achieves full host compromise without any "
                "kernel exploit."
            ),
            remediation=(
                "Upgrade containerd to >= 1.3.9 or >= 1.4.3 (moves the shim "
                "socket out of the root network namespace). Set hostNetwork: "
                "false. Never run workloads as UID 0. Apply network policies to "
                "restrict traffic within the cluster network namespace."
            ),
            references=[
                "https://www.sentinelone.com/vulnerability-database/cve-2020-15257/",
                "https://kloudle.com/academy/cve-2020-15257-what-is-it-and-how-does-it-impact-your-docker-and-kubernetes-environments/",
            ],
        ))

        return findings
