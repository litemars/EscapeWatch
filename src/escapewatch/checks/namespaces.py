from __future__ import annotations

import os
import socket

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity


def read_ns_inode(pid: int | str, ns: str) -> str | None:
    """Read a namespace inode link for a given PID."""
    path = f"/proc/{pid}/ns/{ns}"
    try:
        return os.readlink(path)
    except OSError:
        return None


def _read_comm(pid: int | str) -> str | None:
    """Read /proc/<pid>/comm, returning None on error."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return None


def _read_cmdline(pid: int | str) -> str | None:
    """Read /proc/<pid>/cmdline, returning None on error. Empty string means
    the process has no argv (kernel thread or exec()ing user process)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return None


# Names of well-known kernel threads. Kernel threads only exist in the host
# PID namespace, so seeing any of these is definitive evidence of PID ns sharing.
# /proc/<pid>/comm is truncated to 15 bytes by the kernel, so we match by prefix.
_KERNEL_THREAD_PREFIXES = (
    "kthreadd",
    "kworker/",
    "ksoftirqd/",
    "migration/",
    "rcu_",
    "watchdog/",
    "cpuhp/",
    "idle_inject/",
    "kdevtmpfs",
    "kcompactd",
    "khugepaged",
    "kswapd",
    "oom_reaper",
)


def _is_kernel_thread(pid: int | str) -> bool:
    """A kernel thread has an empty /proc/PID/cmdline and a recognizable comm."""
    cmdline = _read_cmdline(pid)
    if cmdline is None or cmdline != "":
        return False
    comm = _read_comm(pid)
    if not comm:
        return False
    return any(comm.startswith(prefix) for prefix in _KERNEL_THREAD_PREFIXES)


@register_check
class HostPIDCheck(BaseCheck):
    """Detect hostPID namespace sharing.

    Kernel threads (kthreadd, kworker/*, ksoftirqd/*, ...) only ever run in
    the host PID namespace. If a container can see *any* kernel thread in
    `/proc`, it is sharing the host PID namespace — there is no legitimate
    way for a properly-isolated container to see them. This replaces the
    earlier "> 50 processes" heuristic which gave false positives on any
    workload with many processes (nginx workers, JVM threads, ...).
    """

    name = "host-pid"
    description = "Checks for host PID namespace sharing"
    category = Category.NAMESPACES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        pid_ns_1 = read_ns_inode(1, "pid")

        try:
            pids = [int(d) for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return findings

        # Collect up to a few kernel-thread sightings for evidence. Probing
        # every process would be wasteful on hosts with thousands of PIDs.
        kthreads: list[tuple[int, str]] = []
        for pid in sorted(pids):
            if len(kthreads) >= 5:
                break
            if _is_kernel_thread(pid):
                comm = _read_comm(pid) or "?"
                kthreads.append((pid, comm))

        if kthreads:
            sightings = ", ".join(f"PID {p}=[{c}]" for p, c in kthreads)
            findings.append(Finding(
                id="EW-NS-001",
                title="Host PID namespace shared",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.NAMESPACES,
                evidence=(
                    f"Kernel threads visible: {sightings}; "
                    f"PID ns: {pid_ns_1 or 'unknown'}; "
                    f"total visible PIDs: {len(pids)}"
                ),
                why_it_matters=(
                    "Kernel threads only run in the host PID namespace, so "
                    "their visibility proves the container shares it. Host "
                    "PID sharing exposes all host processes: an attacker "
                    "inside the container can inspect cmdlines, environment "
                    "variables, send signals, and (with CAP_SYS_PTRACE) "
                    "attach to host processes to dump memory or inject code."
                ),
                remediation="Set hostPID: false in the pod spec or remove --pid=host.",
                references=[
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                ],
            ))

        return findings


@register_check
class HostNetworkCheck(BaseCheck):
    """Detect host network namespace sharing.

    The most reliable signal is comparing the network namespace inode of
    PID 1 (the container's init) with PID 2 (kthreadd — always in the
    host namespaces).  If both resolve to the same inode the container
    shares the host network namespace; no amount of interface heuristics
    can beat a direct kernel check.

    As a fallback (when /proc/2/ns/net is unreadable — e.g. AppArmor
    blocking), we look for network artefacts that only exist on the host:
    `docker0` bridge, physical NIC prefixes (`ens`, `enp`, `wlan`), or a
    large number of `veth` pairs.
    """

    name = "host-network"
    description = "Checks for host network namespace sharing"
    category = Category.NAMESPACES

    # Interface-name prefixes that are strong host-network indicators.
    # `eth0` is excluded because container runtimes create a virtual eth0
    # inside every isolated netns, so it's not distinctive.
    _HOST_INDICATORS = ("docker0", "ens", "enp", "wlan", "br-", "virbr")

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        net_ns_1 = read_ns_inode(1, "net")
        net_ns_2 = read_ns_inode(2, "net")   # kthreadd — always host ns

        # ── Primary check: namespace inode comparison ──
        if net_ns_1 and net_ns_2 and net_ns_1 == net_ns_2:
            # Collect interface list for evidence
            try:
                ifaces = os.listdir("/sys/class/net/")
            except OSError:
                ifaces = []

            findings.append(Finding(
                id="EW-NS-002",
                title="Host network namespace shared",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.NAMESPACES,
                evidence=(
                    f"PID 1 net ns ({net_ns_1}) == PID 2/kthreadd net ns. "
                    f"Interfaces: {', '.join(ifaces) or 'unknown'}"
                ),
                why_it_matters=(
                    "Host network namespace exposes all host network interfaces, "
                    "allows binding to any port, and can intercept host traffic."
                ),
                remediation="Set hostNetwork: false in the pod spec or remove --net=host.",
                references=[
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                ],
            ))
            return findings

        # ── Fallback: interface heuristic (when ns inodes are unavailable) ──
        try:
            interfaces = os.listdir("/sys/class/net/")
        except OSError:
            return findings

        non_lo = [i for i in interfaces if i != "lo"]
        host_ifaces = [
            i for i in non_lo
            if any(i.startswith(p) for p in self._HOST_INDICATORS)
        ]
        veth_count = sum(1 for i in non_lo if i.startswith("veth"))

        if host_ifaces:
            findings.append(Finding(
                id="EW-NS-002",
                title="Host network namespace likely shared",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.NAMESPACES,
                evidence=(
                    f"Host-only interfaces visible: {', '.join(host_ifaces)}. "
                    f"All interfaces: {', '.join(interfaces)}. "
                    f"Net ns: {net_ns_1 or 'unknown'}"
                ),
                why_it_matters=(
                    "Host network namespace exposes all host network interfaces, "
                    "allows binding to any port, and can intercept host traffic."
                ),
                remediation="Set hostNetwork: false in the pod spec or remove --net=host.",
                references=[],
            ))
        elif veth_count >= 3 and len(non_lo) > 5:
            findings.append(Finding(
                id="EW-NS-002",
                title="Host network namespace possibly shared",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category=Category.NAMESPACES,
                evidence=(
                    f"{veth_count} veth pairs visible among {len(non_lo)} "
                    f"non-loopback interfaces. Net ns: {net_ns_1 or 'unknown'}"
                ),
                why_it_matters=(
                    "Multiple veth pairs and many interfaces suggest the container "
                    "shares the host network namespace."
                ),
                remediation="Verify network namespace isolation. Remove --net=host if present.",
                references=[],
            ))

        return findings


@register_check
class HostIPCCheck(BaseCheck):
    """Detect host IPC namespace sharing.

    Like HostPIDCheck and HostNetworkCheck, the definitive signal is
    comparing namespace inodes: PID 1 (container init) vs PID 2
    (kthreadd, always in host namespaces). If both have the same IPC
    namespace inode the container shares host IPC.

    Falls back to a /dev/shm heuristic only when inode comparison is
    unavailable.
    """

    name = "host-ipc"
    description = "Checks for host IPC namespace sharing"
    category = Category.NAMESPACES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        ipc_ns_1 = read_ns_inode(1, "ipc")
        ipc_ns_2 = read_ns_inode(2, "ipc")  # kthreadd — always host ns

        # ── Primary: namespace inode comparison ──
        if ipc_ns_1 and ipc_ns_2 and ipc_ns_1 == ipc_ns_2:
            findings.append(Finding(
                id="EW-NS-003",
                title="Host IPC namespace shared",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.NAMESPACES,
                evidence=(
                    f"PID 1 ipc ns ({ipc_ns_1}) == PID 2/kthreadd ipc ns"
                ),
                why_it_matters=(
                    "Host IPC namespace allows the container to access shared "
                    "memory segments and semaphores of host processes, "
                    "enabling data exfiltration or tampering."
                ),
                remediation="Set hostIPC: false in the pod spec or remove --ipc=host.",
                references=[
                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                ],
            ))
            return findings

        # ── Fallback: /dev/shm heuristic (less reliable) ──
        shm_path = "/dev/shm"
        try:
            if os.path.isdir(shm_path):
                shm_entries = os.listdir(shm_path)
                if len(shm_entries) > 10:
                    findings.append(Finding(
                        id="EW-NS-003",
                        title="Host IPC namespace possibly shared",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        category=Category.NAMESPACES,
                        evidence=(
                            f"IPC ns: {ipc_ns_1 or 'unknown'}, "
                            f"{len(shm_entries)} entries in /dev/shm"
                        ),
                        why_it_matters=(
                            "Host IPC namespace allows the container to access shared "
                            "memory segments of host processes."
                        ),
                        remediation="Set hostIPC: false in the pod spec or remove --ipc=host.",
                        references=[],
                    ))
        except OSError:
            pass

        return findings
