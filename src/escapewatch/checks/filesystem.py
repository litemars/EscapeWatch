from __future__ import annotations

import glob
import os
import re
import stat
from pathlib import Path

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity

# Sensitive host paths that should not be mounted into containers
SENSITIVE_HOST_MOUNTS = {
    "/": "Full host root filesystem",
    "/etc": "Host configuration files",
    "/proc": "Host process information",
    "/sys": "Host sysfs",
    "/var/run/docker.sock": "Docker runtime socket",
    "/run/docker.sock": "Docker runtime socket",
    "/var/run/containerd": "containerd runtime directory",
    "/run/containerd": "containerd runtime directory",
    "/var/lib/docker": "Docker data directory",
    "/var/lib/kubelet": "Kubelet data directory",
    "/var/log": "Host log directory",
    "/root": "Root home directory",
    "/home": "User home directories",
}

# Single-file bind mounts that every container runtime creates and that
# must not be flagged as "host /etc mounted". They're DNS/hostname plumbing,
# not security issues.
_EXPECTED_SINGLE_FILE_MOUNTS = {
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/dev/termination-log",
}


def _is_path_or_subpath(mp: str, sensitive: str) -> bool:
    """True if `mp` is exactly `sensitive` or a proper path-component child.

    Unlike `str.startswith`, this avoids matching `/etcd-data` against `/etc`
    or `/home2` against `/home`.
    """
    if mp == sensitive:
        return True
    prefix = sensitive.rstrip("/") + "/"
    return mp.startswith(prefix)

# Known container runtime socket paths
RUNTIME_SOCKET_PATHS = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
    "/run/crio/crio.sock",
]


def parse_mounts(text: str) -> list[dict[str, str]]:
    """Parse /proc/mounts or /proc/1/mountinfo into structured data."""
    mounts = []
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mount = {
                "device": parts[0],
                "mountpoint": parts[1],
                "fstype": parts[2] if len(parts) > 2 else "",
                "options": parts[3] if len(parts) > 3 else "",
            }
            mounts.append(mount)
    return mounts


@register_check
class DockerSocketCheck(BaseCheck):
    """Check for exposed Docker/container runtime sockets."""

    name = "docker-socket"
    description = "Checks for mounted container runtime sockets"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for sock_path in RUNTIME_SOCKET_PATHS:
            if self._path_exists(sock_path):
                socket_type = "Docker" if "docker" in sock_path else "containerd/CRI"
                findings.append(Finding(
                    id="EW-FS-001",
                    title=f"{socket_type} socket exposed",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.FILESYSTEM,
                    evidence=f"Socket found: {sock_path}",
                    why_it_matters=(
                        f"Access to the {socket_type} socket allows full control over "
                        "the container runtime, enabling container escape and host compromise."
                    ),
                    remediation=(
                        "Remove the socket mount. If API access is needed, use a "
                        "read-only proxy like docker-socket-proxy."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                    ],
                ))

        return findings


@register_check
class SensitiveMountsCheck(BaseCheck):
    """Check for sensitive host filesystem mounts."""

    name = "sensitive-mounts"
    description = "Checks for sensitive host path mounts"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        mounts_text = self._read_file("/proc/mounts")
        if not mounts_text:
            return findings

        mounts = parse_mounts(mounts_text)

        # Build an index of per-mountpoint source-root info from mountinfo so we
        # can distinguish real host bind mounts from container kernel masks and
        # single-file runtime plumbing.
        mountinfo_text = self._read_file("/proc/1/mountinfo") or ""
        source_roots: dict[str, str] = {}
        for line in mountinfo_text.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            # mountinfo fields: id parent maj:min root mountpoint ...
            source_roots[parts[4]] = parts[3]

        # Track which sensitive paths we've already reported to avoid firing
        # the same finding once per matching subpath.
        reported: set[str] = set()

        for mount in mounts:
            mp = mount["mountpoint"]

            # Skip runtime-created single-file plumbing (hosts, hostname,
            # resolv.conf, termination-log). These look like bind mounts from
            # the host rootfs but are expected in every container.
            if mp in _EXPECTED_SINGLE_FILE_MOUNTS:
                continue

            # Skip kernel masks under /proc/* and /sys/* — the runtime bind-
            # mounts tmpfs/null over dangerous proc/sys files; these are
            # security features, not host mounts. We still catch an actual
            # host /proc or /sys mount because those match `mp == "/proc"` or
            # `mp == "/sys"`.
            if mp.startswith("/proc/") or mp.startswith("/sys/"):
                continue

            # Kernel-managed /proc and /sys are every container's own
            # procfs/sysfs — not a host bind-mount. Only a bind-mount of
            # the host's /proc or /sys would inherit a different fstype.
            fstype = mount.get("fstype", "")
            if mp == "/proc" and fstype == "proc":
                continue
            if mp == "/sys" and fstype in ("sysfs", "tmpfs"):
                continue
            if mp == "/dev" and fstype in ("tmpfs", "devtmpfs"):
                continue

            for sensitive_path, desc in SENSITIVE_HOST_MOUNTS.items():
                if sensitive_path == "/":
                    # Only flag if we see the actual host root bind-mount
                    if mount["device"].startswith("/dev/") and mp == "/hostfs":
                        findings.append(Finding(
                            id="EW-FS-002",
                            title="Host root filesystem mounted",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            category=Category.FILESYSTEM,
                            evidence=f"Device {mount['device']} mounted at {mp}",
                            why_it_matters=(
                                "Full host filesystem access allows reading secrets, "
                                "modifying host binaries, and escaping the container."
                            ),
                            remediation="Remove the host root mount. Use specific subpath mounts.",
                            references=[],
                        ))
                    continue

                if not _is_path_or_subpath(mp, sensitive_path):
                    continue

                # If mountinfo tells us the source root is "/" and the
                # mountpoint equals the sensitive path, it's a real host
                # directory mount. Otherwise require exact match — we don't
                # want to flag every subpath of a sensitive dir once the
                # parent has been flagged (or at all, for subpaths whose
                # source root is "/", which means they're on the container
                # rootfs, not from the host).
                src_root = source_roots.get(mp)
                if mp != sensitive_path and src_root == "/":
                    # e.g. /etc/foo living on the container's own overlay —
                    # not a host mount at all.
                    continue

                if sensitive_path in reported:
                    continue
                reported.add(sensitive_path)

                is_writable = "rw" in mount["options"].split(",")
                sev = Severity.HIGH if is_writable else Severity.MEDIUM
                findings.append(Finding(
                    id="EW-FS-003",
                    title=f"Sensitive host path mounted: {sensitive_path}",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    category=Category.FILESYSTEM,
                    evidence=(
                        f"Mount: {mount['device']} -> {mp} "
                        f"({'writable' if is_writable else 'read-only'})"
                    ),
                    why_it_matters=f"{desc} — exposed to the container.",
                    remediation=f"Remove the mount for {sensitive_path} or make it read-only.",
                    references=[],
                ))
                break  # one finding per mount entry is enough

        return findings


@register_check
class WritableCgroupCheck(BaseCheck):
    """Check for writable cgroup paths."""

    name = "writable-cgroup"
    description = "Checks for writable cgroup paths"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        cgroup_dirs = [
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/memory",
            "/sys/fs/cgroup/cpu",
            "/sys/fs/cgroup/pids",
        ]

        writable_paths = []
        for d in cgroup_dirs:
            if self._path_exists(d) and self._is_writable(d):
                writable_paths.append(d)

        if writable_paths:
            findings.append(Finding(
                id="EW-FS-004",
                title="Writable cgroup paths detected",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"Writable cgroup paths: {', '.join(writable_paths)}",
                why_it_matters=(
                    "Writable cgroup paths can be abused for container escape via "
                    "release_agent or device access manipulation."
                ),
                remediation="Mount cgroup filesystem as read-only inside the container.",
                references=[
                    "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
                ],
            ))

        return findings


@register_check
class ProcSysWriteCheck(BaseCheck):
    """Check for writable /proc/sys paths and unsafe sysctl values."""

    name = "writable-proc-sys"
    description = "Checks for writable /proc/sys entries and unsafe sysctl values"
    category = Category.FILESYSTEM

    DANGEROUS_VALUE_ENTRIES = {
        "/proc/sys/kernel/unprivileged_bpf_disabled": {
            "description": "Controls whether unprivileged users can load eBPF programs",
            "dangerous_value": "0",
            "severity": Severity.HIGH,
            "attack": (
                "Unprivileged eBPF programs can be used to exploit kernel "
                "vulnerabilities or attach kprobes to spy on host processes. "
                "CVE-2022-42150 used CAP_SYS_ADMIN but unprivileged eBPF opens "
                "similar paths to kernel exploitation."
            ),
        },
        "/proc/sys/kernel/perf_event_paranoid": {
            "description": "Controls access to kernel perf counters",
            "dangerous_value": "-1",
            "severity": Severity.MEDIUM,
            "attack": (
                "Values <= 1 grant unprivileged access to hardware performance "
                "counters, enabling cross-process data leakage (Spectre-class "
                "side channels)."
            ),
        },
        "/proc/sys/kernel/kptr_restrict": {
            "description": "Controls kernel pointer exposure in /proc",
            "dangerous_value": "0",
            "severity": Severity.MEDIUM,
            "attack": (
                "Value 0 leaks kernel virtual addresses, bypassing KASLR and "
                "providing gadget addresses needed for kernel ROP exploitation."
            ),
        },
    }

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        dangerous_proc = [
            "/proc/sys/kernel/core_pattern",
            "/proc/sys/kernel/modprobe",
            "/proc/sysrq-trigger",
            "/proc/sys/vm/panic_on_oom",
        ]

        writable = [p for p in dangerous_proc if self._path_exists(p) and self._is_writable(p)]

        if writable:
            findings.append(Finding(
                id="EW-FS-005",
                title="Writable dangerous /proc/sys entries",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"Writable entries: {', '.join(writable)}",
                why_it_matters=(
                    "Writable core_pattern or modprobe paths can be used to execute "
                    "arbitrary code on the host kernel."
                ),
                remediation="Ensure /proc/sys is mounted read-only (default in modern runtimes).",
                references=[],
            ))

        for path, info in self.DANGEROUS_VALUE_ENTRIES.items():
            content = self._read_file(path)
            if content is None:
                continue
            current_value = content.strip()
            if current_value != info["dangerous_value"]:
                continue
            findings.append(Finding(
                id="EW-FS-012",
                title=f"Unsafe sysctl value: {path} = {current_value}",
                severity=info["severity"],
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"{path} = {current_value} ({info['description']})",
                why_it_matters=info["attack"],
                remediation=(
                    f"Set a safer value for {path} via sysctl. Add to "
                    "/etc/sysctl.conf and reload."
                ),
                references=[
                    "https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html",
                ],
            ))

        return findings


@register_check
class ProcMemWriteCheck(BaseCheck):
    """Detect writable /proc/<pid>/mem — direct host memory write primitive."""

    name = "proc-mem-writable"
    description = "Checks if /proc/1/mem is writable"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        path = "/proc/1/mem"
        if not self._path_exists(path):
            return findings

        fd = None
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except (PermissionError, OSError):
            return findings
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        findings.append(Finding(
            id="EW-FS-011",
            title="/proc/1/mem is writable — direct memory injection vector",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.FILESYSTEM,
            evidence=(
                "Opened /proc/1/mem with O_WRONLY successfully — direct host "
                "process memory write is possible without ptrace syscall."
            ),
            why_it_matters=(
                "Direct write access to /proc/<pid>/mem bypasses the ptrace "
                "syscall entirely. While ptrace-based memory injection requires "
                "CAP_SYS_PTRACE and can be blocked by seccomp rules that deny "
                "ptrace(2), /proc/mem writes use only open(2) and write(2) — "
                "syscalls allowed by most seccomp profiles including Docker's "
                "default. An attacker with O_WRONLY access to /proc/1/mem can "
                "inject shellcode into PID 1 (systemd, or the container's init) "
                "and redirect execution, achieving privilege escalation or "
                "escape without any capability requirements beyond the ability "
                "to open the file."
            ),
            remediation=(
                "Apply a seccomp profile that denies open(2) with O_WRONLY on "
                "/proc/*/mem paths. Add an AppArmor rule: "
                "`deny /proc/*/mem rwklx`. Ensure no_new_privs is set."
            ),
            references=[
                "https://some-natalie.dev/container-escapes-ptrace/",
            ],
        ))

        return findings


@register_check
class ReadOnlyRootfsCheck(BaseCheck):
    """Check if root filesystem is read-only."""

    name = "read-only-rootfs"
    description = "Checks for read-only root filesystem"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        mounts_text = self._read_file("/proc/mounts")
        if mounts_text:
            for line in mounts_text.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "/":
                    opts = parts[3].split(",")
                    if "rw" in opts:
                        findings.append(Finding(
                            id="EW-FS-006",
                            title="Root filesystem is writable",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category=Category.FILESYSTEM,
                            evidence=f"Root mount options: {parts[3]}",
                            why_it_matters=(
                                "A writable root filesystem allows an attacker to "
                                "modify binaries and persist changes inside the container."
                            ),
                            remediation="Use --read-only flag when running containers.",
                            references=[
                                "https://docs.docker.com/engine/reference/run/#read-only",
                            ],
                        ))
                    break

        return findings


@register_check
class DeviceMountsCheck(BaseCheck):
    """Check for suspicious block-device mounts.

    This check deliberately reads `/proc/1/mountinfo` instead of
    `/proc/mounts` so it can see each mount's *source root*. A single-file
    bind-mount like `/etc/hosts` inherits its source device from the host
    rootfs (e.g. `/dev/nvme0n1p2`) but has a non-"/" source root — flagging
    it as a "block device mount" is a false positive. Only whole-filesystem
    mounts (source root == "/") should be reported here; sensitive bind
    mounts are covered by EW-FS-003 and EW-FS-010.
    """

    name = "device-mounts"
    description = "Checks for suspicious whole-disk block-device mounts"
    category = Category.FILESYSTEM

    SUSPICIOUS_DEVICE_PREFIXES = (
        "/dev/sd", "/dev/vd", "/dev/xvd",
        "/dev/dm-", "/dev/nvme", "/dev/md",
        "/dev/mem", "/dev/kmem", "/dev/mapper/",
    )
    # Mountpoints we expect even on fully-contained workloads.
    EXPECTED_MOUNTPOINTS = {
        "/", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
        "/dev/termination-log",
    }

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        mountinfo = self._read_file("/proc/1/mountinfo")
        if not mountinfo:
            return findings

        for line in mountinfo.splitlines():
            parts = line.split()
            if len(parts) < 10 or "-" not in parts:
                continue
            try:
                sep = parts.index("-")
            except ValueError:
                continue
            if sep + 2 >= len(parts):
                continue

            source_root = parts[3]
            mountpoint = parts[4]
            source = parts[sep + 2]

            # A whole-filesystem block mount has source_root == "/". Anything
            # else is a file-level or subpath bind mount and is handled by
            # EW-FS-003 / EW-FS-010.
            if source_root != "/":
                continue
            if mountpoint in self.EXPECTED_MOUNTPOINTS:
                continue
            if not any(source.startswith(p) for p in self.SUSPICIOUS_DEVICE_PREFIXES):
                continue

            findings.append(Finding(
                id="EW-FS-007",
                title=f"Block device mounted: {source}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"Device {source} mounted at {mountpoint} (whole-fs)",
                why_it_matters=(
                    "Direct block device access allows reading/writing "
                    "the host filesystem bypassing all mount restrictions."
                ),
                remediation="Remove device mounts from the container.",
                references=[],
            ))

        return findings


@register_check
class CgroupV1ReleaseAgentCheck(BaseCheck):
    """Check for writable cgroup v1 release_agent files (container escape vector)."""

    name = "cgroup-v1-release-agent"
    description = "Checks for writable cgroup v1 release_agent files"
    category = Category.FILESYSTEM

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # cgroup v2 (unified hierarchy) does not have release_agent — attack
        # surface is gone. Emit an INFO finding confirming v2 protection.
        if self._path_exists("/sys/fs/cgroup/cgroup.controllers"):
            return [Finding(
                id="EW-FS-008",
                title="cgroup v2 in use — release_agent vector not applicable",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence="Detected /sys/fs/cgroup/cgroup.controllers (cgroup v2 unified hierarchy)",
                why_it_matters="cgroup v2 does not support the release_agent escape path.",
                remediation="No action required — cgroup v2 eliminates this attack vector.",
                references=["https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html"],
            )]

        release_agents = glob.glob("/sys/fs/cgroup/*/release_agent")

        writable = [p for p in release_agents if self._path_exists(p) and self._is_writable(p)]
        present = [p for p in release_agents if self._path_exists(p)]

        if writable:
            findings.append(Finding(
                id="EW-FS-008",
                title="Writable cgroup v1 release_agent detected",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"Writable release_agent files: {', '.join(writable)}",
                why_it_matters=(
                    "A writable cgroup v1 release_agent allows arbitrary command execution on "
                    "the host. When a cgroup becomes empty, the kernel executes the program "
                    "specified in release_agent as root in the host's namespaces — bypassing "
                    "all container isolation (Felix Wilhelm / Trail of Bits technique)."
                ),
                remediation=(
                    "Mount the cgroup filesystem read-only, migrate to cgroup v2 "
                    "(which removes release_agent), or apply a seccomp/AppArmor profile "
                    "that blocks cgroup writes."
                ),
                references=[
                    "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492",
                ],
            ))
        elif present:
            # Present but read-only — lower severity, worth flagging for correlation
            findings.append(Finding(
                id="EW-FS-008",
                title="Cgroup v1 release_agent present (read-only)",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.FILESYSTEM,
                evidence=f"Release agent files found: {', '.join(present)}",
                why_it_matters=(
                    "Cgroup v1 release_agent is present. If an attacker gains write access "
                    "to cgroup paths through another vulnerability, this becomes a CRITICAL "
                    "container escape vector."
                ),
                remediation=(
                    "Migrate to cgroup v2 to eliminate this attack surface entirely."
                ),
                references=[
                    "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
                ],
            ))

        return findings


@register_check
class VarLogSymlinkEscapeCheck(BaseCheck):
    """Detect symlinks under /var/log that escape the directory.

    Palo Alto Unit 42 — *Container Escape Techniques*, technique #4
    ("Log Mounts"). When a Kubernetes pod has /var/log bind-mounted from
    the host (a common pattern for log collectors), an attacker who can
    write inside that directory can replace a log file with a symlink to
    a sensitive host file (e.g. /etc/shadow, /var/lib/kubelet/...). The
    kubelet log-reading endpoint then dereferences the symlink and
    returns the host file's contents to any caller with `pods/log`
    permissions — yielding host file disclosure and a foothold for
    full container escape.
    """

    name = "var-log-symlink-escape"
    description = "Checks /var/log for symlinks that escape the mount root"
    category = Category.FILESYSTEM

    # Bound the walk so this check stays cheap on hosts with large /var/log
    MAX_ENTRIES = 5000
    MAX_DEPTH = 6
    MAX_REPORTED = 25

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        var_log = "/var/log"
        if not self._path_exists(var_log):
            return findings

        escaping: list[tuple[str, str]] = []
        scanned = 0
        try:
            for root, dirs, files in os.walk(var_log, followlinks=False):
                depth = root[len(var_log):].count(os.sep)
                if depth > self.MAX_DEPTH:
                    dirs[:] = []
                    continue
                for entry in dirs + files:
                    if scanned >= self.MAX_ENTRIES:
                        break
                    scanned += 1
                    full = os.path.join(root, entry)
                    try:
                        st = os.lstat(full)
                    except OSError:
                        continue
                    if not stat.S_ISLNK(st.st_mode):
                        continue
                    try:
                        target = os.readlink(full)
                    except OSError:
                        continue
                    if os.path.isabs(target):
                        resolved = os.path.normpath(target)
                    else:
                        resolved = os.path.normpath(os.path.join(root, target))
                    if resolved == var_log or resolved.startswith(var_log + os.sep):
                        continue
                    escaping.append((full, target))
                    if len(escaping) >= self.MAX_REPORTED:
                        break
                if scanned >= self.MAX_ENTRIES or len(escaping) >= self.MAX_REPORTED:
                    break
        except OSError:
            pass

        if escaping:
            shown = "; ".join(f"{src} -> {dst}" for src, dst in escaping[:5])
            extra = f" (+{len(escaping) - 5} more)" if len(escaping) > 5 else ""
            findings.append(Finding(
                id="EW-FS-009",
                title=f"Symlinks in /var/log escape mount root ({len(escaping)})",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.FILESYSTEM,
                evidence=f"Escaping symlinks: {shown}{extra}",
                why_it_matters=(
                    "When /var/log is bind-mounted from the host into a pod, an "
                    "attacker who can write into it can plant a symlink targeting "
                    "host files (e.g. /etc/shadow). The kubelet log-reading "
                    "endpoint follows the symlink and exposes the target's "
                    "contents to any principal with pods/log permissions — a "
                    "host file disclosure and container escape primitive "
                    "documented by Palo Alto Unit 42."
                ),
                remediation=(
                    "Do not bind-mount /var/log into untrusted pods. If a log "
                    "collector requires it, use a subPath mount, run the "
                    "workload as a non-root user, and disable kubelet log "
                    "reading for that namespace via RBAC."
                ),
                references=[
                    "https://unit42.paloaltonetworks.com/container-escape-techniques/",
                    "https://github.com/kubernetes/kubernetes/issues/87773",
                ],
            ))

        return findings


@register_check
class WritableHostBindMountCheck(BaseCheck):
    """Detect writable host bind-mounts that enable SUID-binary planting.

    Palo Alto Unit 42 — *Container Escape Techniques*, technique #2
    ("Privilege Escalation Using SUID"). A container running as root with
    CAP_SETUID can create a SUID-root binary inside any directory that is
    bind-mounted from the host and writable from inside the container.
    When a host user later executes that binary, the SUID bit grants them
    UID 0 on the host — a full escape that needs no kernel exploit and no
    container runtime vulnerability.
    """

    name = "writable-host-bind-mount"
    description = "Checks for writable host bind-mounts (SUID-planting vector)"
    category = Category.FILESYSTEM

    EXPECTED_CONTAINER_PATHS = {
        "/", "/proc", "/sys", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm",
        "/dev/console", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
        "/dev/termination-log",
    }
    EXPECTED_PREFIXES = ("/proc/", "/sys/", "/dev/", "/run/secrets/")
    NON_BIND_FSTYPES = {
        "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "tmpfs",
        "overlay", "fuse.overlayfs", "ramfs", "squashfs", "binfmt_misc",
        "fusectl", "pstore", "tracefs", "debugfs", "configfs", "securityfs",
        "selinuxfs", "bpf", "rpc_pipefs", "nsfs", "autofs",
    }

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        mountinfo = self._read_file("/proc/1/mountinfo")
        if not mountinfo:
            return findings

        candidates: list[tuple[str, str, str]] = []
        for line in mountinfo.splitlines():
            parts = line.split()
            if len(parts) < 10 or "-" not in parts:
                continue
            try:
                sep = parts.index("-")
            except ValueError:
                continue
            if sep < 6 or sep + 2 >= len(parts):
                continue
            source_root = parts[3]
            mountpoint = parts[4]
            options = parts[5]
            fstype = parts[sep + 1]

            if fstype in self.NON_BIND_FSTYPES:
                continue
            if mountpoint in self.EXPECTED_CONTAINER_PATHS:
                continue
            if any(mountpoint.startswith(p) for p in self.EXPECTED_PREFIXES):
                continue

            opts = options.split(",")
            if "rw" not in opts:
                continue
            # A mount with `nosuid` can't be used to plant a SUID-root binary
            # that the host will honor — the kernel strips the SUID bit on
            # exec from a nosuid mount. Skip these entirely; they're not an
            # escape vector for the technique this check exists to catch.
            if "nosuid" in opts:
                continue
            # A bind mount of a host subpath shows up with a non-"/" source root.
            # Whole-disk bind mounts of host root are caught by EW-FS-002/EW-FS-007.
            if source_root == "/":
                continue
            if not self._is_writable(mountpoint):
                continue
            candidates.append((mountpoint, source_root, fstype))

        if not candidates:
            return findings

        running_as_root = os.getuid() == 0
        nnp_off = self._no_new_privs_disabled()

        if running_as_root and nnp_off:
            sev = Severity.HIGH
            posture = (
                "container is root and no_new_privs is disabled — a SUID binary "
                "planted here will be honored on the host's exec path"
            )
        elif running_as_root:
            sev = Severity.MEDIUM
            posture = (
                "container is root — SUID binaries can be planted, but "
                "no_new_privs may neutralize them depending on the host's "
                "exec context"
            )
        else:
            sev = Severity.LOW
            posture = (
                "container is non-root — SUID-planting is not directly "
                "possible today, but any escalation to UID 0 in the container "
                "would unlock it"
            )

        shown = "; ".join(
            f"{mp} (src_root={sr}, fstype={ft})" for mp, sr, ft in candidates[:5]
        )
        extra = f" (+{len(candidates) - 5} more)" if len(candidates) > 5 else ""

        findings.append(Finding(
            id="EW-FS-010",
            title=f"Writable host bind-mount ({len(candidates)}) — SUID-planting vector",
            severity=sev,
            confidence=Confidence.MEDIUM,
            category=Category.FILESYSTEM,
            evidence=f"{shown}{extra}; {posture}",
            why_it_matters=(
                "A writable directory shared between the container and the "
                "host lets a container-root attacker create a SUID-root binary "
                "that, when executed by any user on the host, grants them "
                "UID 0. This is the canonical Palo Alto Unit 42 SUID escape "
                "primitive: it requires only CAP_SETUID inside the container "
                "and a writable shared filesystem — no kernel exploit, no "
                "container runtime vulnerability."
            ),
            remediation=(
                "Mount shared host directories with the 'nosuid' option (and "
                "ideally 'noexec'), drop CAP_SETUID/CAP_SETGID, or run the pod "
                "as a non-root user with a user-namespace mapping so the SUID "
                "bit cannot be set with host-root semantics."
            ),
            references=[
                "https://unit42.paloaltonetworks.com/container-escape-techniques/",
                "https://man7.org/linux/man-pages/man8/mount.8.html",
            ],
        ))

        return findings

    def _no_new_privs_disabled(self) -> bool:
        status = self._read_file("/proc/1/status")
        if not status:
            return False
        match = re.search(r"NoNewPrivs:\s+(\d)", status)
        return match is not None and match.group(1) == "0"
