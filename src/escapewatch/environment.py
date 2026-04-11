from __future__ import annotations

import os
import platform
import re
from pathlib import Path

from escapewatch.models import EnvironmentInfo


def detect_environment() -> EnvironmentInfo:
    """Detect the current execution environment."""
    env = EnvironmentInfo()

    env.kernel_version = platform.release()
    env.hostname = platform.node()

    _detect_container(env)
    _detect_cgroup_version(env)
    _detect_init_process(env)
    _detect_namespaces(env)
    _detect_runtime(env)
    _detect_rootless(env)

    if not env.is_container:
        env.is_host = True

    return env


def _detect_container(env: EnvironmentInfo) -> None:
    """Detect if running inside a container."""
    # Check /.dockerenv (Docker)
    if Path("/.dockerenv").exists():
        env.is_container = True
        env.is_docker = True
        env.runtime_hints.append("/.dockerenv exists")

    # Check /run/.containerenv (Podman / Buildah)
    if Path("/run/.containerenv").exists():
        env.is_container = True
        env.runtime_hints.append("/run/.containerenv exists (Podman/Buildah)")

    # Check cgroup for container IDs
    cgroup_path = Path("/proc/1/cgroup")
    if cgroup_path.exists():
        try:
            text = cgroup_path.read_text()
            if "docker" in text:
                env.is_container = True
                env.is_docker = True
                env.runtime_hints.append("docker found in /proc/1/cgroup")
            if "containerd" in text or "cri-containerd" in text:
                env.is_container = True
                env.is_containerd = True
                env.runtime_hints.append("containerd found in /proc/1/cgroup")
            if "kubepods" in text:
                env.is_container = True
                env.is_kubernetes = True
                env.runtime_hints.append("kubepods found in /proc/1/cgroup")
            # cgroup v2 with container runtimes often uses a scoped path
            if "scope" in text and ("/docker-" in text or "/cri-" in text):
                env.is_container = True
                env.runtime_hints.append("container scope in cgroup v2 path")
            # Extract container ID (64-char hex)
            match = re.search(r"[0-9a-f]{64}", text)
            if match:
                env.container_id = match.group(0)
        except OSError:
            pass

    # Kubernetes detection via service account
    if Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists():
        env.is_kubernetes = True
        env.is_container = True
        env.runtime_hints.append("Kubernetes service account token found")

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        env.is_kubernetes = True
        env.is_container = True
        env.runtime_hints.append("KUBERNETES_SERVICE_HOST set")

    # PID namespace isolation check: on a host, PID 1 is init/systemd
    # whose PID ns matches PID 2 (kthreadd). In a container, PID 1 has
    # its own PID ns and PID 2 is usually not visible at all. If /proc/2
    # doesn't exist, it's a strong container indicator.
    if not env.is_container and not Path("/proc/2/comm").exists():
        env.is_container = True
        env.runtime_hints.append("PID 2 not visible (PID namespace isolation)")

    # Check for container-like init
    sched_path = Path("/proc/1/sched")
    if sched_path.exists():
        try:
            first_line = sched_path.read_text().splitlines()[0]
            if "bash" in first_line or "sh" in first_line:
                env.is_container = True
                env.runtime_hints.append("PID 1 is a shell (container-like)")
        except (OSError, IndexError):
            pass


def _detect_cgroup_version(env: EnvironmentInfo) -> None:
    """Detect cgroup v1 or v2."""
    mounts_path = Path("/proc/mounts")
    if mounts_path.exists():
        try:
            text = mounts_path.read_text()
            if "cgroup2" in text:
                env.cgroup_version = "v2"
            elif "cgroup" in text:
                env.cgroup_version = "v1"
        except OSError:
            pass

    if not env.cgroup_version and Path("/sys/fs/cgroup/cgroup.controllers").exists():
        env.cgroup_version = "v2"
    elif not env.cgroup_version and Path("/sys/fs/cgroup").is_dir():
        env.cgroup_version = "v1"


def _detect_init_process(env: EnvironmentInfo) -> None:
    """Identify PID 1 process."""
    comm_path = Path("/proc/1/comm")
    if comm_path.exists():
        try:
            env.init_process = comm_path.read_text().strip()
        except OSError:
            pass


def _detect_namespaces(env: EnvironmentInfo) -> None:
    """Collect namespace inode IDs for PID 1."""
    ns_dir = Path("/proc/1/ns")
    try:
        if ns_dir.is_dir():
            for ns_link in ns_dir.iterdir():
                try:
                    target = os.readlink(str(ns_link))
                    env.namespace_ids[ns_link.name] = target
                except OSError:
                    pass
    except OSError:
        pass


def _detect_runtime(env: EnvironmentInfo) -> None:
    """Additional runtime detection via environment."""
    if os.environ.get("container") == "docker":
        env.is_docker = True
        env.runtime_hints.append("container=docker in env")
    if os.environ.get("container") == "containerd":
        env.is_containerd = True
        env.runtime_hints.append("container=containerd in env")


def _detect_rootless(env: EnvironmentInfo) -> None:
    """Detect rootless container indicators.

    "Rootless" in the container context means the container runtime itself
    runs without real root on the host — not merely that the process
    inside the container has a non-zero UID. The definitive signal is
    user-namespace UID remapping: the container's UID-0 maps to a non-zero
    UID on the host, visible in /proc/1/uid_map.
    """
    # Check for user namespace remapping first — this is the canonical
    # rootless indicator and works regardless of the UID inside the container.
    uid_map = Path("/proc/1/uid_map")
    if uid_map.exists():
        try:
            text = uid_map.read_text().strip()
            # In a user namespace remap, the mapping won't be identity "0 0 4294967295"
            parts = text.split()
            if len(parts) >= 3 and parts[0] == "0" and parts[1] != "0":
                env.is_rootless = True
                env.runtime_hints.append("User namespace UID remapping detected")
                return
        except OSError:
            pass

    # If we're in a container and running as non-root *without* user-ns
    # remapping, that's "non-root" but not "rootless runtime". Only note
    # it as a hint — don't set is_rootless which implies the runtime
    # itself is unprivileged on the host.
    if env.is_container and os.getuid() != 0:
        env.runtime_hints.append("Running as non-root UID inside container")
