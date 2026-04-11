# EscapeWatch Check Reference

This document describes every security check in EscapeWatch, organized by category.

## Runtime Privileges

### EW-PRIV-001: Privileged Container Detected
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** Whether the container has all Linux capabilities enabled (privileged mode)
- **How it works:** Reads `/proc/1/status` CapEff field and checks for the full capability bitmask
- **Impact:** A privileged container has full access to host devices and can trivially escape to the host via device access, mount manipulation, or kernel module loading
- **Remediation:** Remove the `--privileged` flag. Grant only specific capabilities with `--cap-add`

### EW-PRIV-002: Critical Linux Capabilities Granted
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Presence of critical capabilities: `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_PTRACE`
- **How it works:** Parses the CapEff bitmask and matches against known dangerous capability bits
- **Impact:** These capabilities enable container escape via mount manipulation, kernel module loading, raw I/O, or process tracing
- **Remediation:** Drop unnecessary capabilities with `--cap-drop ALL --cap-add <needed>`

### EW-PRIV-003: Dangerous Linux Capabilities Granted
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **What it checks:** Non-critical but dangerous capabilities like `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`
- **Impact:** These capabilities expand the attack surface beyond the default Docker capability set
- **Remediation:** Drop unnecessary capabilities with `--cap-drop`

### EW-PRIV-004: Seccomp Disabled
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether seccomp syscall filtering is disabled (mode 0)
- **How it works:** Reads the `Seccomp` field from `/proc/1/status`
- **Impact:** Without seccomp, the container can invoke any syscall, increasing the kernel attack surface significantly
- **Remediation:** Use the default Docker seccomp profile or apply a custom profile

### EW-PRIV-005: Seccomp in Strict Mode
- **Severity:** INFO
- **Confidence:** HIGH
- **What it checks:** Whether seccomp is in strict mode (mode 1)
- **Impact:** Strict mode is very restrictive, allowing only read/write/exit/sigreturn

### EW-PRIV-006: AppArmor Unconfined
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Whether the AppArmor profile is "unconfined"
- **How it works:** Reads `/proc/1/attr/current`
- **Impact:** Without AppArmor, the container lacks mandatory access control restrictions
- **Remediation:** Apply the default Docker AppArmor profile or a custom profile

### EW-PRIV-007: SELinux Permissive
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Whether SELinux is in permissive mode
- **How it works:** Reads `/sys/fs/selinux/enforce`
- **Impact:** Permissive mode logs violations but does not enforce them
- **Remediation:** Set SELinux to enforcing mode

### EW-PRIV-008: Running as Root
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **What it checks:** Whether the current process runs as UID 0
- **Impact:** Root inside a container becomes root on the host if user namespaces are not in use
- **Remediation:** Add a `USER` directive to the Dockerfile

### EW-PRIV-009: no_new_privs Not Set
- **Severity:** LOW
- **Confidence:** MEDIUM
- **What it checks:** Whether the `NoNewPrivs` flag is set on PID 1
- **Impact:** Without this flag, processes can gain privileges through setuid binaries
- **Remediation:** Set `--security-opt no-new-privileges:true`

## Filesystem and Mounts

### EW-FS-001: Container Runtime Socket Exposed
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** Presence of Docker, containerd, or CRI-O sockets at standard paths
- **Impact:** Socket access allows full control over the container runtime, enabling escape and host compromise
- **Remediation:** Remove the socket mount. Use a read-only proxy if API access is needed

### EW-FS-002: Host Root Filesystem Mounted
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** Whether the host root filesystem is bind-mounted into the container
- **Impact:** Full host filesystem access allows reading secrets, modifying binaries, and escaping
- **Remediation:** Remove the mount. Use specific subpath mounts instead

### EW-FS-003: Sensitive Host Path Mounted
- **Severity:** HIGH/MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Mounts of sensitive paths: `/etc`, `/var/lib/docker`, `/var/lib/kubelet`, `/root`, `/home`, etc.
- **How it works:** Parses `/proc/mounts` and matches against known sensitive paths
- **Impact:** Exposes host configuration, credentials, or runtime data
- **Remediation:** Remove sensitive mounts or make them read-only

### EW-FS-004: Writable Cgroup Paths
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether cgroup directories are writable from inside the container
- **Impact:** Writable cgroups can be abused for container escape via release_agent manipulation
- **Remediation:** Mount cgroup filesystem as read-only

### EW-FS-005: Writable /proc/sys Entries
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Write access to dangerous `/proc/sys` entries: `core_pattern`, `modprobe`, `sysrq-trigger`
- **Impact:** Writable core_pattern or modprobe can be used for arbitrary code execution on the host
- **Remediation:** Ensure `/proc/sys` is mounted read-only

### EW-FS-006: Root Filesystem Writable
- **Severity:** LOW
- **Confidence:** HIGH
- **What it checks:** Whether the container root filesystem is mounted read-write
- **Impact:** Allows modification of container binaries and persistence of changes
- **Remediation:** Use the `--read-only` flag

### EW-FS-007: Block Device Mounted
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Direct block device mounts (`/dev/sda`, `/dev/vda`, `/dev/nvme*`, etc.)
- **Impact:** Direct device access allows reading/writing the host filesystem bypassing mount restrictions
- **Remediation:** Remove device mounts

### EW-FS-008: Cgroup v1 release_agent
- **Severity:** CRITICAL (writable) / LOW (read-only present)
- **Confidence:** HIGH / MEDIUM
- **What it checks:** Presence and writability of `/sys/fs/cgroup/*/release_agent` files
- **How it works:** Globs cgroup v1 hierarchies and tests `release_agent` writability
- **Impact:** A writable `release_agent` allows arbitrary command execution on the host as root when a cgroup empties (Felix Wilhelm / Trail of Bits technique, also CVE-2022-0492)
- **Remediation:** Mount the cgroup filesystem read-only, migrate to cgroup v2, or block cgroup writes via seccomp/AppArmor

### EW-FS-009: /var/log Symlink Escape
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Symlinks under `/var/log` whose targets point outside `/var/log`
- **How it works:** Walks `/var/log` (bounded depth/entry count), inspects each symlink with `lstat`, resolves the target relative to its parent and flags any that escape the directory
- **Impact:** When `/var/log` is bind-mounted from the host into a pod (common for log collectors), an attacker who can write into it can plant a symlink targeting host files (e.g. `/etc/shadow`). The kubelet log endpoint then dereferences the symlink and exposes the target's contents to anyone with `pods/log` permissions — host file disclosure and a container-escape primitive (Palo Alto Unit 42 — *Container Escape Techniques*, technique #4)
- **Remediation:** Do not bind-mount `/var/log` into untrusted pods. Use `subPath` mounts, run the workload as a non-root user, and restrict `pods/log` via RBAC

### EW-FS-010: Writable Host Bind-Mount (SUID-planting vector)
- **Severity:** HIGH (root + no_new_privs off) / MEDIUM (root) / LOW (non-root)
- **Confidence:** MEDIUM
- **What it checks:** Bind-mounts of host subpaths (`/proc/1/mountinfo` entries with non-`/` source root) that are mounted `rw` and writable from inside the container
- **How it works:** Parses `/proc/1/mountinfo`, filters out container-internal filesystems and standard paths (`/etc/resolv.conf`, `/proc`, `/sys`, `/dev`, …), then cross-references with the container's UID and `no_new_privs` flag to grade severity
- **Impact:** A container running as root with CAP_SETUID can plant a SUID-root binary in any writable host bind-mount. When a host user later executes that binary, the SUID bit grants them UID 0 on the host — a full escape with no kernel exploit (Palo Alto Unit 42 — *Container Escape Techniques*, technique #2)
- **Remediation:** Mount shared host directories with `nosuid` (and ideally `noexec`), drop `CAP_SETUID`/`CAP_SETGID`, or run the pod as a non-root user with a user-namespace mapping

## Namespaces

### EW-NS-001: Host PID Namespace Shared
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **What it checks:** Whether the container can see a large number of processes (host-like)
- **Impact:** Exposes all host processes, enabling inspection, signal sending, and ptrace attacks
- **Remediation:** Set `hostPID: false` or remove `--pid=host`

### EW-NS-002: Host Network Namespace Shared
- **Severity:** HIGH/MEDIUM
- **Confidence:** HIGH/LOW
- **What it checks:** Presence of host-like network interfaces (docker0 bridge, many interfaces)
- **Impact:** Exposes host network interfaces, allows binding to any port and traffic interception
- **Remediation:** Set `hostNetwork: false` or remove `--net=host`

### EW-NS-003: Host IPC Namespace Shared
- **Severity:** MEDIUM
- **Confidence:** LOW
- **What it checks:** Elevated number of shared memory entries in `/dev/shm`
- **Impact:** Allows access to shared memory segments of host processes
- **Remediation:** Set `hostIPC: false` or remove `--ipc=host`

## Kubernetes

### EW-K8S-001: Service Account Token Mounted
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **What it checks:** Presence of a service account token at the default mount path
- **Impact:** Token can authenticate to the Kubernetes API. If overprivileged, enables cluster-wide operations
- **Remediation:** Set `automountServiceAccountToken: false` unless needed

### EW-K8S-002: Service Account Token Decoded
- **Severity:** INFO
- **Confidence:** HIGH
- **What it checks:** Decodes JWT payload to reveal service account identity, issuer, and audience
- **Impact:** Reveals the scope and identity of the service account

### EW-K8S-003: Kubernetes API Server Reachable
- **Severity:** INFO
- **Confidence:** HIGH
- **What it checks:** TCP reachability of the API server from inside the pod
- **Impact:** API access combined with a token allows cluster interaction
- **Remediation:** Use `NetworkPolicy` to restrict API access

### EW-K8S-004: Kubeconfig File Found
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Presence of kubeconfig files at standard paths or `$KUBECONFIG`
- **Impact:** Kubeconfig may contain cluster admin credentials
- **Remediation:** Remove kubeconfig mounts

### EW-K8S-005: SelfSubjectRulesReview — Effective RBAC
- **Severity:** CRITICAL (cluster-admin equivalent) / HIGH (secret read, pod create, sensitive writes) / MEDIUM (wildcard verbs) / INFO (no findings)
- **Confidence:** HIGH (concrete privilege flags) / MEDIUM (wildcard heuristic)
- **What it checks:** The actual effective RBAC of the mounted service account
- **How it works:** When a SA token, CA cert, and `KUBERNETES_SERVICE_HOST` are present, POSTs a `SelfSubjectRulesReview` to `/apis/authorization.k8s.io/v1/selfsubjectrulesreview` using the SA bearer token (validated against the SA CA cert). Parses the returned `resourceRules` and flags wildcard verbs/resources, secret read access, pod-create rights, and write access to RBAC objects (`secrets`, `pods`, `pods/exec`, `clusterrolebindings`, `roles`, `serviceaccounts`, `nodes`, …)
- **Impact:** Overpermissive service accounts are the single most exploited entry vector after a pod compromise (Palo Alto Unit 42 — *Modern Kubernetes Threats*, T1528 + T1098.006). Cluster-admin equivalence trivializes full cluster takeover; secret read enables credential harvest and lateral movement; pod-create is functionally equivalent to node compromise unless Pod Security Admission blocks it
- **Remediation:** Bind a least-privilege Role to the ServiceAccount; never grant cluster-admin to workload SAs; replace wildcard verbs with explicit lists; enforce a Pod Security Standard `restricted` admission policy on the namespace

## Cloud and Metadata

### EW-CLOUD-001: Cloud Metadata Endpoint Reachable
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** TCP reachability of cloud metadata IPs (169.254.169.254, etc.)
- **Impact:** Metadata endpoints expose instance credentials, IAM roles, and configuration
- **Remediation:** Block with network policies or use IMDSv2

## Secrets Exposure

### EW-SECRET-001: Sensitive Environment Variables
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Environment variables with sensitive keywords (password, token, secret, etc.)
- **How it works:** Scans `os.environ` keys against a keyword list. Values are redacted in output
- **Impact:** Secrets in env vars are visible to all processes and may leak through logs
- **Remediation:** Use mounted secrets files or a secrets manager

### EW-SECRET-002: Secret Files Accessible
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Presence of known secret file paths (`/var/run/secrets`, SSH keys, AWS credentials, etc.)
- **Impact:** Mounted secrets may enable lateral movement
- **Remediation:** Minimize mounted secrets

### EW-SECRET-003: Secrets in Process Environments
- **Severity:** MEDIUM
- **Confidence:** LOW
- **What it checks:** Sensitive keywords in `/proc/*/environ` of other accessible processes
- **Impact:** Access to other processes' env vars can leak secrets from sidecars
- **Remediation:** Use `hostPID: false` and prefer file-based secrets

## Runtime Sockets and Services

### EW-SOCK-001: Runtime Socket Found
- **Severity:** CRITICAL/HIGH
- **Confidence:** HIGH
- **What it checks:** UNIX sockets matching known runtime patterns (Docker, containerd, CRI-O, kubelet)
- **How it works:** Walks `/var/run`, `/run`, `/tmp` for socket files and matches names
- **Impact:** Runtime socket access may enable container escape
- **Remediation:** Remove the socket mount

### EW-SOCK-002: Other UNIX Sockets
- **Severity:** INFO
- **Confidence:** LOW
- **What it checks:** UNIX sockets that don't match known runtime patterns
- **Impact:** Unknown sockets may expose management interfaces
- **Remediation:** Audit sockets accessible from the container

### EW-SOCK-003: Dangerous Management Port Open
- **Severity:** HIGH/MEDIUM
- **Confidence:** HIGH
- **What it checks:** Localhost ports associated with Docker (2375/2376), Kubelet (10250/10255), etcd (2379/2380), and Kubernetes API (6443/8080)
- **Impact:** Exposed management ports enable runtime control or cluster compromise
- **Remediation:** Restrict access with network policies and enable authentication/TLS
