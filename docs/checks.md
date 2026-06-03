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
- **What it checks:** Presence of critical capabilities: `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_BPF`
- **How it works:** Parses the CapEff bitmask and matches against known dangerous capability bits
- **Impact:** These capabilities enable container escape via mount manipulation, kernel module loading, raw I/O, process tracing, filesystem bypass, or eBPF verifier exploitation
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

### EW-PRIV-010: Dangerous Ambient Capabilities Set
- **Severity:** MEDIUM (dangerous caps) / LOW (non-dangerous caps)
- **Confidence:** HIGH
- **What it checks:** Whether `CapAmb` (ambient capabilities) is non-zero and includes dangerous capabilities
- **How it works:** Reads the `CapAmb` field from `/proc/1/status` and matches against the dangerous capability set
- **Impact:** Ambient capabilities are automatically inherited by child processes across `execve()` even for non-privileged executables. Any process spawned in the container inherits these capabilities without needing SUID bits or file capabilities
- **Remediation:** Remove ambient capabilities with `capsh --drop` or ensure the container spec does not set `ambientCapabilities`

### EW-PRIV-011: CAP_DAC_READ_SEARCH — Shocker Escape Vector
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether `CAP_DAC_READ_SEARCH` is in the effective capability set
- **How it works:** Reads CapEff from `/proc/1/status` and checks for the `cap_dac_read_search` bit
- **Impact:** Combined with `open_by_handle_at(2)` (the Shocker technique), this capability allows opening any file on the host filesystem by raw inode number, bypassing the container's mount namespace. An attacker can read or overwrite sensitive host files (`/etc/shadow`, SSH keys, kubeconfig, cloud credentials) without CAP_SYS_ADMIN or any kernel exploit
- **Remediation:** Drop `CAP_DAC_READ_SEARCH` with `--cap-drop CAP_DAC_READ_SEARCH`. Block `open_by_handle_at` via seccomp (denied by the default Docker seccomp profile)

### EW-PRIV-012: CAP_BPF — eBPF Verifier Bug Escape Vector
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **What it checks:** Whether `CAP_BPF` is in the effective capability set
- **How it works:** Reads CapEff from `/proc/1/status` and checks for the `cap_bpf` bit
- **Impact:** `CAP_BPF` (Linux 5.8+) grants loading eBPF programs without `CAP_SYS_ADMIN`. The eBPF verifier has a history of exploitable arithmetic/type-confusion bugs that have enabled kernel code execution from `CAP_BPF` alone. Additionally permits socket-filter interception of host traffic and, in certain helper contexts, writing to host process memory
- **Remediation:** Drop `CAP_BPF` unless strictly required. Block the `bpf()` syscall via seccomp. Set `kernel.unprivileged_bpf_disabled=2` on the host

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

### EW-FS-012: Unsafe sysctl Value
- **Severity:** HIGH / MEDIUM (per entry)
- **Confidence:** HIGH
- **What it checks:** Dangerous *values* of kernel sysctls readable from the container: `unprivileged_bpf_disabled=0`, `perf_event_paranoid=-1`, `kptr_restrict=0`
- **Impact:** Unsafe values enable unprivileged eBPF kernel attacks, Spectre-class side channels, and KASLR bypass for kernel ROP
- **Remediation:** Set safer values via `sysctl`, persist in `/etc/sysctl.conf`, and reload

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

### EW-FS-011: /proc/1/mem Writable — Direct Memory Injection
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** Whether `/proc/1/mem` is writable from inside the container
- **How it works:** Attempts to open `/proc/1/mem` with `O_WRONLY` and checks for success
- **Impact:** Write access to `/proc/1/mem` allows injecting arbitrary code into PID 1's address space without ptrace. An attacker can overwrite function pointers or executable pages to hijack control flow and execute arbitrary code in the init process context, achieving host compromise
- **Remediation:** Ensure seccomp blocks `ptrace` and direct `/proc/<pid>/mem` writes. Do not grant `CAP_SYS_PTRACE`

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

### EW-NS-004: Host UTS Namespace Shared
- **Severity:** LOW
- **Confidence:** MEDIUM
- **What it checks:** Whether the container shares the host's UTS (hostname) namespace
- **How it works:** Compares the UTS namespace inode of PID 1 and PID 2 (kthreadd)
- **Impact:** Sharing the UTS namespace allows a container to change the host's hostname and NIS domain name, potentially disrupting host services or aiding social engineering/log confusion attacks
- **Remediation:** Set `hostIPC: false` — UTS namespace sharing is controlled by `hostIPC` in Kubernetes pod specs; in Docker use `--uts=host` only when necessary

### EW-NS-005: User Namespace Not in Use
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **What it checks:** Whether UID 0 inside the container maps to UID 0 on the host (no user namespace remapping)
- **How it works:** Reads `/proc/1/uid_map` to check if container UID 0 maps to host UID 0
- **Impact:** Without user namespace remapping, root inside the container is root on the host. Any container escape automatically grants host root. With remapping, container root maps to an unprivileged host UID, limiting escape impact
- **Remediation:** Enable rootless container mode or configure user namespace remapping (`userns-remap` in Docker, `RunAsUser` with a high UID in Kubernetes pod security contexts)

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
- **Finding IDs:** Distinct privileges that can co-occur are reported under dedicated IDs so each is independently triageable in SARIF: `EW-K8S-005` (cluster-admin equivalent / INFO summary), `EW-K8S-005-SECRETS-READ`, `EW-K8S-005-PODS-CREATE`, `EW-K8S-005-SENSITIVE-WRITE`, `EW-K8S-005-WILDCARD-VERBS`
- **What it checks:** The actual effective RBAC of the mounted service account
- **How it works:** When a SA token, CA cert, and `KUBERNETES_SERVICE_HOST` are present, POSTs a `SelfSubjectRulesReview` to `/apis/authorization.k8s.io/v1/selfsubjectrulesreview` using the SA bearer token (validated against the SA CA cert). Parses the returned `resourceRules` and flags wildcard verbs/resources, secret read access, pod-create rights, and write access to RBAC objects (`secrets`, `pods`, `pods/exec`, `clusterrolebindings`, `roles`, `serviceaccounts`, `nodes`, …)
- **Impact:** Overpermissive service accounts are the single most exploited entry vector after a pod compromise (Palo Alto Unit 42 — *Modern Kubernetes Threats*, T1528 + T1098.006). Cluster-admin equivalence trivializes full cluster takeover; secret read enables credential harvest and lateral movement; pod-create is functionally equivalent to node compromise unless Pod Security Admission blocks it
- **Remediation:** Bind a least-privilege Role to the ServiceAccount; never grant cluster-admin to workload SAs; replace wildcard verbs with explicit lists; enforce a Pod Security Standard `restricted` admission policy on the namespace

### EW-K8S-006: Admission Webhook Failure Policy Open
- **Severity:** HIGH/MEDIUM
- **Confidence:** MEDIUM
- **What it checks:** Whether validating or mutating admission webhooks are configured with `failurePolicy: Ignore` or overly-broad selectors
- **How it works:** Queries the Kubernetes API for `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` objects and audits their `failurePolicy` and `namespaceSelector`/`objectSelector` fields
- **Impact:** Webhooks with `failurePolicy: Ignore` silently pass all requests when the webhook backend is unavailable. An attacker who can disrupt the webhook backend (or exploit a gap in selector coverage) can bypass Pod Security admission, OPA policies, or other admission controls, allowing deployment of privileged pods
- **Remediation:** Set `failurePolicy: Fail` for security-critical webhooks. Ensure `namespaceSelector` covers all namespaces where policy enforcement is required

### EW-K8S-007: Dangerous Node/Cluster-Level RBAC Rights
- **Severity:** HIGH/CRITICAL
- **Confidence:** HIGH
- **What it checks:** Whether the service account has node-level rights such as `nodes/proxy`, `nodes/exec`, or write access to cluster-scoped resources
- **Impact:** Node proxy access allows proxying requests to the Kubelet API, enabling arbitrary command execution on any node. Write access to `clusterrolebindings` allows privilege escalation by granting cluster-admin to any principal
- **Remediation:** Remove cluster-scoped write rights from workload service accounts. Use namespace-scoped roles where possible

### EW-K8S-008: Service Account Can Write pods/ephemeralcontainers
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether the service account has write access to the `pods/ephemeralcontainers` subresource
- **Impact:** The `pods/ephemeralcontainers` subresource allows injecting an ephemeral container into any running pod without Pod Security Admission validation. An attacker with this right can inject a privileged container into any pod in the namespace, bypassing all securityContext restrictions
- **Remediation:** Remove `pods/ephemeralcontainers` write rights from service accounts. Apply Pod Security Standards at the `restricted` level to limit container security contexts

## Cloud and Metadata

### EW-CLOUD-001: Cloud Metadata Endpoint Reachable
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** TCP reachability of cloud metadata IPs (169.254.169.254, etc.)
- **Impact:** Metadata endpoints expose instance credentials, IAM roles, and configuration
- **Remediation:** Block with network policies or use IMDSv2

### EW-CLOUD-002: AWS IMDSv1 Active / IMDSv2 Status
- **Severity:** HIGH (IMDSv1 active) / INFO (IMDSv2 enforced)
- **Confidence:** HIGH
- **What it checks:** Whether the AWS Instance Metadata Service responds to IMDSv1 (token-free) requests
- **How it works:** Sends a GET request to `http://169.254.169.254/latest/meta-data/` without an IMDSv2 token; a 200 response indicates IMDSv1 is active
- **Impact:** IMDSv1 allows any process in the container to retrieve the instance's IAM role credentials via a single unauthenticated HTTP request, enabling lateral movement to AWS APIs with the instance's permissions. SSRF vulnerabilities in applications can also be leveraged to reach IMDSv1 without direct network access
- **Remediation:** Enforce IMDSv2 by setting `HttpTokens: required` on the instance (`aws ec2 modify-instance-metadata-options`). Use IAM Roles for Service Accounts (IRSA) in EKS instead of instance-level credentials

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

### EW-SOCK-004: Dangerous Abstract Unix Socket Visible
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **What it checks:** Abstract Unix domain sockets in `/proc/net/unix` matching known container runtime patterns (`containerd-shim`, `dockerd`, `podman`, etc.)
- **How it works:** Reads `/proc/net/unix`, filters for entries starting with `@` (abstract socket encoding), and matches names against known dangerous runtime socket patterns
- **Impact:** Abstract sockets are not filesystem-visible and are accessible to any process sharing the same network namespace. If the container shares the host network namespace (`hostNetwork: true`), it can connect to the containerd-shim API abstract socket and instruct the runtime to spawn arbitrary privileged containers (CVE-2020-15257)
- **Remediation:** Do not run containers with `hostNetwork: true` unless strictly required. Upgrade containerd to >= 1.3.9 / 1.4.3 which moved the shim socket out of the root network namespace

## Runtime Versions

### EW-RT-001: runc < 1.1.12 — CVE-2024-21626 (Working-Directory Breakout)
- **Severity:** CRITICAL
- **Confidence:** HIGH (version found) / MEDIUM (binary found, version unreadable)
- **What it checks:** Whether the runc binary version is below 1.1.12
- **How it works:** Scans `/proc/*/exe` symlinks and common binary paths for the runc binary, then reads the version string from the binary or cmdline
- **Impact:** CVE-2024-21626 (CVSS 8.6) — runc leaks a file descriptor pointing to the host cgroup filesystem. Setting `WORKDIR` to `/proc/self/fd/7` in a Dockerfile causes the container process's working directory to point directly at the host filesystem, bypassing the container chroot. An attacker can overwrite host binaries to achieve persistent root code execution. Requires only the ability to run a container with a custom image
- **Remediation:** Upgrade runc to >= 1.1.12, Docker to >= 25.0.2 or 24.0.9, containerd to >= 1.6.28 or 1.7.13

### EW-RT-002: runc 2025 Trinity — CVE-2025-31133 / 52565 / 52881
- **Severity:** CRITICAL
- **Confidence:** HIGH (version found) / MEDIUM (binary found, version unreadable)
- **What it checks:** Whether runc is in a vulnerable range: 1.2.0–1.2.7, 1.3.0–1.3.2, or 1.4.0-rc.0–rc.2
- **Impact:** Three race-condition vulnerabilities in runc's mount handling. CVE-2025-31133: replacing `/dev/null` with a symlink tricks runc into bind-mounting an attacker-controlled path read-write, enabling writes to `/proc/sys/kernel/core_pattern`. CVE-2025-52565: race during `/dev/pts` mount grants write access to protected procfs entries. CVE-2025-52881: procfs write redirect via symlinks in shared tmpfs. All enable host shell execution
- **Remediation:** Upgrade runc to 1.2.8+, 1.3.3+, or 1.4.0-rc.3+

### EW-RT-003: containerd < 1.3.9 / 1.4.3 — CVE-2020-15257 (Abstract Socket Abuse)
- **Severity:** CRITICAL (with hostNetwork) / HIGH
- **Confidence:** HIGH (version found) / LOW (binary found, version unreadable)
- **What it checks:** Whether containerd is in vulnerable ranges: 1.3.0–1.3.8 or 1.4.0–1.4.2
- **Impact:** The containerd-shim API is exposed over an abstract Unix domain socket in the root network namespace. A container running with `hostNetwork: true` and UID 0 can connect to the shim API and spawn arbitrary containers with any security configuration, including privileged containers with host mounts
- **Remediation:** Upgrade containerd to >= 1.3.9 or >= 1.4.3. Never run containers with `hostNetwork: true` unless strictly required

### EW-RT-004: CRI-O < patched — CVE-2022-0811 (cr8escape)
- **Severity:** CRITICAL
- **Confidence:** HIGH (version found) / MEDIUM (detected, version unreadable)
- **What it checks:** Whether CRI-O is in vulnerable ranges: 1.19–1.23 (before individual patch versions)
- **Impact:** CVE-2022-0811 (CVSS 8.8, cr8escape) — CRI-O's `pinns` utility sets kernel parameters from pod sysctl annotations without sanitizing special characters. A Kubernetes user with pod deployment rights can inject arbitrary sysctl values including `kernel.core_pattern`, causing any core dump to execute the attacker's binary as root on the host
- **Remediation:** Upgrade CRI-O to a patched version. Enforce PodSecurity `restricted` admission policy to block pods with unsafe sysctl annotations

### EW-RT-005: BuildKit < 0.12.5 — Leaky Vessels (CVE-2024-23651/52/53)
- **Severity:** HIGH
- **Confidence:** HIGH (version found) / MEDIUM (detected, version unreadable)
- **What it checks:** Whether BuildKit is below version 0.12.5
- **Impact:** Three Leaky Vessels vulnerabilities in BuildKit's build pipeline. CVE-2024-23651: TOCTOU race on mount cache grants read/write access to host filesystem paths. CVE-2024-23652: symlink swap during container teardown causes BuildKit to delete arbitrary host files. CVE-2024-23653: missing authorization check allows running build containers with `--privileged` without the required entitlement. All exploitable via malicious Dockerfile or base image
- **Remediation:** Upgrade BuildKit to >= 0.12.5. For Docker Desktop: upgrade to >= 4.28.0

### EW-RT-006: runc < 1.0.0-rc7 — CVE-2019-5736 (/proc/self/exe Overwrite)
- **Severity:** CRITICAL
- **Confidence:** HIGH (version found) / MEDIUM (binary found, version unreadable)
- **What it checks:** Whether the runc binary version is below 1.0.0-rc7
- **Impact:** CVE-2019-5736 (CVSS 8.6) — a malicious container can overwrite the runc binary on the host by exploiting a race between container process startup and runc's access to `/proc/self/exe`. The next container start on any container on the host executes the attacker's binary as root. Requires only the ability to run a container with a custom entrypoint
- **Remediation:** Upgrade runc to >= 1.0.0-rc7. For Docker: upgrade to >= 18.09.2

### EW-RT-007: runc < 1.0.1 — CVE-2021-30465 (Symlink-Exchange Mount Attack)
- **Severity:** HIGH
- **Confidence:** HIGH (version found) / MEDIUM (binary found, version unreadable)
- **What it checks:** Whether the runc binary version is below 1.0.1
- **Impact:** CVE-2021-30465 (CVSS 8.2) — a TOCTOU race in runc's volume mount handling. A malicious container image can swap a directory with a symlink during the window between path validation and mount time, causing runc to bind-mount an arbitrary host directory (e.g. `/etc`, `/var/lib/kubelet`) into the container. Requires only the ability to start a container with a bind-mount
- **Remediation:** Upgrade runc to >= 1.0.1. For Docker: upgrade to >= 20.10.6

## Kernel Vulnerabilities

### EW-KERN-001: CVE-2022-0847 — Dirty Pipe
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether the kernel version falls in the Dirty Pipe vulnerable range (5.8–5.16.10)
- **How it works:** Reads the kernel version from `EnvironmentInfo.kernel_version` or `/proc/version` and parses the version triple
- **Impact:** CVE-2022-0847 allows any local process — including an unprivileged process inside a container — to overwrite the content of read-only memory-mapped files backed by the kernel page cache. By overwriting a SUID binary (e.g. `/bin/su`) with shellcode, an unprivileged user gains UID 0 inside the container namespace. Combined with escape vectors in EW-FS-* or EW-NS-*, this enables full host compromise. Unlike Dirty COW, exploitation is deterministic and requires no race condition
- **Patched in:** 5.10.102, 5.15.25, 5.16.11, 5.17+
- **Remediation:** Upgrade the host kernel to >= 5.10.102, 5.15.25, 5.16.11, or 5.17

### EW-KERN-002: CVE-2023-0386 / CVE-2023-2640 — GameOver(lay)
- **Severity:** HIGH
- **Confidence:** HIGH (Ubuntu) / MEDIUM (mainline)
- **What it checks:** Whether the kernel is vulnerable to GameOver(lay) OverlayFS privilege escalation
- **How it works:** Checks kernel version (5.11–6.1 for mainline CVE-2023-0386; Ubuntu-specific for CVE-2023-2640/32629), overlay mount status in `/proc/self/mountinfo`, and `max_user_namespaces` sysctl
- **Impact:** OverlayFS copy-up logic fails to verify UID/GID namespace mappings when copying files with SUID bits or capability xattrs from the lower layer. An unprivileged container user can create a crafted overlay lower directory with a SUID-root binary, trigger copy-up, and execute it to gain UID 0 inside the container. Container root then enables all classical escape vectors
- **Patched in:** Ubuntu: USN-6250-1 and USN-6252-1. Mainline: >= 6.2
- **Remediation:** Apply kernel updates. Temporary: set `user.max_user_namespaces=0` (breaks rootless containers)

### EW-KERN-003: Unprivileged eBPF Available
- **Severity:** HIGH (disabled=0) / INFO (disabled=1)
- **Confidence:** HIGH
- **What it checks:** The value of `/proc/sys/kernel/unprivileged_bpf_disabled`
- **Impact:** When set to 0, any unprivileged process inside the container can load eBPF programs (socket filters, tracepoints, kprobes) without capabilities. eBPF programs using `bpf_probe_write_user()` can write to host process memory, and socket programs can intercept host network traffic
- **Remediation:** Set `kernel.unprivileged_bpf_disabled=1` or `2` via sysctl. Value 2 is recommended for production and cannot be changed at runtime without a reboot

### EW-KERN-004: CVE-2023-6817 / CVE-2024-0582 — io_uring UAF
- **Severity:** HIGH
- **Confidence:** HIGH
- **What it checks:** Whether the kernel version falls in the io_uring UAF vulnerable range (6.4.0–6.6.13)
- **How it works:** Reads the kernel version and checks against the vulnerable range
- **Impact:** Two use-after-free vulnerabilities in the io_uring subsystem. CVE-2023-6817: UAF in registered-buffer management allows reading and writing freed kernel memory. CVE-2024-0582: UAF in the buffer-ring implementation (`IORING_REGISTER_PBUF_RING`) allows kernel heap corruption and code execution. Both are exploitable without any special capabilities from within a container that has access to the `io_uring` syscall. Public PoC exists for CVE-2024-0582. A successful exploit grants the container process root on the host kernel, defeating all namespace isolation
- **Patched in:** CVE-2023-6817: 6.6.3. CVE-2024-0582: 6.6.14
- **Remediation:** Upgrade the host kernel to >= 6.6.14. Temporary: block `io_uring_setup`, `io_uring_enter`, and `io_uring_register` via seccomp (denied by the default Docker seccomp profile)

## Attack Chains

### EW-CHAIN-001: CAP_SYS_PTRACE + hostPID — Process Injection Chain
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** The simultaneous presence of `CAP_SYS_PTRACE` in `CapEff` AND visibility of kernel threads in `/proc` (indicating host PID namespace)
- **How it works:** Reads CapEff from `/proc/1/status`, checks for `cap_sys_ptrace`, then scans `/proc` for kernel thread processes (empty cmdline + known kernel comm names) as a definitive host-PID indicator
- **Impact:** This combination is a complete, trivially-exploitable container escape via ptrace process injection. An attacker can enumerate all host processes, select a high-privilege target (systemd, sshd, kubelet), attach with `ptrace(PTRACE_ATTACH)`, write shellcode via `PTRACE_POKEDATA`, and redirect execution with `PTRACE_SETREGS`. The shellcode runs with the target's UID and capabilities — typically root on the host. Individually CAP_SYS_PTRACE and hostPID each warrant HIGH severity; together they form a one-step, no-exploit escape
- **Remediation:** Remove `CAP_SYS_PTRACE` (`--cap-drop CAP_SYS_PTRACE`) and set `hostPID: false`

### EW-CHAIN-002: CAP_SYS_ADMIN + cgroup v1 release_agent — Full Escape Chain
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **What it checks:** The simultaneous presence of `CAP_SYS_ADMIN`, cgroup v1 in use (no cgroup v2 controller file), and writable `release_agent` files
- **How it works:** Reads CapEff, checks for `cap_sys_admin`, verifies cgroup v1 is mounted via `/proc/mounts`, and globs `/sys/fs/cgroup/*/release_agent`
- **Impact:** This is a complete, one-step container escape. With CAP_SYS_ADMIN and a writable cgroup v1 `release_agent`, an attacker writes an arbitrary script path to the release_agent, enables `notify_on_release`, and triggers a cgroup release by killing the last process in a child cgroup. The kernel executes the release_agent script as root in the host's initial namespace. This technique has been public since 2019 and is reliably exploitable on any kernel with cgroup v1 and these preconditions
- **Remediation:** Do not grant `CAP_SYS_ADMIN`. Migrate to cgroup v2. Mount `/sys/fs/cgroup` read-only as an interim measure

### EW-CHAIN-003: hostNetwork + UID 0 — CVE-2020-15257 Abstract Socket Chain
- **Severity:** CRITICAL
- **Confidence:** HIGH (shim socket confirmed in /proc/net/unix) / MEDIUM (conditions met but socket not visible)
- **What it checks:** The combination of host network namespace sharing (confirmed via PID 1/2 net namespace inode comparison), running as UID 0, and optionally the containerd-shim abstract socket visible in `/proc/net/unix`
- **Impact:** The containerd-shim API is exposed over an abstract Unix domain socket in the root network namespace. Abstract sockets are accessible to any process sharing the network namespace. With `hostNetwork: true` and UID 0, an attacker can connect to the shim socket using the TTRPC protocol and issue container management commands, including spawning a new privileged container with a host root bind-mount. Achieves full host compromise without any kernel exploit
- **Remediation:** Upgrade containerd to >= 1.3.9 or >= 1.4.3. Set `hostNetwork: false`. Never run workloads as UID 0
