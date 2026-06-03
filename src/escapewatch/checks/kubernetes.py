from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from escapewatch.checks.base import BaseCheck, register_check
from escapewatch.models import Category, Confidence, Finding, Severity

SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_NAMESPACE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def decode_jwt_payload(token: str) -> dict | None:
    """Decode JWT payload without verification (for local inspection only)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        # Add padding
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None


@register_check
class ServiceAccountTokenCheck(BaseCheck):
    """Check for mounted Kubernetes service account token."""

    name = "k8s-service-account-token"
    description = "Checks for mounted Kubernetes service account tokens"
    category = Category.KUBERNETES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        token_content = self._read_file(SA_TOKEN_PATH)
        if not token_content:
            return findings

        findings.append(Finding(
            id="EW-K8S-001",
            title="Kubernetes service account token mounted",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=Category.KUBERNETES,
            evidence="Service account token found at default mount path",
            why_it_matters=(
                "A mounted service account token can be used to authenticate to "
                "the Kubernetes API server. If overprivileged, it may allow "
                "cluster-wide operations."
            ),
            remediation=(
                "Set automountServiceAccountToken: false unless API access is needed. "
                "Use a dedicated service account with minimal RBAC."
            ),
            references=[
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
            ],
        ))

        # Decode and inspect token claims
        payload = decode_jwt_payload(token_content)
        if payload:
            sa_name = payload.get("sub", "unknown")
            audiences = payload.get("aud", [])
            issuer = payload.get("iss", "unknown")

            evidence_parts = [f"Subject: {sa_name}", f"Issuer: {issuer}"]
            if audiences:
                evidence_parts.append(
                    f"Audiences: {audiences if isinstance(audiences, list) else [audiences]}"
                )

            findings.append(Finding(
                id="EW-K8S-002",
                title="Service account token decoded",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category=Category.KUBERNETES,
                evidence="; ".join(evidence_parts),
                why_it_matters="Token claims reveal the service account identity and scope.",
                remediation="Ensure this service account has minimal RBAC permissions.",
                references=[],
            ))

        return findings


@register_check
class KubeAPIReachabilityCheck(BaseCheck):
    """Check if the Kubernetes API server is reachable."""

    name = "k8s-api-reachability"
    description = "Checks Kubernetes API server reachability"
    category = Category.KUBERNETES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        api_host = os.environ.get("KUBERNETES_SERVICE_HOST")
        api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")

        if not api_host:
            return findings

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((api_host, int(api_port)))
            sock.close()

            if result == 0:
                findings.append(Finding(
                    id="EW-K8S-003",
                    title="Kubernetes API server reachable",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    category=Category.KUBERNETES,
                    evidence=f"API server at {api_host}:{api_port} is reachable",
                    why_it_matters=(
                        "API server reachability combined with a service account token "
                        "means the pod can interact with the Kubernetes API."
                    ),
                    remediation=(
                        "Use NetworkPolicy to restrict API server access from pods "
                        "that don't need it."
                    ),
                    references=[],
                ))
        except (OSError, ValueError):
            pass

        return findings


@register_check
class KubeconfigCheck(BaseCheck):
    """Check for mounted kubeconfig files."""

    name = "k8s-kubeconfig"
    description = "Checks for mounted kubeconfig files"
    category = Category.KUBERNETES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        kubeconfig_paths = [
            os.environ.get("KUBECONFIG", ""),
            os.path.expanduser("~/.kube/config"),
            "/etc/kubernetes/admin.conf",
            "/etc/kubernetes/kubelet.conf",
        ]

        for kc_path in kubeconfig_paths:
            if kc_path and self._path_exists(kc_path):
                findings.append(Finding(
                    id="EW-K8S-004",
                    title=f"Kubeconfig file found: {kc_path}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.KUBERNETES,
                    evidence=f"Kubeconfig at {kc_path}",
                    why_it_matters=(
                        "A kubeconfig file may contain cluster credentials that allow "
                        "full cluster administration."
                    ),
                    remediation="Remove kubeconfig mounts from the container.",
                    references=[],
                ))

        return findings


@register_check
class SelfSubjectRulesReviewCheck(BaseCheck):
    """Enumerate the service account's effective RBAC via SelfSubjectRulesReview.

    Palo Alto Unit 42 — *Modern Kubernetes Threats* lists overpermissive
    service accounts as the single most exploited entry vector after a
    pod compromise (T1528 + T1098.006). This check actively asks the API
    server "what can I do?" using the mounted SA token, then flags
    cluster-admin equivalence, secret read access, pod-create rights,
    and write access to RBAC objects.
    """

    name = "k8s-selfsubject-rules"
    description = "Queries SelfSubjectRulesReview to enumerate effective RBAC"
    category = Category.KUBERNETES

    HIGHLY_SENSITIVE_RESOURCES = {
        "secrets", "pods", "pods/exec", "pods/attach", "pods/ephemeralcontainers",
        "deployments", "daemonsets", "statefulsets", "clusterrolebindings",
        "rolebindings", "clusterroles", "roles", "serviceaccounts", "nodes",
        "nodes/proxy",
    }
    READ_DANGEROUS_RESOURCES = {"nodes/proxy", "nodes/log"}
    WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "*"}
    READ_VERBS = {"get", "list", "watch", "*"}

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        token = self._read_file(SA_TOKEN_PATH)
        if not token:
            return findings
        token = token.strip()

        api_host = os.environ.get("KUBERNETES_SERVICE_HOST")
        api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not api_host:
            return findings

        namespace = (self._read_file(SA_NAMESPACE_PATH) or "default").strip()

        response = self._post_rules_review(api_host, api_port, token, namespace)
        if not response:
            return findings

        status = response.get("status", {}) if isinstance(response, dict) else {}
        resource_rules = status.get("resourceRules", []) or []
        non_resource_rules = status.get("nonResourceRules", []) or []
        incomplete = status.get("incomplete", False)
        eval_error = status.get("evaluationError", "") or ""

        wildcard_all = False
        wildcard_resources: list[str] = []
        sensitive_writes: list[str] = []
        can_create_pods = False
        can_read_secrets = False
        nodes_proxy_access: list[str] = []
        nodes_proxy_verbs: set[str] = set()
        ephemeral_writes: list[str] = []

        for rule in resource_rules:
            verbs = set(rule.get("verbs", []) or [])
            api_groups = set(rule.get("apiGroups", []) or [""])
            resources = set(rule.get("resources", []) or [])

            if "*" in verbs and "*" in resources and "*" in api_groups:
                wildcard_all = True
            if "*" in verbs:
                for r in resources:
                    if r != "*":
                        wildcard_resources.append(r)
            for r in resources:
                if r in self.READ_DANGEROUS_RESOURCES:
                    matched = verbs & (self.READ_VERBS | self.WRITE_VERBS)
                    if matched:
                        nodes_proxy_access.append(r)
                        nodes_proxy_verbs |= matched
                if r in self.HIGHLY_SENSITIVE_RESOURCES:
                    if verbs & self.WRITE_VERBS:
                        sensitive_writes.append(r)
                    if r == "secrets" and (verbs & self.READ_VERBS):
                        can_read_secrets = True
                    if r in ("pods", "pods/exec") and (verbs & {"create", "*"}):
                        can_create_pods = True
                    if r == "pods/ephemeralcontainers" and (verbs & {"create", "update", "*"}):
                        ephemeral_writes.append(r)

        if nodes_proxy_access:
            unique_resources = sorted(set(nodes_proxy_access))
            findings.append(Finding(
                id="EW-K8S-006",
                title=(
                    f"Service account has GET on {', '.join(unique_resources)} "
                    "— this is RCE, not read-only"
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.KUBERNETES,
                evidence=(
                    f"Verbs {sorted(nodes_proxy_verbs)} on {unique_resources} "
                    f"in namespace '{namespace}'"
                ),
                why_it_matters=(
                    "nodes/proxy proxies requests directly to the Kubelet API. "
                    "The Kubelet supports WebSocket exec endpoints over HTTP GET, "
                    "meaning `get` permission here allows running arbitrary commands "
                    "in any pod on the node — bypassing Kubernetes audit logging and "
                    "admission control entirely."
                ),
                remediation=(
                    "Remove get/list/watch on nodes/proxy and nodes/log from this SA's "
                    "Role. Use the Kubernetes exec API (pods/exec) with audit logging "
                    "instead of direct Kubelet proxy access."
                ),
                references=[
                    "https://horizon3.ai/attack-research/when-read-only-isnt-k8s-nodes-proxy-get-to-rce/",
                    "https://www.stream.security/post/invisible-kubernetes-rec-why-nodes-proxy-get-is-more-dangerous-than-you-think",
                ],
            ))

        if ephemeral_writes:
            findings.append(Finding(
                id="EW-K8S-008",
                title="Service account can write pods/ephemeralcontainers",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.KUBERNETES,
                evidence=(
                    f"create/update on 'pods/ephemeralcontainers' allowed in "
                    f"namespace '{namespace}'"
                ),
                why_it_matters=(
                    "pods/ephemeralcontainers write permission allows injecting an "
                    "ephemeral debug container into any running pod in the namespace. "
                    "Ephemeral containers share the target pod's PID, network, and IPC "
                    "namespaces, allowing an attacker to inspect and interact with all "
                    "processes in the target pod, read its memory, exfiltrate secrets, "
                    "and inject malicious code into the running application — equivalent "
                    "to RCE in the target pod without creating any new pods that might "
                    "trigger alerts."
                ),
                remediation=(
                    "Remove create/update on pods/ephemeralcontainers from this SA "
                    "unless the SA is exclusively used for debugging workflows with "
                    "human oversight."
                ),
                references=[
                    "https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/",
                ],
            ))

        if wildcard_all:
            findings.append(Finding(
                id="EW-K8S-005",
                title="Service account has cluster-admin equivalent rights (verbs=*, resources=*)",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.KUBERNETES,
                evidence=(
                    f"SelfSubjectRulesReview in namespace '{namespace}' returned a "
                    "rule with verbs=['*'] resources=['*'] apiGroups=['*']"
                ),
                why_it_matters=(
                    "A pod whose service account holds wildcard permissions is "
                    "indistinguishable from cluster-admin. Any RCE in this pod "
                    "trivially compromises the entire cluster — secrets, nodes, "
                    "RBAC, and admission controllers."
                ),
                remediation=(
                    "Bind a least-privilege Role to this ServiceAccount. Never "
                    "grant cluster-admin to workload SAs. Audit ClusterRoleBindings "
                    "with `kubectl get clusterrolebindings -o wide`."
                ),
                references=[
                    "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
                ],
            ))
        else:
            if can_read_secrets:
                findings.append(Finding(
                    id="EW-K8S-005-SECRETS-READ",
                    title="Service account can read Kubernetes secrets",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.KUBERNETES,
                    evidence=f"get/list on 'secrets' allowed in namespace '{namespace}'",
                    why_it_matters=(
                        "Read access to secrets typically yields database "
                        "passwords, cloud credentials, and other tokens used "
                        "for lateral movement. Palo Alto Unit 42 lists secret "
                        "enumeration as the #1 post-exploitation step after a "
                        "pod compromise."
                    ),
                    remediation=(
                        "Remove get/list/watch on 'secrets' from this SA's "
                        "Role. Use envFrom with specific secret names rather "
                        "than broad API access."
                    ),
                    references=[
                        "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                    ],
                ))
            if can_create_pods:
                findings.append(Finding(
                    id="EW-K8S-005-PODS-CREATE",
                    title="Service account can create pods (privilege escalation primitive)",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.KUBERNETES,
                    evidence=f"create on 'pods' allowed in namespace '{namespace}'",
                    why_it_matters=(
                        "Pod-create rights let an attacker schedule a "
                        "privileged or hostPath-mounted pod and pivot directly "
                        "onto a node — functionally equivalent to node "
                        "compromise unless a Pod Security Admission policy "
                        "blocks it."
                    ),
                    remediation=(
                        "Remove pod-create rights, or enforce a Pod Security "
                        "Standard 'restricted' admission policy on the namespace."
                    ),
                    references=[
                        "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                    ],
                ))
            if sensitive_writes:
                unique = sorted(set(sensitive_writes))
                findings.append(Finding(
                    id="EW-K8S-005-SENSITIVE-WRITE",
                    title=f"Service account can write sensitive resources: {', '.join(unique)}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category=Category.KUBERNETES,
                    evidence=(
                        f"Write verbs allowed on {', '.join(unique)} in "
                        f"namespace '{namespace}'"
                    ),
                    why_it_matters=(
                        "Write access to RBAC objects, workloads, or service "
                        "accounts enables persistent privilege escalation and "
                        "is a prerequisite for the malicious-pod-deployment "
                        "and clusterrolebinding-modification techniques in "
                        "the Palo Alto threat catalog."
                    ),
                    remediation=(
                        "Restrict the SA's Role to read-only verbs on these "
                        "resources unless write access is strictly required."
                    ),
                    references=[
                        "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                    ],
                ))
            if wildcard_resources:
                unique = sorted(set(wildcard_resources))
                findings.append(Finding(
                    id="EW-K8S-005-WILDCARD-VERBS",
                    title=f"Service account has wildcard verbs on resources: {', '.join(unique[:5])}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category=Category.KUBERNETES,
                    evidence=(
                        f"verbs=['*'] on resources={unique[:10]} in namespace "
                        f"'{namespace}'"
                    ),
                    why_it_matters=(
                        "Wildcard verbs include destructive verbs like delete "
                        "and deletecollection. Even on innocuous-looking "
                        "resources this can be abused for denial-of-service "
                        "or persistence."
                    ),
                    remediation="Replace verbs=['*'] with an explicit verb list.",
                    references=[],
                ))

        if not findings and resource_rules:
            details = (
                f"Namespace '{namespace}': {len(resource_rules)} resource rules, "
                f"{len(non_resource_rules)} non-resource rules"
            )
            if incomplete:
                details += "; incomplete=true"
            if eval_error:
                details += f"; evaluationError={eval_error}"
            findings.append(Finding(
                id="EW-K8S-005",
                title=f"SelfSubjectRulesReview succeeded ({len(resource_rules)} resource rules)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category=Category.KUBERNETES,
                evidence=details,
                why_it_matters=(
                    "No clearly dangerous RBAC rules detected for this service "
                    "account in this namespace. The full rule set is available "
                    "via `kubectl auth can-i --list` for manual review."
                ),
                remediation="None — informational.",
                references=[
                    "https://unit42.paloaltonetworks.com/modern-kubernetes-threats/",
                ],
            ))

        return findings

    def _post_rules_review(
        self, host: str, port: str, token: str, namespace: str
    ) -> dict | None:
        url = f"https://{host}:{port}/apis/authorization.k8s.io/v1/selfsubjectrulesreview"
        body = json.dumps({
            "kind": "SelfSubjectRulesReview",
            "apiVersion": "authorization.k8s.io/v1",
            "spec": {"namespace": namespace},
        }).encode()

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            if self._path_exists(SA_CA_PATH):
                ctx = ssl.create_default_context(cafile=SA_CA_PATH)
            else:
                ctx = ssl.create_default_context()
        except (OSError, ssl.SSLError):
            return None

        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if resp.status not in (200, 201):
                    return None
                return json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            return None


@register_check
class AdmissionWebhookFailurePolicyCheck(BaseCheck):
    """Audit admission webhook failurePolicy and namespace exclusions."""

    name = "k8s-admission-webhook-failurepolicy"
    description = "Audits admission webhook failurePolicy and selectors"
    category = Category.KUBERNETES

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        token = self._read_file(SA_TOKEN_PATH)
        if not token:
            return findings
        token = token.strip()

        api_host = os.environ.get("KUBERNETES_SERVICE_HOST")
        api_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not api_host:
            return findings

        try:
            if self._path_exists(SA_CA_PATH):
                ctx = ssl.create_default_context(cafile=SA_CA_PATH)
            else:
                ctx = ssl.create_default_context()
        except (OSError, ssl.SSLError):
            return findings

        endpoints = [
            ("ValidatingWebhookConfiguration",
             f"https://{api_host}:{api_port}/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"),
            ("MutatingWebhookConfiguration",
             f"https://{api_host}:{api_port}/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations"),
        ]

        for kind, url in endpoints:
            data = self._get_json(url, token, ctx)
            if not data:
                continue
            items = data.get("items", []) if isinstance(data, dict) else []
            for cfg in items:
                if not isinstance(cfg, dict):
                    continue
                cfg_name = (cfg.get("metadata", {}) or {}).get("name", "unknown")
                webhooks = cfg.get("webhooks", []) or []
                for hook in webhooks:
                    if not isinstance(hook, dict):
                        continue
                    hook_name = hook.get("name", "unknown")
                    failure_policy = hook.get("failurePolicy", "Fail")
                    ns_selector = hook.get("namespaceSelector", {}) or {}
                    obj_selector = hook.get("objectSelector", {}) or {}

                    if failure_policy == "Ignore":
                        findings.append(Finding(
                            id="EW-K8S-007-FAILUREPOLICY-IGNORE",
                            title=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' "
                                "has failurePolicy=Ignore"
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=Category.KUBERNETES,
                            evidence=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' has "
                                "failurePolicy=Ignore. If the webhook pod is deleted "
                                "or unreachable, ALL pod creation requests are "
                                "admitted without policy enforcement."
                            ),
                            why_it_matters=(
                                "Admission webhooks are the primary runtime "
                                "enforcement point for Pod Security policies "
                                "(OPA/Gatekeeper, Kyverno, Kube-webhook-certmanager). "
                                "failurePolicy=Ignore means that if the webhook pod is "
                                "unavailable — due to a restart, OOM kill, or "
                                "deliberate deletion by an attacker with pod-delete "
                                "rights — all admission requests are approved without "
                                "policy checks. This allows deployment of privileged "
                                "pods, hostPath mounts, and containers running as root, "
                                "bypassing all policy guardrails."
                            ),
                            remediation=(
                                "Set failurePolicy: Fail for all security-relevant "
                                "admission webhooks. Ensure webhook pods have "
                                "PodDisruptionBudgets and are replicated."
                            ),
                            references=[
                                "https://aquilax.ai/blog/kubernetes-admission-controller-escape",
                                "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/",
                            ],
                        ))

                    if self._excludes_kube_system(ns_selector):
                        findings.append(Finding(
                            id="EW-K8S-007-NS-EXCLUDE-KUBE-SYSTEM",
                            title=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' "
                                "excludes namespace 'kube-system'"
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category=Category.KUBERNETES,
                            evidence=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' "
                                "excludes namespace 'kube-system' via "
                                "namespaceSelector. Privileged pods can be "
                                "deployed in kube-system to bypass admission "
                                "policies."
                            ),
                            why_it_matters=(
                                "Excluding kube-system from a security-enforcing "
                                "webhook is dangerous because kube-system pods "
                                "run with host-level privileges. Any principal "
                                "with pod-create rights in kube-system can "
                                "deploy a privileged pod that bypasses all "
                                "policy checks."
                            ),
                            remediation=(
                                "Remove the kube-system exclusion from the "
                                "namespaceSelector for security-enforcing "
                                "webhooks. Use ClusterRoleBinding scoping to "
                                "restrict pod-create rights in kube-system."
                            ),
                            references=[
                                "https://aquilax.ai/blog/kubernetes-admission-controller-escape",
                            ],
                        ))

                    if obj_selector and self._excludes_nodes_or_system(obj_selector):
                        findings.append(Finding(
                            id="EW-K8S-007-OBJECTSELECTOR-EXCLUDE",
                            title=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' "
                                "objectSelector may exclude system objects"
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category=Category.KUBERNETES,
                            evidence=(
                                f"{kind} '{cfg_name}' webhook '{hook_name}' "
                                f"objectSelector: {obj_selector}"
                            ),
                            why_it_matters=(
                                "objectSelector matchExpressions excluding "
                                "system or node objects may allow privileged "
                                "workloads to bypass admission policy checks."
                            ),
                            remediation=(
                                "Audit the objectSelector to ensure no critical "
                                "system objects are excluded from policy enforcement."
                            ),
                            references=[
                                "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/",
                            ],
                        ))

        return findings

    def _get_json(self, url: str, token: str, ctx: ssl.SSLContext) -> dict | None:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if resp.status != 200:
                    return None
                return json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _excludes_kube_system(ns_selector: dict) -> bool:
        match_expressions = ns_selector.get("matchExpressions", []) or []
        for expr in match_expressions:
            if not isinstance(expr, dict):
                continue
            if expr.get("key") != "kubernetes.io/metadata.name":
                continue
            op = expr.get("operator", "")
            values = expr.get("values", []) or []
            if op == "NotIn" and "kube-system" in values:
                return True
        match_labels = ns_selector.get("matchLabels", {}) or {}
        if isinstance(match_labels, dict):
            name = match_labels.get("kubernetes.io/metadata.name")
            if name and name != "kube-system":
                # An equality selector that excludes kube-system implicitly.
                return False
        return False

    @staticmethod
    def _excludes_nodes_or_system(obj_selector: dict) -> bool:
        match_expressions = obj_selector.get("matchExpressions", []) or []
        for expr in match_expressions:
            if not isinstance(expr, dict):
                continue
            op = expr.get("operator", "")
            values = expr.get("values", []) or []
            if op == "NotIn":
                for v in values:
                    if isinstance(v, str) and ("node" in v.lower() or "system" in v.lower()):
                        return True
        return False
