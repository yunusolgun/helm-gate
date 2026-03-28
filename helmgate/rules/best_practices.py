from typing import Any
from .base import Rule, Severity, Finding
from .security import _get_containers, _pod_spec


class ResourceLimitsRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' is missing CPU or memory limits.",
                    path=path,
                    line_hint=f"containers[{name}].resources.limits",
                ))
        return findings


class ResourceRequestsRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            resources = container.get("resources", {})
            requests = resources.get("requests", {})
            if not requests.get("cpu") or not requests.get("memory"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' is missing CPU or memory requests.",
                    path=path,
                    line_hint=f"containers[{name}].resources.requests",
                ))
        return findings


class ImageTagLatestRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            image: str = container.get("image", "")
            tag = image.split(":")[-1] if ":" in image else "latest"
            if tag in ("latest", ""):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' uses the 'latest' image tag — pin to a specific version.",
                    path=path,
                    line_hint=f"containers[{name}].image",
                ))
        return findings


class LivenessProbeRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            if not container.get("livenessProbe"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' has no livenessProbe.",
                    path=path,
                    line_hint=f"containers[{name}].livenessProbe",
                ))
        return findings


class ReadinessProbeRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            if not container.get("readinessProbe"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' has no readinessProbe.",
                    path=path,
                    line_hint=f"containers[{name}].readinessProbe",
                ))
        return findings


_ALLOWED_REGISTRIES = {"gcr.io", "ghcr.io", "quay.io", "registry.k8s.io"}


class ImageRegistryRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            image: str = container.get("image", "")
            registry = image.split("/")[0] if "/" in image else "docker.io"
            if registry not in _ALLOWED_REGISTRIES:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' uses image from untrusted registry '{registry}'.",
                    path=path,
                    line_hint=f"containers[{name}].image",
                ))
        return findings


class DefaultNamespaceRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        namespace = manifest.get("metadata", {}).get("namespace", "")
        if namespace == "default":
            kind = manifest.get("kind", "resource")
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"{kind} is deployed to the 'default' namespace.",
                path=path,
                line_hint="metadata.namespace",
            ))
        return findings


class ReplicasRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        kind = manifest.get("kind", "")
        if kind in ("Deployment", "StatefulSet"):
            replicas = manifest.get("spec", {}).get("replicas", 1)
            if replicas < 2:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"{kind} has only {replicas} replica(s) — consider at least 2 for HA.",
                    path=path,
                    line_hint="spec.replicas",
                ))
        return findings


class StartupProbeRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            if not container.get("startupProbe"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' has no startupProbe — slow-starting containers may be killed prematurely.",
                    path=path,
                    line_hint=f"containers[{name}].startupProbe",
                ))
        return findings


class ImagePullPolicyRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            policy = container.get("imagePullPolicy", "")
            image: str = container.get("image", "")
            has_digest = "@sha256:" in image
            if policy == "Always" and has_digest:
                continue
            if policy not in ("IfNotPresent", "Never") and not has_digest:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' does not set imagePullPolicy: IfNotPresent.",
                    path=path,
                    line_hint=f"containers[{name}].imagePullPolicy",
                ))
        return findings


class DefaultServiceAccountRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        sa = spec.get("serviceAccountName", "default")
        if sa == "default":
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod uses the default service account — create a dedicated one with least privilege.",
                path=path,
                line_hint="spec.serviceAccountName",
            ))
        return findings


_REQUIRED_LABELS = {"app.kubernetes.io/name", "app.kubernetes.io/version"}


class StandardLabelsRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        labels = manifest.get("metadata", {}).get("labels", {}) or {}
        missing = _REQUIRED_LABELS - set(labels.keys())
        if missing:
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"Resource is missing standard labels: {', '.join(sorted(missing))}.",
                path=path,
                line_hint="metadata.labels",
            ))
        return findings


class TerminationGracePeriodRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        if "terminationGracePeriodSeconds" not in spec:
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod does not set terminationGracePeriodSeconds — defaults to 30s which may not suit the workload.",
                path=path,
                line_hint="spec.terminationGracePeriodSeconds",
            ))
        return findings


class ContainerPortNameRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            for port in container.get("ports", []):
                if not port.get("name"):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Container '{name}' has an unnamed port {port.get('containerPort')} — add a name for discoverability.",
                        path=path,
                        line_hint=f"containers[{name}].ports",
                    ))
        return findings


class ImageDigestRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for name, container in _get_containers(manifest):
            image: str = container.get("image", "")
            if "@sha256:" not in image:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' image is not pinned to a digest — use @sha256:... for reproducibility.",
                    path=path,
                    line_hint=f"containers[{name}].image",
                ))
        return findings


class PodAntiAffinityRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        kind = manifest.get("kind", "")
        if kind not in ("Deployment", "StatefulSet"):
            return findings
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        affinity = spec.get("affinity", {})
        if not affinity.get("podAntiAffinity"):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"{kind} has no podAntiAffinity — pods may be scheduled on the same node.",
                path=path,
                line_hint="spec.affinity.podAntiAffinity",
            ))
        return findings


class RevisionHistoryLimitRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        if manifest.get("kind") != "Deployment":
            return findings
        if "revisionHistoryLimit" not in manifest.get("spec", {}):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Deployment does not set revisionHistoryLimit — defaults to 10, consuming unnecessary etcd storage.",
                path=path,
                line_hint="spec.revisionHistoryLimit",
            ))
        return findings


class ProgressDeadlineRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        if manifest.get("kind") != "Deployment":
            return findings
        if "progressDeadlineSeconds" not in manifest.get("spec", {}):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Deployment does not set progressDeadlineSeconds — stuck rollouts may go undetected.",
                path=path,
                line_hint="spec.progressDeadlineSeconds",
            ))
        return findings


class UpdateStrategyRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        kind = manifest.get("kind", "")
        if kind not in ("StatefulSet", "DaemonSet"):
            return findings
        if "updateStrategy" not in manifest.get("spec", {}):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"{kind} does not define updateStrategy — rolling update behavior is undefined.",
                path=path,
                line_hint="spec.updateStrategy",
            ))
        return findings


class MinReadySecondsRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        if manifest.get("kind") != "Deployment":
            return findings
        if "minReadySeconds" not in manifest.get("spec", {}):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Deployment does not set minReadySeconds — new pods are considered ready immediately after starting.",
                path=path,
                line_hint="spec.minReadySeconds",
            ))
        return findings


class PriorityClassRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        if not spec.get("priorityClassName"):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod does not set priorityClassName — workload priority during eviction is undefined.",
                path=path,
                line_hint="spec.priorityClassName",
            ))
        return findings


class CronJobConcurrencyRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        if manifest.get("kind") != "CronJob":
            return findings
        policy = manifest.get("spec", {}).get("concurrencyPolicy", "Allow")
        if policy == "Allow":
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="CronJob uses concurrencyPolicy: Allow — concurrent runs may cause race conditions. Consider Forbid or Replace.",
                path=path,
                line_hint="spec.concurrencyPolicy",
            ))
        return findings


# ── rule registry ─────────────────────────────────────────────────────────────

BEST_PRACTICE_RULES: list[Rule] = [
    ResourceLimitsRule(
        id="BP001",
        name="Resource limits",
        severity=Severity.HIGH,
        description="All containers must define CPU and memory limits.",
    ),
    ResourceRequestsRule(
        id="BP002",
        name="Resource requests",
        severity=Severity.MEDIUM,
        description="All containers must define CPU and memory requests.",
    ),
    ImageTagLatestRule(
        id="BP003",
        name="Image tag latest",
        severity=Severity.HIGH,
        description="Do not use the 'latest' image tag in production.",
    ),
    LivenessProbeRule(
        id="BP004",
        name="Liveness probe",
        severity=Severity.MEDIUM,
        description="All containers should define a livenessProbe.",
    ),
    ReadinessProbeRule(
        id="BP005",
        name="Readiness probe",
        severity=Severity.MEDIUM,
        description="All containers should define a readinessProbe.",
    ),
    ReplicasRule(
        id="BP006",
        name="Replica count",
        severity=Severity.LOW,
        description="Deployments should have at least 2 replicas for high availability.",
    ),
    ImageRegistryRule(
        id="BP007",
        name="Untrusted image registry",
        severity=Severity.MEDIUM,
        description="Images should be pulled from trusted registries.",
    ),
    DefaultNamespaceRule(
        id="BP008",
        name="Default namespace",
        severity=Severity.LOW,
        description="Resources should not be deployed to the default namespace.",
    ),
    StartupProbeRule(
        id="BP009",
        name="Startup probe",
        severity=Severity.LOW,
        description="Containers should define a startupProbe for slow-starting workloads.",
    ),
    ImagePullPolicyRule(
        id="BP010",
        name="Image pull policy",
        severity=Severity.LOW,
        description="imagePullPolicy should be IfNotPresent to avoid unnecessary pulls.",
    ),
    DefaultServiceAccountRule(
        id="BP011",
        name="Default service account",
        severity=Severity.MEDIUM,
        description="Pods should use a dedicated service account, not the default one.",
    ),
    StandardLabelsRule(
        id="BP012",
        name="Missing standard labels",
        severity=Severity.LOW,
        description="Resources should have app.kubernetes.io/name and app.kubernetes.io/version labels.",
    ),
    TerminationGracePeriodRule(
        id="BP013",
        name="Termination grace period not set",
        severity=Severity.LOW,
        description="Pods should explicitly set terminationGracePeriodSeconds.",
    ),
    ContainerPortNameRule(
        id="BP014",
        name="Unnamed container port",
        severity=Severity.LOW,
        description="Container ports should have names for discoverability.",
    ),
    ImageDigestRule(
        id="BP015",
        name="Image not pinned to digest",
        severity=Severity.MEDIUM,
        description="Images should be pinned to a digest for reproducible deployments.",
    ),
    PodAntiAffinityRule(
        id="BP016",
        name="No pod anti-affinity",
        severity=Severity.LOW,
        description="Deployments should define podAntiAffinity to spread pods across nodes.",
    ),
    RevisionHistoryLimitRule(
        id="BP017",
        name="revisionHistoryLimit not set",
        severity=Severity.LOW,
        description="Deployments should set revisionHistoryLimit to limit stored revisions.",
    ),
    ProgressDeadlineRule(
        id="BP018",
        name="progressDeadlineSeconds not set",
        severity=Severity.LOW,
        description="Deployments should set progressDeadlineSeconds to detect stuck rollouts.",
    ),
    UpdateStrategyRule(
        id="BP019",
        name="updateStrategy not set",
        severity=Severity.MEDIUM,
        description="StatefulSets and DaemonSets should explicitly define updateStrategy.",
    ),
    MinReadySecondsRule(
        id="BP020",
        name="minReadySeconds not set",
        severity=Severity.LOW,
        description="Deployments should set minReadySeconds to avoid premature traffic routing.",
    ),
    PriorityClassRule(
        id="BP021",
        name="priorityClassName not set",
        severity=Severity.LOW,
        description="Pods should set priorityClassName to define eviction priority.",
    ),
    CronJobConcurrencyRule(
        id="BP022",
        name="CronJob concurrency policy",
        severity=Severity.MEDIUM,
        description="CronJobs should set concurrencyPolicy to Forbid or Replace.",
    ),
]
