from dataclasses import dataclass
from typing import Any
from .base import Finding, Severity


@dataclass
class ValuesRule:
    id: str
    name: str
    severity: Severity
    description: str

    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        raise NotImplementedError


_SECRET_KEYWORDS = {
    "PASSWORD", "SECRET", "TOKEN", "KEY", "PASSWD", "PASS",
    "API_KEY", "PRIVATE", "CREDENTIAL", "AUTH",
}


def _recursive_secret_scan(obj: Any, path_parts: list[str]) -> list[tuple[str, str]]:
    """Recursively find keys that look like secrets with non-empty string values."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = path_parts + [str(k)]
            key_upper = str(k).upper()
            if any(kw in key_upper for kw in _SECRET_KEYWORDS):
                if isinstance(v, str) and v.strip():
                    found.append((".".join(current_path), v))
            else:
                found.extend(_recursive_secret_scan(v, current_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(_recursive_secret_scan(item, path_parts + [str(i)]))
    return found


class HardcodedSecretRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        for key_path, _ in _recursive_secret_scan(values, []):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"Hardcoded secret at '{key_path}' — use Kubernetes Secrets instead.",
                path=path,
                line_hint=key_path,
            ))
        return findings


class PrivilegedValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        sc = values.get("securityContext", {})
        if not isinstance(sc, dict):
            return []
        if sc.get("privileged") is True:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="securityContext.privileged is true — container has full host kernel access.",
                path=path,
                line_hint="securityContext.privileged",
            )]
        return []


class RunAsRootValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        sc = values.get("securityContext", {})
        if not isinstance(sc, dict):
            return []
        if sc.get("runAsUser") == 0:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="securityContext.runAsUser is 0 — container runs as root.",
                path=path,
                line_hint="securityContext.runAsUser",
            )]
        return []


class AllowPrivilegeEscalationValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        sc = values.get("securityContext", {})
        if not isinstance(sc, dict):
            return []
        if sc.get("allowPrivilegeEscalation") is True:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="securityContext.allowPrivilegeEscalation is true.",
                path=path,
                line_hint="securityContext.allowPrivilegeEscalation",
            )]
        return []


class HostNetworkValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        if values.get("hostNetwork") is True:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="hostNetwork is true — pod shares host network namespace.",
                path=path,
                line_hint="hostNetwork",
            )]
        return []


class HostPIDValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        if values.get("hostPID") is True:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="hostPID is true — pod shares host PID namespace.",
                path=path,
                line_hint="hostPID",
            )]
        return []


class ImageTagLatestValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        image = values.get("image", {})
        if not isinstance(image, dict):
            return []
        tag = str(image.get("tag", "")).strip()
        if tag.lower() in ("latest", ""):
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"image.tag is '{tag or 'unset'}' — pin to a specific version.",
                path=path,
                line_hint="image.tag",
            )]
        return []


class MissingResourceLimitsValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        resources = values.get("resources", {})
        if not isinstance(resources, dict) or not resources:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="resources is empty — set CPU and memory limits to prevent noisy-neighbor issues.",
                path=path,
                line_hint="resources",
            )]
        return []


class NetworkPolicyDisabledValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        np = values.get("networkPolicy", {})
        if isinstance(np, dict) and np.get("enabled") is False:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="networkPolicy.enabled is false — all pods can communicate freely.",
                path=path,
                line_hint="networkPolicy.enabled",
            )]
        return []


class DangerousCapabilitiesValuesRule(ValuesRule):
    _DANGEROUS = {
        "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
        "SYS_BOOT", "SYS_TIME", "DAC_OVERRIDE", "DAC_READ_SEARCH",
        "SETUID", "SETGID", "NET_RAW",
    }

    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        sc = values.get("securityContext", {})
        if not isinstance(sc, dict):
            return []
        added = sc.get("capabilities", {}).get("add", [])
        findings = []
        for cap in added:
            if cap in self._DANGEROUS:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Dangerous capability '{cap}' added in securityContext.",
                    path=path,
                    line_hint="securityContext.capabilities.add",
                ))
        return findings


class ClusterAdminValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        rbac = values.get("rbac", {})
        if isinstance(rbac, dict) and rbac.get("clusterAdmin") is True:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="rbac.clusterAdmin is true — grants full cluster-wide access (least privilege violation).",
                path=path,
                line_hint="rbac.clusterAdmin",
            )]
        return []


class IngressTLSDisabledValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        ingress = values.get("ingress", {})
        if not isinstance(ingress, dict):
            return []
        if ingress.get("enabled") is True and not ingress.get("tls"):
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="ingress.tls is empty while ingress is enabled — traffic served over plain HTTP.",
                path=path,
                line_hint="ingress.tls",
            )]
        return []


class ServiceNodePortValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        service = values.get("service", {})
        if not isinstance(service, dict):
            return []
        stype = service.get("type", "")
        if stype in ("NodePort", "LoadBalancer"):
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"service.type is '{stype}' — exposes the service on every node IP.",
                path=path,
                line_hint="service.type",
            )]
        return []


class PDBDisabledValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        pdb = values.get("pdb", {})
        if isinstance(pdb, dict) and pdb.get("enabled") is False:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="pdb.enabled is false — no PodDisruptionBudget, full downtime possible during node drain.",
                path=path,
                line_hint="pdb.enabled",
            )]
        return []


class ImagePullPolicyAlwaysValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        image = values.get("image", {})
        if not isinstance(image, dict):
            return []
        if image.get("pullPolicy") == "Always":
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="image.pullPolicy is 'Always' — unnecessary pulls on every pod start, prefer IfNotPresent.",
                path=path,
                line_hint="image.pullPolicy",
            )]
        return []


class DebugLogLevelValuesRule(ValuesRule):
    _DEBUG_LEVELS = {"debug", "trace", "verbose", "all"}

    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        data = values.get("configMap", {}).get("data", {})
        if not isinstance(data, dict):
            return []
        log_level = str(data.get("LOG_LEVEL", "")).strip().lower()
        if log_level in self._DEBUG_LEVELS:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"LOG_LEVEL is '{log_level}' — debug logging may expose sensitive data in production logs.",
                path=path,
                line_hint="configMap.data.LOG_LEVEL",
            )]
        return []


class ReadWriteManyValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        persistence = values.get("persistence", {})
        if not isinstance(persistence, dict) or not persistence.get("enabled"):
            return []
        if "ReadWriteMany" in persistence.get("accessModes", []):
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="persistence.accessModes includes ReadWriteMany — concurrent writes risk data corruption.",
                path=path,
                line_hint="persistence.accessModes",
            )]
        return []


class EmptyPodSecurityContextValuesRule(ValuesRule):
    def check(self, values: dict[str, Any], path: str) -> list[Finding]:
        psc = values.get("podSecurityContext", {})
        if isinstance(psc, dict) and not psc:
            return [Finding(
                rule_id=self.id,
                severity=self.severity,
                message="podSecurityContext is empty — set at least runAsNonRoot, runAsUser, and fsGroup.",
                path=path,
                line_hint="podSecurityContext",
            )]
        return []


FREE_VALUES_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

VALUES_RULES: list[ValuesRule] = [
    HardcodedSecretRule(
        id="VAL001",
        name="Hardcoded secret in values",
        severity=Severity.CRITICAL,
        description="Secret values should not be hardcoded — use Kubernetes Secrets.",
    ),
    PrivilegedValuesRule(
        id="VAL002",
        name="Privileged container in values",
        severity=Severity.CRITICAL,
        description="securityContext.privileged should not be true.",
    ),
    RunAsRootValuesRule(
        id="VAL003",
        name="Run as root in values",
        severity=Severity.HIGH,
        description="Container should not run as root (runAsUser: 0).",
    ),
    AllowPrivilegeEscalationValuesRule(
        id="VAL004",
        name="Privilege escalation in values",
        severity=Severity.HIGH,
        description="allowPrivilegeEscalation should be false.",
    ),
    HostNetworkValuesRule(
        id="VAL005",
        name="Host network in values",
        severity=Severity.HIGH,
        description="hostNetwork should not be true.",
    ),
    HostPIDValuesRule(
        id="VAL006",
        name="Host PID in values",
        severity=Severity.HIGH,
        description="hostPID should not be true.",
    ),
    ImageTagLatestValuesRule(
        id="VAL007",
        name="Latest image tag in values",
        severity=Severity.HIGH,
        description="image.tag should not be 'latest'.",
    ),
    MissingResourceLimitsValuesRule(
        id="VAL008",
        name="Missing resource limits in values",
        severity=Severity.HIGH,
        description="resources should define CPU and memory limits.",
    ),
    DangerousCapabilitiesValuesRule(
        id="VAL009",
        name="Dangerous capabilities in values",
        severity=Severity.HIGH,
        description="Containers should not add dangerous Linux capabilities.",
    ),
    NetworkPolicyDisabledValuesRule(
        id="VAL010",
        name="Network policy disabled in values",
        severity=Severity.MEDIUM,
        description="networkPolicy.enabled should be true.",
    ),
    ClusterAdminValuesRule(
        id="VAL011",
        name="RBAC cluster-admin in values",
        severity=Severity.CRITICAL,
        description="rbac.clusterAdmin should not be true — use least-privilege roles.",
    ),
    IngressTLSDisabledValuesRule(
        id="VAL012",
        name="Ingress TLS disabled in values",
        severity=Severity.MEDIUM,
        description="TLS should be configured when ingress is enabled.",
    ),
    ServiceNodePortValuesRule(
        id="VAL013",
        name="Service type NodePort in values",
        severity=Severity.LOW,
        description="service.type should be ClusterIP; expose externally via Ingress.",
    ),
    PDBDisabledValuesRule(
        id="VAL014",
        name="PDB disabled in values",
        severity=Severity.LOW,
        description="pdb.enabled should be true to prevent full downtime during disruptions.",
    ),
    ImagePullPolicyAlwaysValuesRule(
        id="VAL015",
        name="Image pull policy Always in values",
        severity=Severity.LOW,
        description="imagePullPolicy: Always causes unnecessary registry pulls.",
    ),
    DebugLogLevelValuesRule(
        id="VAL016",
        name="Debug log level in values",
        severity=Severity.LOW,
        description="Debug/trace log levels can leak sensitive data in production.",
    ),
    ReadWriteManyValuesRule(
        id="VAL017",
        name="ReadWriteMany persistence access mode",
        severity=Severity.MEDIUM,
        description="ReadWriteMany allows concurrent writes and risks data corruption.",
    ),
    EmptyPodSecurityContextValuesRule(
        id="VAL018",
        name="Empty podSecurityContext in values",
        severity=Severity.MEDIUM,
        description="podSecurityContext should define runAsNonRoot, runAsUser, and fsGroup.",
    ),
]

FREE_VALUES_RULES: list[ValuesRule] = [
    r for r in VALUES_RULES if r.severity in FREE_VALUES_SEVERITIES
]
