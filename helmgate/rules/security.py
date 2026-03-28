from typing import Any
from .base import Rule, Severity, Finding


class RunAsRootRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            run_as_non_root = sc.get("securityContext", {}).get("runAsNonRoot")
            run_as_user = sc.get("securityContext", {}).get("runAsUser", -1)
            if run_as_non_root is False or run_as_user == 0:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' may run as root.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext",
                ))
        return findings


class PrivilegedContainerRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            privileged = sc.get("securityContext", {}).get("privileged", False)
            if privileged:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' is running in privileged mode.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.privileged",
                ))
        return findings


class AllowPrivilegeEscalationRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            ape = sc.get("securityContext", {}).get("allowPrivilegeEscalation")
            if ape is True or ape is None:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' allows privilege escalation. Set allowPrivilegeEscalation: false.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.allowPrivilegeEscalation",
                ))
        return findings


class ReadOnlyRootFilesystemRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            ro = sc.get("securityContext", {}).get("readOnlyRootFilesystem", False)
            if not ro:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' does not have a read-only root filesystem.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.readOnlyRootFilesystem",
                ))
        return findings


class HostNetworkRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec and spec.get("hostNetwork", False):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod uses hostNetwork: true — shares host network namespace.",
                path=path,
                line_hint="spec.hostNetwork",
            ))
        return findings


class HostPIDRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec and spec.get("hostPID", False):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod uses hostPID: true — shares host PID namespace.",
                path=path,
                line_hint="spec.hostPID",
            ))
        return findings


class CapabilitiesDropRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            drop = sc.get("securityContext", {}).get("capabilities", {}).get("drop", [])
            if "ALL" not in drop:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' does not drop ALL capabilities.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.capabilities.drop",
                ))
        return findings


_SECRET_KEYWORDS = {"PASSWORD", "SECRET", "TOKEN", "KEY", "PASSWD", "PASS", "API_KEY"}


class SecretEnvVarRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            for env in sc.get("env", []):
                env_name = env.get("name", "").upper()
                if any(k in env_name for k in _SECRET_KEYWORDS) and "value" in env:
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Container '{name}' has a plain-text secret in env var '{env.get('name')}'.",
                        path=path,
                        line_hint=f"containers[{name}].env[{env.get('name')}]",
                    ))
        return findings


class HostIPCRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec and spec.get("hostIPC", False):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod uses hostIPC: true — shares host IPC namespace.",
                path=path,
                line_hint="spec.hostIPC",
            ))
        return findings


class SeccompProfileRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            profile = sc.get("securityContext", {}).get("seccompProfile", {}).get("type")
            if profile not in ("RuntimeDefault", "Localhost"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' has no seccomp profile set (RuntimeDefault or Localhost).",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.seccompProfile",
                ))
        return findings


_DANGEROUS_CAPS = {
    "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
    "SYS_BOOT", "SYS_TIME", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER",
    "SETUID", "SETGID", "NET_RAW",
}


class DangerousCapabilitiesRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            added = sc.get("securityContext", {}).get("capabilities", {}).get("add", [])
            dangerous = [c for c in added if c in _DANGEROUS_CAPS]
            for cap in dangerous:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' adds dangerous capability '{cap}'.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.capabilities.add",
                ))
        return findings


class HostPathVolumeRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if not spec:
            return findings
        for volume in spec.get("volumes", []):
            if "hostPath" in volume:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Volume '{volume.get('name')}' mounts a hostPath — exposes host filesystem.",
                    path=path,
                    line_hint=f"spec.volumes[{volume.get('name')}].hostPath",
                ))
        return findings


class AutomountServiceAccountTokenRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        automount = spec.get("automountServiceAccountToken")
        if automount is None or automount is True:
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod does not set automountServiceAccountToken: false.",
                path=path,
                line_hint="spec.automountServiceAccountToken",
            ))
        return findings


class HostPortRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            for port in sc.get("ports", []):
                if port.get("hostPort"):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Container '{name}' uses hostPort {port['hostPort']} — bypasses network policies.",
                        path=path,
                        line_hint=f"containers[{name}].ports[{port.get('name', port['hostPort'])}].hostPort",
                    ))
        return findings


class AppArmorProfileRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        annotations = manifest.get("metadata", {}).get("annotations", {}) or {}
        for name, sc in containers:
            # Kubernetes 1.30+ securityContext.appArmorProfile
            profile = sc.get("securityContext", {}).get("appArmorProfile", {}).get("type")
            # Older annotation-based approach
            annotation_key = f"container.apparmor.security.beta.kubernetes.io/{name}"
            has_annotation = annotation_key in annotations
            if not profile and not has_annotation:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' has no AppArmor profile configured.",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.appArmorProfile",
                ))
        return findings


class RunAsRootGroupRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            run_as_group = sc.get("securityContext", {}).get("runAsGroup")
            if run_as_group == 0:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Container '{name}' runs with root group (runAsGroup: 0).",
                    path=path,
                    line_hint=f"containers[{name}].securityContext.runAsGroup",
                ))
        return findings


_SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_unprivileged_port_start",
}


class UnsafeSysctlsRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if not spec:
            return findings
        sysctls = spec.get("securityContext", {}).get("sysctls", [])
        for sysctl in sysctls:
            name = sysctl.get("name", "")
            if name not in _SAFE_SYSCTLS:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Pod uses unsafe sysctl '{name}'.",
                    path=path,
                    line_hint="spec.securityContext.sysctls",
                ))
        return findings


class ShareProcessNamespaceRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec and spec.get("shareProcessNamespace", False):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod has shareProcessNamespace: true — containers share each other's processes.",
                path=path,
                line_hint="spec.shareProcessNamespace",
            ))
        return findings


class SubPathVolumeMountRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        containers = _get_containers(manifest)
        for name, sc in containers:
            for mount in sc.get("volumeMounts", []):
                if mount.get("subPath") or mount.get("subPathExpr"):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Container '{name}' uses subPath in volumeMount '{mount.get('name')}' — can be a path traversal risk.",
                        path=path,
                        line_hint=f"containers[{name}].volumeMounts[{mount.get('name')}].subPath",
                    ))
        return findings


class PodSecurityContextRule(Rule):
    def check(self, manifest: dict[str, Any], path: str) -> list[Finding]:
        findings = []
        spec = _pod_spec(manifest)
        if spec is None:
            return findings
        if not spec.get("securityContext"):
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message="Pod has no pod-level securityContext — set runAsNonRoot, runAsUser, fsGroup at minimum.",
                path=path,
                line_hint="spec.securityContext",
            ))
        return findings


# ── helpers ───────────────────────────────────────────────────────────────────

def _pod_spec(manifest: dict[str, Any]) -> dict | None:
    kind = manifest.get("kind", "")
    if kind == "Pod":
        return manifest.get("spec")
    return manifest.get("spec", {}).get("template", {}).get("spec")


def _get_containers(manifest: dict[str, Any]) -> list[tuple[str, dict]]:
    spec = _pod_spec(manifest)
    if not spec:
        return []
    containers = spec.get("containers", []) + spec.get("initContainers", [])
    return [(c.get("name", "unknown"), c) for c in containers if isinstance(c, dict)]


# ── rule registry ─────────────────────────────────────────────────────────────

SECURITY_RULES: list[Rule] = [
    RunAsRootRule(
        id="SEC001",
        name="Run as root",
        severity=Severity.HIGH,
        description="Containers should not run as root.",
    ),
    PrivilegedContainerRule(
        id="SEC002",
        name="Privileged container",
        severity=Severity.CRITICAL,
        description="Privileged containers have full host access.",
    ),
    AllowPrivilegeEscalationRule(
        id="SEC003",
        name="Privilege escalation",
        severity=Severity.HIGH,
        description="allowPrivilegeEscalation should be false.",
    ),
    ReadOnlyRootFilesystemRule(
        id="SEC004",
        name="Read-only root filesystem",
        severity=Severity.MEDIUM,
        description="Root filesystem should be read-only.",
    ),
    HostNetworkRule(
        id="SEC005",
        name="Host network",
        severity=Severity.HIGH,
        description="Pods should not share the host network namespace.",
    ),
    HostPIDRule(
        id="SEC006",
        name="Host PID",
        severity=Severity.HIGH,
        description="Pods should not share the host PID namespace.",
    ),
    CapabilitiesDropRule(
        id="SEC007",
        name="Capabilities not dropped",
        severity=Severity.HIGH,
        description="Containers should drop ALL capabilities.",
    ),
    SecretEnvVarRule(
        id="SEC008",
        name="Secret in env var",
        severity=Severity.MEDIUM,
        description="Secrets should not be passed as plain-text environment variables.",
    ),
    HostIPCRule(
        id="SEC009",
        name="Host IPC",
        severity=Severity.HIGH,
        description="Pods should not share the host IPC namespace.",
    ),
    SeccompProfileRule(
        id="SEC010",
        name="Seccomp profile not set",
        severity=Severity.MEDIUM,
        description="Containers should have a seccomp profile (RuntimeDefault or Localhost).",
    ),
    DangerousCapabilitiesRule(
        id="SEC011",
        name="Dangerous capabilities added",
        severity=Severity.HIGH,
        description="Containers should not add dangerous Linux capabilities.",
    ),
    HostPathVolumeRule(
        id="SEC012",
        name="HostPath volume",
        severity=Severity.HIGH,
        description="Pods should not mount host filesystem paths.",
    ),
    AutomountServiceAccountTokenRule(
        id="SEC013",
        name="Automount service account token",
        severity=Severity.MEDIUM,
        description="Pods should set automountServiceAccountToken: false if they don't need API access.",
    ),
    HostPortRule(
        id="SEC014",
        name="Host port used",
        severity=Severity.MEDIUM,
        description="Containers should not use hostPort as it bypasses network policies.",
    ),
    AppArmorProfileRule(
        id="SEC015",
        name="AppArmor profile not set",
        severity=Severity.MEDIUM,
        description="Containers should have an AppArmor profile configured.",
    ),
    RunAsRootGroupRule(
        id="SEC016",
        name="Run as root group",
        severity=Severity.HIGH,
        description="Containers should not run with root group (runAsGroup: 0).",
    ),
    UnsafeSysctlsRule(
        id="SEC017",
        name="Unsafe sysctls",
        severity=Severity.HIGH,
        description="Pods should only use safe, namespaced sysctls.",
    ),
    ShareProcessNamespaceRule(
        id="SEC018",
        name="Share process namespace",
        severity=Severity.MEDIUM,
        description="Pods should not share process namespace between containers.",
    ),
    SubPathVolumeMountRule(
        id="SEC019",
        name="SubPath volume mount",
        severity=Severity.MEDIUM,
        description="subPath in volumeMounts can be exploited for path traversal.",
    ),
    PodSecurityContextRule(
        id="SEC020",
        name="No pod-level securityContext",
        severity=Severity.LOW,
        description="Pods should define a pod-level securityContext.",
    ),
]
