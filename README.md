# helmgate

[![PyPI version](https://badge.fury.io/py/helmgate.svg)](https://pypi.org/project/helmgate/)

**Helm chart security scanner and policy enforcement CLI.**

Scans Kubernetes Helm charts for security vulnerabilities and best-practice violations — across rendered manifests *and* raw `values.yaml` files.

## How it works

helmgate runs two scanning passes on every chart:

1. **Manifest scan** — renders the chart via `helm template` and applies security/best-practice rules against every Kubernetes workload, RBAC, Ingress, Service, and ConfigMap resource.
2. **Values scan** — parses every `values*.yaml` file directly to catch hardcoded secrets, dangerous security context settings, and misconfigurations before they reach the cluster.

## Installation

```bash
pip install helmgate
```

## Usage

```bash
# Scan a chart with default values (table output)
helmgate scan ./my-chart

# Scan with a specific values file
helmgate scan ./my-chart -f ./my-chart/values-prod.yaml

# Export findings as JSON (Pro)
helmgate scan ./my-chart --output json
```

### `--fail-on` — CI/CD exit code control

Controls at which severity level the CLI exits with code `1`. Useful for blocking deployments in CI pipelines.

| Value | Behavior |
|---|---|
| `CRITICAL` | Exit 1 only if CRITICAL findings exist (default) |
| `HIGH` | Exit 1 if HIGH or above findings exist |
| `MEDIUM` | Exit 1 if MEDIUM or above findings exist |
| `LOW` | Exit 1 if LOW or above findings exist |
| `INFO` | Exit 1 if any findings exist |
| `NONE` | Never exit 1 regardless of findings |

```bash
# Fail the build on any CRITICAL finding (default)
helmgate scan ./my-chart

# Fail the build on HIGH or above
helmgate scan ./my-chart --fail-on HIGH

# Scan without failing the build (report only)
helmgate scan ./my-chart --fail-on NONE

# Scan a specific values file and fail on MEDIUM+
helmgate scan ./my-chart -f values-prod.yaml --fail-on MEDIUM
```

**GitHub Actions example:**

```yaml
- name: Scan Helm chart
  run: helmgate scan ./chart --fail-on HIGH
```

## Free vs Pro

| Feature | Free | Pro |
|---|---|---|
| CRITICAL & HIGH rules (29 rules) | ✓ | ✓ |
| MEDIUM & LOW rules (41 rules) | — | ✓ |
| JSON output | — | ✓ |
| Price | Free | $9 one-time (lifetime) |

**To get a Pro license key**, send an email to [yunus.olgun@outlook.com](mailto:yunus.olgun@outlook.com) with the subject `helmgate Pro License`.

Once you have a key:

```bash
helmgate activate HGATE-<your-key>
```

Or set it as an environment variable:

```bash
export HELMGATE_LICENSE_KEY=HGATE-<your-key>
```

## Rules

### Security (SEC) — 26 rules

| ID | Severity | Description |
|---|---|---|
| SEC001 | HIGH | Container runs as root |
| SEC002 | CRITICAL | Privileged container |
| SEC003 | HIGH | Privilege escalation allowed |
| SEC004 | MEDIUM | Root filesystem not read-only |
| SEC005 | HIGH | Host network namespace shared |
| SEC006 | HIGH | Host PID namespace shared |
| SEC007 | HIGH | Linux capabilities not dropped (ALL) |
| SEC008 | MEDIUM | Secret passed as plain-text env var |
| SEC009 | HIGH | Host IPC namespace shared |
| SEC010 | MEDIUM | Seccomp profile not set |
| SEC011 | HIGH | Dangerous capability added (SYS_ADMIN, NET_ADMIN, etc.) |
| SEC012 | HIGH | hostPath volume mounted |
| SEC013 | MEDIUM | Service account token auto-mounted |
| SEC014 | MEDIUM | Host port used |
| SEC015 | MEDIUM | AppArmor profile not configured |
| SEC016 | HIGH | Container runs with root group (runAsGroup: 0) |
| SEC017 | HIGH | Unsafe sysctls present |
| SEC018 | MEDIUM | shareProcessNamespace enabled |
| SEC019 | MEDIUM | subPath used in volumeMount |
| SEC020 | LOW | No pod-level securityContext |
| SEC021 | HIGH | RBAC role grants wildcard verbs (*) |
| SEC022 | HIGH | RBAC role grants wildcard resources (*) |
| SEC023 | HIGH | RBAC role allows reading Secrets |
| SEC024 | CRITICAL | RBAC role grants escalation verbs (bind/escalate/impersonate) |
| SEC025 | CRITICAL | Binding to cluster-admin role |
| SEC026 | CRITICAL | ConfigMap contains plaintext secret |

### Best Practices (BP) — 26 rules

| ID | Severity | Description |
|---|---|---|
| BP001 | HIGH | Missing CPU/memory limits |
| BP002 | MEDIUM | Missing CPU/memory requests |
| BP003 | HIGH | Image uses `latest` tag |
| BP004 | MEDIUM | No liveness probe |
| BP005 | MEDIUM | No readiness probe |
| BP006 | LOW | Fewer than 2 replicas |
| BP007 | MEDIUM | Image from untrusted registry |
| BP008 | LOW | Deployed to default namespace |
| BP009 | LOW | No startup probe |
| BP010 | LOW | imagePullPolicy not IfNotPresent |
| BP011 | MEDIUM | Uses default service account |
| BP012 | LOW | Missing standard labels (app.kubernetes.io/name, version) |
| BP013 | LOW | terminationGracePeriodSeconds not set |
| BP014 | LOW | Unnamed container port |
| BP015 | MEDIUM | Image not pinned to digest |
| BP016 | LOW | No pod anti-affinity defined |
| BP017 | LOW | revisionHistoryLimit not set (Deployment) |
| BP018 | LOW | progressDeadlineSeconds not set (Deployment) |
| BP019 | MEDIUM | updateStrategy not defined (StatefulSet/DaemonSet) |
| BP020 | LOW | minReadySeconds not set (Deployment) |
| BP021 | LOW | priorityClassName not set |
| BP022 | MEDIUM | CronJob concurrencyPolicy is Allow |
| BP023 | MEDIUM | Ingress has no TLS configured |
| BP024 | MEDIUM | Ingress rule uses wildcard/empty host |
| BP025 | LOW | Service type is NodePort or LoadBalancer |
| BP026 | MEDIUM | Service sets externalIPs |

### Values (VAL) — 18 rules

Checks raw `values.yaml` / `values*.yaml` files directly — catches misconfigurations before `helm template` is even run.

| ID | Severity | Description |
|---|---|---|
| VAL001 | CRITICAL | Hardcoded secret in values (password, token, key, etc.) |
| VAL002 | CRITICAL | securityContext.privileged: true |
| VAL003 | HIGH | securityContext.runAsUser: 0 (root) |
| VAL004 | HIGH | securityContext.allowPrivilegeEscalation: true |
| VAL005 | HIGH | hostNetwork: true |
| VAL006 | HIGH | hostPID: true |
| VAL007 | HIGH | image.tag is `latest` |
| VAL008 | HIGH | resources is empty (no CPU/memory limits) |
| VAL009 | HIGH | Dangerous capability added (NET_ADMIN, SYS_ADMIN, etc.) |
| VAL010 | MEDIUM | networkPolicy.enabled: false |
| VAL011 | CRITICAL | rbac.clusterAdmin: true |
| VAL012 | MEDIUM | ingress.tls is empty while ingress is enabled |
| VAL013 | LOW | service.type is NodePort |
| VAL014 | LOW | pdb.enabled: false (no PodDisruptionBudget) |
| VAL015 | LOW | image.pullPolicy: Always |
| VAL016 | LOW | LOG_LEVEL is debug/trace in configMap |
| VAL017 | MEDIUM | persistence.accessModes includes ReadWriteMany |
| VAL018 | MEDIUM | podSecurityContext is empty |
