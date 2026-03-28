import subprocess
from pathlib import Path
from typing import Iterator
import yaml

from .rules import ALL_RULES, VALUES_RULES, Finding, Rule
from .rules.values_rules import ValuesRule


SUPPORTED_KINDS = {
    # Workloads
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
    "Pod", "ReplicaSet",
    # RBAC
    "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding",
    # Networking
    "Ingress", "Service",
    # Config
    "ConfigMap",
}


def _render_with_helm(chart_path: Path, values_file: Path | None = None) -> str | None:
    """Run `helm template` and return rendered YAML, or None if helm is unavailable."""
    cmd = ["helm", "template", "release", str(chart_path)]
    if values_file:
        cmd += ["-f", str(values_file)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _iter_manifests(
    chart_path: Path,
    values_file: Path | None = None,
) -> Iterator[tuple[str, dict]]:
    """Yield (source_label, parsed_manifest) for Kubernetes workload manifests.

    Tries `helm template` first; falls back to direct YAML parsing of templates/
    (which will silently skip Helm-templated files that contain {{ }} expressions).
    """
    rendered = _render_with_helm(chart_path, values_file)
    if rendered is not None:
        label = f"helm:template({values_file.name if values_file else 'values.yaml'})"
        for doc in yaml.safe_load_all(rendered):
            if isinstance(doc, dict):
                yield label, doc
        return

    # Fallback: direct YAML parse (templated files with {{ }} will be skipped)
    templates_dir = chart_path / "templates"
    search_dir = templates_dir if templates_dir.exists() else chart_path

    for yaml_file in sorted(search_dir.rglob("*.yaml")) + sorted(search_dir.rglob("*.yml")):
        rel = str(yaml_file.relative_to(chart_path))
        try:
            with yaml_file.open() as f:
                for doc in yaml.safe_load_all(f):
                    if isinstance(doc, dict):
                        yield rel, doc
        except yaml.YAMLError:
            pass  # skip unparseable files (e.g. templates with {{ }})


def _iter_values_files(
    chart_path: Path,
    values_file: Path | None = None,
) -> Iterator[tuple[str, dict]]:
    """Yield (relative_path, parsed_values) for values files to scan.

    If `values_file` is given, only that file is scanned.
    Otherwise, all values*.yaml / values*.yml files in the chart root are scanned.
    """
    if values_file:
        candidates = [values_file]
    else:
        candidates = sorted(chart_path.glob("values*.yaml")) + sorted(
            chart_path.glob("values*.yml")
        )

    for vf in candidates:
        try:
            with vf.open() as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                try:
                    rel = str(vf.relative_to(chart_path))
                except ValueError:
                    rel = str(vf)
                yield rel, data
        except (yaml.YAMLError, OSError):
            pass


def scan(
    chart_path: Path,
    rules: list[Rule] | None = None,
    values_file: Path | None = None,
    values_rules: list[ValuesRule] | None = None,
) -> list[Finding]:
    """Scan a Helm chart and return all findings.

    Combines two passes:
    1. Manifest scan — renders the chart via `helm template` (or falls back to
       direct YAML parsing) then applies `rules` against every workload manifest.
    2. Values scan — reads every values*.yaml in the chart root (or the explicit
       `values_file`) and applies `values_rules` against the raw values dict.
    """
    active_rules = rules if rules is not None else ALL_RULES
    active_values_rules = values_rules if values_rules is not None else VALUES_RULES
    findings: list[Finding] = []

    # Pass 1: manifest rules on rendered/parsed templates
    for rel_path, manifest in _iter_manifests(chart_path, values_file):
        kind = manifest.get("kind", "")
        if kind not in SUPPORTED_KINDS:
            continue
        for rule in active_rules:
            findings.extend(rule.check(manifest, rel_path))

    # Pass 2: values rules on raw values files
    for rel_path, values in _iter_values_files(chart_path, values_file):
        for rule in active_values_rules:
            findings.extend(rule.check(values, rel_path))

    return findings
