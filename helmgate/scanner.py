from pathlib import Path
from typing import Iterator
import yaml

from .rules import ALL_RULES, Finding, Rule


SUPPORTED_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob",
    "Pod", "ReplicaSet",
}


def _iter_manifests(chart_path: Path) -> Iterator[tuple[str, dict]]:
    """Yield (relative_path, parsed_dict) for every YAML manifest in the chart."""
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
            pass  # skip unparseable files (e.g. templated YAML with {{ }})


def scan(chart_path: Path, rules: list[Rule] | None = None) -> list[Finding]:
    """
    Scan a Helm chart directory and return all findings.
    Pass `rules` to override the default rule set.
    """
    active_rules = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []

    for rel_path, manifest in _iter_manifests(chart_path):
        kind = manifest.get("kind", "")
        if kind not in SUPPORTED_KINDS:
            continue
        for rule in active_rules:
            findings.extend(rule.check(manifest, rel_path))

    return findings
