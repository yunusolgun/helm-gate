from pathlib import Path
from helmgate.scanner import scan
from helmgate.rules import Severity
from typer.testing import CliRunner
from helmgate.cli import app
import json

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_bad_chart_has_findings():
    findings = scan(FIXTURES / "bad-chart")
    assert len(findings) > 0


def test_bad_chart_detects_privileged():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC002" in ids  # privileged


def test_bad_chart_detects_latest_tag():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "BP003" in ids  # latest tag


def test_bad_chart_detects_host_network():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC005" in ids


def test_good_chart_no_critical_or_high():
    findings = scan(FIXTURES / "good-chart")
    bad = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert bad == [], f"Unexpected findings: {bad}"


def test_good_chart_no_security_findings():
    findings = scan(FIXTURES / "good-chart")
    sec = [f for f in findings if f.rule_id.startswith("SEC")]
    assert sec == []


def test_bad_chart_detects_secret_env_var():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC008" in ids


def test_bad_chart_detects_capabilities_not_dropped():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC007" in ids


def test_bad_chart_detects_default_namespace():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "BP008" in ids


def test_bad_chart_detects_untrusted_registry():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "BP007" in ids


def test_bad_chart_detects_host_ipc():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC009" in ids


def test_bad_chart_detects_dangerous_capabilities():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC011" in ids


def test_bad_chart_detects_hostpath_volume():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC012" in ids


def test_bad_chart_detects_automount_service_account_token():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC013" in ids


def test_bad_chart_detects_host_port():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "SEC014" in ids


def test_bad_chart_detects_default_service_account():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "BP011" in ids


def test_bad_chart_detects_missing_standard_labels():
    findings = scan(FIXTURES / "bad-chart")
    ids = [f.rule_id for f in findings]
    assert "BP012" in ids


def test_good_chart_no_critical_or_high_extended():
    findings = scan(FIXTURES / "good-chart")
    bad = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert bad == [], f"Unexpected HIGH/CRITICAL findings: {bad}"


def test_json_output_requires_pro():
    result = runner.invoke(app, ["scan", str(FIXTURES / "bad-chart"), "--output", "json"])
    assert result.exit_code == 1
    assert "Pro license" in result.output


def test_json_output_structure(monkeypatch):
    monkeypatch.setattr("helmgate.cli.is_pro", lambda: True)
    result = runner.invoke(app, ["scan", str(FIXTURES / "bad-chart"), "--output", "json", "--fail-on", "NONE"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert len(data) > 0
    assert all(k in data[0] for k in ["rule_id", "severity", "path", "message", "hint"])


def test_json_output_good_chart_empty(monkeypatch):
    monkeypatch.setattr("helmgate.cli.is_pro", lambda: True)
    result = runner.invoke(app, ["scan", str(FIXTURES / "good-chart"), "--output", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
