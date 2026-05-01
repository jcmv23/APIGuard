"""
APIGuard Enterprise — CI/CD Integration
==========================================
Provides:
  - SARIF output for GitHub Code Scanning integration
  - Exit code logic for pipeline gates (fail on CRITICAL/HIGH)
  - CLI-friendly scan summary
"""

import json
import time
from typing import Optional


class SARIFExporter:
    """Export scan results in SARIF 2.1.0 format for GitHub Code Scanning."""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    def __init__(self, report: dict):
        self.report = report

    def to_sarif(self) -> dict:
        """Convert the scan report to SARIF format."""
        rules = []
        results = []
        rule_ids = set()

        for mod_name, mod_data in self.report.get("modules", {}).items():
            if not isinstance(mod_data, dict):
                continue
            for finding in mod_data.get("findings", []):
                vuln_type = finding.get("vulnerability_type", finding.get("finding_type", "UNKNOWN"))
                rule_id = f"apiguard/{vuln_type.lower().replace(' ', '_')}"

                if rule_id not in rule_ids:
                    rule_ids.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "name": vuln_type,
                        "shortDescription": {"text": vuln_type.replace("_", " ").title()},
                        "fullDescription": {"text": finding.get("description", vuln_type)},
                        "defaultConfiguration": {
                            "level": self.SEVERITY_MAP.get(finding.get("severity", "MEDIUM"), "warning")
                        },
                        "helpUri": "https://owasp.org/API-Security/",
                        "properties": {
                            "tags": ["security", "api", "owasp"],
                            "security-severity": self._sev_score(finding.get("severity", "MEDIUM"))
                        }
                    })

                results.append({
                    "ruleId": rule_id,
                    "level": self.SEVERITY_MAP.get(finding.get("severity", "MEDIUM"), "warning"),
                    "message": {"text": finding.get("description", "Security issue detected")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("endpoint", finding.get("path", self.report.get("target", "/")))
                            }
                        }
                    }],
                    "properties": {
                        "severity": finding.get("severity", "MEDIUM"),
                        "module": mod_name,
                        "remediation": finding.get("remediation", ""),
                        "proof": finding.get("proof", "")[:500],
                    }
                })

        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "APIGuard Enterprise",
                        "version": self.report.get("version", "2.0.0"),
                        "informationUri": "https://github.com/apiguard",
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": self.report.get("scan_date", time.strftime("%Y-%m-%dT%H:%M:%SZ"))
                }]
            }]
        }

    def to_json(self) -> str:
        return json.dumps(self.to_sarif(), indent=2)

    @staticmethod
    def _sev_score(severity: str) -> str:
        return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "1.0"}.get(severity, "5.0")


def compute_exit_code(report: dict, fail_on: str = "HIGH") -> int:
    """Compute CI exit code based on findings severity.
    
    Args:
        report: Scan report
        fail_on: Minimum severity to fail: CRITICAL, HIGH, MEDIUM, LOW
    
    Returns:
        0 = pass, 1 = fail (findings at or above threshold)
    """
    threshold = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(fail_on.upper(), 3)
    sev_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for mod_data in report.get("modules", {}).values():
        if not isinstance(mod_data, dict):
            continue
        for finding in mod_data.get("findings", []):
            sev = finding.get("severity", "LOW").upper()
            if sev_levels.get(sev, 0) >= threshold:
                return 1  # FAIL
    return 0  # PASS


def format_ci_summary(report: dict) -> str:
    """Format a CLI-friendly summary for CI logs."""
    lines = [
        "=" * 60,
        "  APIGuard Security Gate — Scan Summary",
        "=" * 60,
        f"  Target:  {report.get('target', 'N/A')}",
        f"  Date:    {report.get('scan_date', 'N/A')}",
        "",
    ]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for mod_data in report.get("modules", {}).values():
        if not isinstance(mod_data, dict):
            continue
        for f in mod_data.get("findings", []):
            sev = f.get("severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1

    total = sum(counts.values())
    lines.append(f"  Total Findings: {total}")
    lines.append(f"  CRITICAL: {counts['CRITICAL']}  |  HIGH: {counts['HIGH']}  |  MEDIUM: {counts['MEDIUM']}  |  LOW: {counts['LOW']}")
    lines.append("")

    exit_code = compute_exit_code(report)
    if exit_code == 0:
        lines.append("  Result: ✅ PASSED — No critical/high vulnerabilities")
    else:
        lines.append("  Result: ❌ FAILED — Critical/high vulnerabilities detected")

    lines.append("=" * 60)
    return "\n".join(lines)
