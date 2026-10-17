import json
import re
from typing import List
from datetime import datetime
from .scanner import Check, RiskLevel

# SARIF severity mappings. `level` is the SARIF result level; `security-severity`
# is the numeric string GitHub code scanning uses to bucket findings.
SARIF_LEVEL = {
    RiskLevel.CRITICAL: "error", RiskLevel.HIGH: "error",
    RiskLevel.MEDIUM: "warning", RiskLevel.LOW: "note", RiskLevel.INFO: "note",
}
SECURITY_SEVERITY = {
    RiskLevel.CRITICAL: "9.5", RiskLevel.HIGH: "8.0",
    RiskLevel.MEDIUM: "5.0", RiskLevel.LOW: "3.0", RiskLevel.INFO: "0.0",
}
_TOOL_URI = "https://github.com/LHMisme420/mcp-authscan"


def _rule_id(name: str) -> str:
    return "mcp-authscan/" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def build_sarif(per_target, tool_version: str = "0.0.0") -> dict:
    """Build a SARIF 2.1.0 document from [(target_url, [Check, ...]), ...].

    Only failed checks become SARIF results (findings); passed checks are not
    emitted. Works for a single target or a whole fleet (all results land in
    one run). The endpoint URL is used as the result's artifact location.
    """
    rules, results = {}, []
    for target, checks in per_target:
        base = target.rstrip("/")
        for c in checks:
            if c.passed:
                continue
            rid = _rule_id(c.name)
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": re.sub(r"[^A-Za-z0-9]+", "", c.name),
                    "shortDescription": {"text": c.name},
                    "fullDescription": {"text": c.description or c.name},
                    "helpUri": _TOOL_URI,
                    "defaultConfiguration": {"level": SARIF_LEVEL[c.risk_level]},
                    "properties": {"security-severity": SECURITY_SEVERITY[c.risk_level]},
                }
            endpoint = "" if c.endpoint in (None, "*") else c.endpoint
            results.append({
                "ruleId": rid,
                "level": SARIF_LEVEL[c.risk_level],
                "message": {"text": f"{c.name} on {c.endpoint}: {c.details} "
                                    f"Remediation: {c.remediation}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": base + endpoint},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{
                        "fullyQualifiedName": f"{base}{c.endpoint}", "kind": "resource"}],
                }],
                "properties": {"target": target, "endpoint": c.endpoint,
                               "risk_level": c.risk_level.value},
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-authscan",
                "informationUri": _TOOL_URI,
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }

class SecurityReport:
    def __init__(self, checks: List[Check], target_url: str):
        self.checks = checks
        self.target_url = target_url
        self.timestamp = datetime.utcnow().isoformat()
    
    def summary(self) -> dict:
        critical = len([c for c in self.checks if c.risk_level == RiskLevel.CRITICAL])
        high = len([c for c in self.checks if c.risk_level == RiskLevel.HIGH])
        passed = len([c for c in self.checks if c.passed])
        return {
            "target": self.target_url,
            "timestamp": self.timestamp,
            "total_checks": len(self.checks),
            "passed": passed,
            "failed": len(self.checks) - passed,
            "critical": critical,
            "high": high
        }
    
    def text(self) -> str:
        lines = [
            "=" * 80,
            "MCP SECURITY SCAN REPORT",
            "=" * 80,
            f"\nTarget: {self.target_url}",
            f"Scan Time: {self.timestamp}",
            f"\nSummary:",
        ]
        summary = self.summary()
        lines.extend([
            f"  Total Checks: {summary['total_checks']}",
            f"  Passed: {summary['passed']}",
            f"  Failed: {summary['failed']}",
            f"  CRITICAL: {summary['critical']}",
            f"  HIGH: {summary['high']}",
            f"",
            "-" * 80,
            "FINDINGS:",
            "-" * 80,
        ])
        by_risk = {}
        for check in self.checks:
            if check.risk_level not in by_risk:
                by_risk[check.risk_level] = []
            by_risk[check.risk_level].append(check)
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
            if risk_level in by_risk:
                lines.append(f"\n[{risk_level.value}]")
                for check in by_risk[risk_level]:
                    status = "✗ FAILED" if not check.passed else "✓ PASSED"
                    lines.extend([
                        f"  {status} - {check.name}",
                        f"    Endpoint: {check.endpoint}",
                        f"    Details: {check.details}",
                        f"    Remediation: {check.remediation}",
                        ""
                    ])
        lines.extend(["=" * 80, "END REPORT", "=" * 80])
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "checks": [{
                "name": c.name,
                "endpoint": c.endpoint,
                "risk_level": c.risk_level.value,
                "passed": c.passed,
                "details": c.details,
                "remediation": c.remediation
            } for c in self.checks]
        }

    def json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
