import json
from typing import List
from datetime import datetime
from .scanner import Check, RiskLevel

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
