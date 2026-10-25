"""Security report generation"""
import json
from datetime import datetime

class SecurityReport:
    """Generate security scan reports"""
    
    def __init__(self):
        self.findings = {}
    
    def add_findings(self, server_name, findings):
        """Add findings for a server"""
        self.findings[server_name] = findings
    
    def to_text(self):
        """Text report"""
        report = f"Security Scan Report\n{datetime.now()}\n\n"
        
        critical_count = 0
        high_count = 0
        
        for server, findings in self.findings.items():
            if findings:
                report += f"\n{server}:\n"
                for f in findings:
                    sev = f.get("severity", "INFO")
                    report += f"  [{sev}] {f.get('issue', 'Unknown')}\n"
                    
                    if sev == "CRITICAL":
                        critical_count += 1
                    elif sev == "HIGH":
                        high_count += 1
        
        report += f"\n\nSUMMARY: {critical_count} CRITICAL, {high_count} HIGH\n"
        return report
    
    def to_dict(self):
        """Dict representation"""
        return self.findings
