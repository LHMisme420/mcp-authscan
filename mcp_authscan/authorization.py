"""
Authorization tracking and metadata for security scan reports.
Provides chain-of-custody for compliance audits and regulatory requirements.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional


class ScanAuthorization:
    """Tracks who authorized the scan and under what authority."""

    def __init__(
        self,
        authorized_by: str,
        client_name: str,
        client_title: str,
        auth_basis: str,
        ticket_ref: str,
        contact: str,
        scan_date: Optional[str] = None
    ):
        self.authorized_by = authorized_by
        self.client_name = client_name
        self.client_title = client_title
        self.auth_basis = auth_basis
        self.ticket_ref = ticket_ref
        self.contact = contact
        self.scan_date = scan_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def to_dict(self) -> dict:
        return {
            "authorized_by": self.authorized_by,
            "client_name": self.client_name,
            "client_title": self.client_title,
            "auth_basis": self.auth_basis,
            "ticket_ref": self.ticket_ref,
            "contact": self.contact,
            "scan_date": self.scan_date,
        }

    def format_block(self) -> str:
        """Generate the authorization block for report headers."""
        lines = [
            "AUTHORIZATION BLOCK",
            "-" * 80,
            f"Authorized By: {self.authorized_by}",
            f"Client Name: {self.client_name}",
            f"Client Title: {self.client_title}",
            f"Authorization Basis: {self.auth_basis}",
            f"Ticket Reference: {self.ticket_ref}",
            f"Contact: {self.contact}",
            f"Scan Date: {self.scan_date}",
            "-" * 80,
        ]
        return "\n".join(lines)


class ScanMetadata:
    """Metadata about the scan itself."""

    def __init__(
        self,
        scope: str,
        probe_set_version: str = "1.0.0",
        not_tested: Optional[list] = None,
        repo_url: Optional[str] = None,
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        files_examined: Optional[int] = None,
        files_total: Optional[int] = None,
        files_excluded: Optional[list] = None,
        lines_examined: Optional[int] = None,
        target: Optional[str] = None,
        probes_attempted: Optional[int] = None,
        probes_passed: Optional[int] = None,
        probes_not_observed: Optional[int] = None,
        elapsed_seconds: Optional[float] = None
    ):
        self.scope = scope
        self.probe_set_version = probe_set_version
        self.not_tested = not_tested or []
        self.repo_url = repo_url
        self.branch = branch
        self.commit_sha = commit_sha
        self.files_examined = files_examined
        self.files_total = files_total
        self.files_excluded = files_excluded or []
        self.lines_examined = lines_examined
        self.target = target
        self.probes_attempted = probes_attempted
        self.probes_passed = probes_passed
        self.probes_not_observed = probes_not_observed
        self.elapsed_seconds = elapsed_seconds

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "probe_set_version": self.probe_set_version,
            "not_tested": self.not_tested,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
        }

    def format_block(self) -> str:
        """Generate the metadata block for reports."""
        lines = [
            "SCAN METADATA",
            "-" * 80,
        ]

        # Target
        if self.target:
            lines.append(f"Target: {self.target}")

        # Repository information
        if self.repo_url:
            lines.append(f"Repository: {self.repo_url}")
        if self.branch:
            lines.append(f"Branch: {self.branch}")
        if self.commit_sha:
            lines.append(f"Commit SHA: {self.commit_sha}")

        lines.append(f"Scope: {self.scope}")
        lines.append(f"Probe Set Version: {self.probe_set_version}")

        # Probe telemetry
        if self.probes_attempted is not None:
            lines.append(f"Probes Attempted: {self.probes_attempted}")
            if self.probes_passed is not None:
                lines.append(f"Probes Passed: {self.probes_passed}")
            if self.probes_not_observed is not None:
                lines.append(f"Probes Not Observed: {self.probes_not_observed}")
        if self.elapsed_seconds is not None:
            lines.append(f"Elapsed Time: {self.elapsed_seconds:.2f} seconds")

        # Examination metrics with coverage
        if self.files_examined is not None and self.files_total is not None:
            lines.append(f"Files Examined: {self.files_examined} of {self.files_total}")
            if self.files_excluded:
                lines.append(f"Excluded Categories: {', '.join(self.files_excluded)}")
        elif self.files_examined is not None:
            lines.append(f"Files Examined: {self.files_examined}")

        if self.lines_examined is not None:
            lines.append(f"Lines of Code Examined: {self.lines_examined}")

        # Out-of-scope items (honest about limitations)
        if self.not_tested:
            lines.append("")
            lines.append("Not Tested Explicitly:")
            for item in self.not_tested:
                lines.append(f"  - {item}")

        lines.append("-" * 80)
        return "\n".join(lines)


def compute_content_hash(content: str) -> str:
    """Compute SHA256 hash of report content for integrity verification."""
    return hashlib.sha256(content.encode()).hexdigest()


def report_header_with_authorization(
    authorization: ScanAuthorization,
    metadata: ScanMetadata,
    findings_count: int,
    findings_by_severity: dict
) -> str:
    """Generate complete report header with authorization and metadata."""
    lines = [
        "=" * 80,
        "MCP-AUTHSCAN SECURITY REPORT",
        "=" * 80,
        "",
        authorization.format_block(),
        "",
        metadata.format_block(),
        "",
        "FINDINGS SUMMARY",
        "-" * 80,
    ]

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = findings_by_severity.get(severity, 0)
        lines.append(f"  {severity}: {count}")

    lines.append(f"  TOTAL: {findings_count}")
    lines.append("-" * 80)

    return "\n".join(lines)
