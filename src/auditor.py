"""
IAMAuditor — orchestrates all security checks and aggregates findings.

Usage (mock mode):
    from moto import mock_aws
    import boto3
    from mock_data.generate_mock import setup_mock_iam
    from src.auditor import IAMAuditor

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        setup_mock_iam(iam)
        auditor = IAMAuditor(iam)
        results = auditor.run_all_checks()
        print(auditor.to_dict())

Usage (real AWS — credentials must be configured):
    import boto3
    from src.auditor import IAMAuditor

    iam = boto3.client("iam", region_name="us-east-1")
    auditor = IAMAuditor(iam)
    results = auditor.run_all_checks()
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.checks import (
    check_unused_access_keys,
    check_users_without_mfa,
    check_overly_permissive_policies,
    check_inactive_users,
    check_root_account_usage,
    check_password_policy,
    Finding,
)

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


class IAMAuditor:
    """
    Runs all IAM security checks against a boto3 IAM client and aggregates results.

    Args:
        iam_client: A boto3 IAM client.  Can be a real AWS client or a
                    moto-mocked client — the auditor does not care.
        unused_key_days: Threshold in days for check_unused_access_keys (default 90).
        inactive_user_days: Threshold in days for check_inactive_users (default 180).
    """

    def __init__(
        self,
        iam_client,
        unused_key_days: int = 90,
        inactive_user_days: int = 180,
    ) -> None:
        self.iam_client = iam_client
        self.unused_key_days = unused_key_days
        self.inactive_user_days = inactive_user_days
        self._findings: list[Finding] = []
        self._ran_at: datetime | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_all_checks(self) -> list[Finding]:
        """
        Execute all 6 security checks in order and return the aggregated
        findings list sorted by severity (HIGH → MEDIUM → LOW).
        """
        self._findings = []
        self._ran_at = datetime.now(timezone.utc)

        checks = [
            ("check_root_account_usage",        lambda: check_root_account_usage(self.iam_client)),
            ("check_users_without_mfa",          lambda: check_users_without_mfa(self.iam_client)),
            ("check_overly_permissive_policies", lambda: check_overly_permissive_policies(self.iam_client)),
            ("check_unused_access_keys",         lambda: check_unused_access_keys(self.iam_client, self.unused_key_days)),
            ("check_inactive_users",             lambda: check_inactive_users(self.iam_client, self.inactive_user_days)),
            ("check_password_policy",            lambda: check_password_policy(self.iam_client)),
        ]

        for name, fn in checks:
            try:
                results = fn()
                self._findings.extend(results)
            except Exception as exc:
                # Surface check errors as LOW findings so a single failing
                # check never silences the rest of the report.
                self._findings.append({
                    "severity":      "LOW",
                    "check_name":    name,
                    "resource_type": "AWSAccount",
                    "resource_name": "audit_error",
                    "description":   f"Check '{name}' raised an unexpected error: {exc}",
                    "remediation":   "Review check configuration and IAM permissions.",
                })

        self._findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
        return self._findings

    def to_dict(self) -> dict[str, Any]:
        """
        Return a structured summary dict suitable for JSON serialisation or
        passing to the reporter.

        Schema:
            {
                "ran_at":   str,           # ISO-8601 UTC timestamp
                "summary":  {
                    "total":  int,
                    "HIGH":   int,
                    "MEDIUM": int,
                    "LOW":    int,
                },
                "findings": list[Finding],
            }
        """
        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self._findings:
            sev = f.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "ran_at": self._ran_at.isoformat() if self._ran_at else None,
            "summary": {
                "total":  len(self._findings),
                "HIGH":   counts["HIGH"],
                "MEDIUM": counts["MEDIUM"],
                "LOW":    counts["LOW"],
            },
            "findings": self._findings,
        }

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def findings(self) -> list[Finding]:
        """All findings from the last run_all_checks() call."""
        return self._findings

    def findings_by_severity(self, severity: str) -> list[Finding]:
        """Return only findings matching a given severity string."""
        return [f for f in self._findings if f["severity"] == severity]
