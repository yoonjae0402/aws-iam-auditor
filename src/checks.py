"""
Security check functions for IAM resources.

Each function takes a boto3 IAM client and returns list[Finding].

Finding schema:
    {
        "severity":      str,   # "HIGH" | "MEDIUM" | "LOW"
        "check_name":    str,   # snake_case identifier
        "resource_type": str,   # "IAMUser" | "IAMPolicy" | "AWSAccount"
        "resource_name": str,   # username, policy name, or "root"
        "description":   str,   # human-readable explanation
        "remediation":   str,   # actionable fix
    }

CIS AWS Foundations Benchmark references are noted per check.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Any

from botocore.exceptions import ClientError


Finding = dict[str, Any]

_CHECK_UNUSED_KEYS      = "unused_access_keys"
_CHECK_NO_MFA           = "users_without_mfa"
_CHECK_OVERLY_PERMISSIVE = "overly_permissive_policies"
_CHECK_INACTIVE_USERS   = "inactive_users"
_CHECK_ROOT_USAGE       = "root_account_usage"
_CHECK_PASSWORD_POLICY  = "password_policy"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _paginate(iam_client, method_name: str, result_key: str, **kwargs) -> list:
    """Exhaust a paginated IAM list call and return all results."""
    paginator = iam_client.get_paginator(method_name)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page[result_key])
    return results


def _user_tags(iam_client, username: str) -> dict[str, str]:
    """Return a flat {key: value} dict of all tags on an IAM user."""
    tags = iam_client.list_user_tags(UserName=username)["Tags"]
    return {t["Key"]: t["Value"] for t in tags}


def _finding(
    check_name: str,
    severity: str,
    resource_type: str,
    resource_name: str,
    description: str,
    remediation: str,
) -> Finding:
    return {
        "severity":      severity,
        "check_name":    check_name,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "description":   description,
        "remediation":   remediation,
    }


def _as_list(value) -> list:
    """Normalise IAM policy Action/Resource — can be a string or a list."""
    if isinstance(value, list):
        return value
    return [value]


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Check 1 — Unused / stale access keys
# CIS AWS Foundations Benchmark 1.14
# ---------------------------------------------------------------------------

def check_unused_access_keys(iam_client, days: int = 90) -> list[Finding]:
    """
    CIS 1.14 — Ensure access keys are rotated every 90 days or less.

    Flags every active access key whose effective age exceeds `days`.
    In real AWS the key's CreateDate is used; when running against a moto
    mock the tag ``mock:access_key_age_days`` (set by generate_mock.py)
    is used instead because moto always stamps keys with today's date.

    Severity: MEDIUM
    """
    findings = []
    threshold = timedelta(days=days)
    now = _now()

    users = _paginate(iam_client, "list_users", "Users")

    for user in users:
        username = user["UserName"]
        tags = _user_tags(iam_client, username)
        mock_age = tags.get("mock:access_key_age_days")

        keys = _paginate(
            iam_client, "list_access_keys", "AccessKeyMetadata",
            UserName=username,
        )

        for key in keys:
            if key["Status"] != "Active":
                continue

            key_id = key["AccessKeyId"]

            # Determine effective key age: prefer synthetic mock tag over real
            # CreateDate (moto stamps all keys with today so real dates are useless
            # in mock mode).
            if mock_age is not None:
                key_age_days = int(mock_age)
                effective_age = timedelta(days=key_age_days)
            else:
                create_date = _ensure_tz(key["CreateDate"])
                effective_age = now - create_date
                key_age_days = effective_age.days

            if effective_age < threshold:
                continue

            # Provide context on whether the key was ever used.
            last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")

            if last_used_date is not None:
                last_used_date = _ensure_tz(last_used_date)
                days_since_used = (now - last_used_date).days
                usage_context = f"last used {days_since_used} day(s) ago"
            else:
                usage_context = "never used"

            findings.append(_finding(
                check_name=_CHECK_UNUSED_KEYS,
                severity="MEDIUM",
                resource_type="IAMUser",
                resource_name=username,
                description=(
                    f"Active access key {key_id} for user '{username}' is {key_age_days} day(s) old "
                    f"({usage_context}). Keys should be rotated every {days} days."
                ),
                remediation=(
                    "Rotate the key: (1) create a new access key, (2) update all applications "
                    "or scripts to use the new key, (3) deactivate the old key, (4) verify "
                    "nothing breaks, then (5) delete the old key."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 2 — Console users without MFA
# CIS AWS Foundations Benchmark 1.10
# ---------------------------------------------------------------------------

def check_users_without_mfa(iam_client) -> list[Finding]:
    """
    CIS 1.10 — Ensure MFA is enabled for all IAM users that have a console password.

    Only flags users with an active login profile (console access).
    Programmatic-only users (no login profile) are excluded; use
    check_unused_access_keys for their key hygiene.

    Severity: HIGH
    """
    findings = []
    users = _paginate(iam_client, "list_users", "Users")

    for user in users:
        username = user["UserName"]

        # Skip users that have no console login profile (programmatic-only).
        try:
            iam_client.get_login_profile(UserName=username)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            raise

        mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]

        if not mfa_devices:
            findings.append(_finding(
                check_name=_CHECK_NO_MFA,
                severity="HIGH",
                resource_type="IAMUser",
                resource_name=username,
                description=(
                    f"IAM user '{username}' has console access but no MFA device is enabled."
                ),
                remediation=(
                    f"Assign an MFA device: IAM console → Users → {username} → "
                    "Security credentials → Assign MFA device. "
                    "Enforce via IAM policy: deny all actions unless aws:MultiFactorAuthPresent is true."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 3 — Overly permissive customer-managed policies
# CIS AWS Foundations Benchmark 1.22
# ---------------------------------------------------------------------------

def _classify_statement_permissiveness(stmt: dict) -> str | None:
    """
    Return a severity string if a single policy statement is overly broad, else None.

    Rules (in priority order):
      HIGH   — Effect Allow + Action "*" + Resource "*"  (full admin wildcard)
      MEDIUM — Effect Allow + any service wildcard (e.g. "s3:*", "iam:*") + Resource "*"
    """
    if stmt.get("Effect") != "Allow":
        return None

    actions   = _as_list(stmt.get("Action",   []))
    resources = _as_list(stmt.get("Resource", []))

    has_full_wildcard_action   = "*" in actions
    has_wildcard_resource      = "*" in resources
    has_service_wildcard_action = any(
        a != "*" and a.endswith(":*") for a in actions
    )

    if has_full_wildcard_action and has_wildcard_resource:
        return "HIGH"
    if has_service_wildcard_action and has_wildcard_resource:
        return "MEDIUM"
    return None


def check_overly_permissive_policies(iam_client) -> list[Finding]:
    """
    CIS 1.22 — Ensure IAM policies that allow full "*:*" administrative privileges
    are not attached.

    Scans only customer-managed policies (Scope='Local').  For each policy,
    inspects every statement in the default version's document.  Two tiers:

      HIGH   — Action "*" + Resource "*"  (unrestricted admin access)
      MEDIUM — Service-level wildcard (e.g. "s3:*") + Resource "*"

    Severity: HIGH or MEDIUM (per statement)
    """
    findings = []
    policies = _paginate(iam_client, "list_policies", "Policies", Scope="Local")

    for policy in policies:
        policy_name = policy["PolicyName"]
        policy_arn  = policy["Arn"]
        version_id  = policy["DefaultVersionId"]

        doc = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        )["PolicyVersion"]["Document"]

        # Document may come back as a dict (already parsed) or a URL-encoded string.
        if isinstance(doc, str):
            doc = json.loads(doc)

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        worst_severity = None
        for stmt in statements:
            sev = _classify_statement_permissiveness(stmt)
            if sev == "HIGH":
                worst_severity = "HIGH"
                break
            if sev == "MEDIUM":
                worst_severity = "MEDIUM"

        if worst_severity is None:
            continue

        label = "full admin wildcard (Action:* + Resource:*)" if worst_severity == "HIGH" \
            else "service-level wildcard action on all resources"

        findings.append(_finding(
            check_name=_CHECK_OVERLY_PERMISSIVE,
            severity=worst_severity,
            resource_type="IAMPolicy",
            resource_name=policy_name,
            description=(
                f"Customer-managed policy '{policy_name}' grants {label}. "
                f"ARN: {policy_arn}"
            ),
            remediation=(
                "Apply the principle of least privilege: replace wildcard actions/resources "
                "with the specific actions and resource ARNs the policy actually needs. "
                "Use the IAM Access Analyzer policy generation feature to derive a minimal policy."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 4 — Inactive console users
# CIS AWS Foundations Benchmark 1.15
# ---------------------------------------------------------------------------

def check_inactive_users(iam_client, days: int = 180) -> list[Finding]:
    """
    CIS 1.15 — Ensure IAM users are removed or deactivated if unused for 45+ days
    (this implementation uses a configurable threshold, default 180 days).

    Checks PasswordLastUsed on users with console access.  When running
    against a moto mock the tag ``mock:last_active_days`` is used as a
    substitute because moto does not populate PasswordLastUsed.

    Severity: LOW
    """
    findings = []
    threshold = timedelta(days=days)
    now = _now()

    users = _paginate(iam_client, "list_users", "Users")

    for user in users:
        username = user["UserName"]

        # Only check users with console access.
        try:
            iam_client.get_login_profile(UserName=username)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            raise

        tags = _user_tags(iam_client, username)
        mock_inactive_days = tags.get("mock:last_active_days")

        if mock_inactive_days is not None:
            # Mock mode: tag carries synthetic last-active age.
            inactive_days = int(mock_inactive_days)
            if inactive_days < days:
                continue
            detail = f"last active {inactive_days} day(s) ago (mock data)"
        else:
            # Real AWS: use PasswordLastUsed from the user record.
            password_last_used = user.get("PasswordLastUsed")
            if password_last_used is None:
                # Never logged in — treat creation date as last activity.
                create_date = _ensure_tz(user["CreateDate"])
                inactive_days = (now - create_date).days
                if inactive_days < days:
                    continue
                detail = f"console password has never been used (account {inactive_days}d old)"
            else:
                password_last_used = _ensure_tz(password_last_used)
                inactive_days = (now - password_last_used).days
                if inactive_days < days:
                    continue
                detail = f"last console login {inactive_days} day(s) ago"

        findings.append(_finding(
            check_name=_CHECK_INACTIVE_USERS,
            severity="LOW",
            resource_type="IAMUser",
            resource_name=username,
            description=(
                f"IAM user '{username}' appears inactive: {detail}. "
                f"Threshold is {days} day(s)."
            ),
            remediation=(
                "Confirm whether the user still needs access. If not, disable the "
                "login profile and deactivate access keys, or delete the user entirely. "
                "Use IAM Access Advisor to verify the last service access dates."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 5 — Root account access keys and MFA
# CIS AWS Foundations Benchmark 1.4 + 1.5
# ---------------------------------------------------------------------------

def check_root_account_usage(iam_client) -> list[Finding]:
    """
    CIS 1.4 — Ensure no root account access key exists.
    CIS 1.5 — Ensure MFA is enabled for the root account.

    Uses get_account_summary() which does not require the caller to be root.

    Severity: HIGH
    """
    findings = []

    summary = iam_client.get_account_summary()["SummaryMap"]

    # CIS 1.4 — root access keys
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(_finding(
            check_name=_CHECK_ROOT_USAGE,
            severity="HIGH",
            resource_type="AWSAccount",
            resource_name="root",
            description=(
                "The root account has one or more active access keys. "
                "Root access keys provide unrestricted access to every AWS service "
                "and cannot be restricted by IAM policies."
            ),
            remediation=(
                "Delete all root account access keys immediately: AWS Console → "
                "account menu → Security credentials → Access keys → Delete. "
                "Create a dedicated IAM user with only the permissions required for daily tasks."
            ),
        ))

    # CIS 1.5 — root MFA
    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(_finding(
            check_name=_CHECK_ROOT_USAGE,
            severity="HIGH",
            resource_type="AWSAccount",
            resource_name="root",
            description=(
                "The root account does not have MFA enabled. "
                "Root account compromise without MFA allows an attacker immediate, "
                "unrestricted access to all AWS resources."
            ),
            remediation=(
                "Enable MFA on the root account: AWS Console → account menu → "
                "Security credentials → Multi-factor authentication (MFA) → Activate MFA. "
                "A hardware MFA device is recommended for root."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 6 — Account password policy
# CIS AWS Foundations Benchmark 1.8 – 1.11
# ---------------------------------------------------------------------------

# CIS-recommended minimums
_PW_MIN_LENGTH            = 14
_PW_MAX_AGE_DAYS          = 90
_PW_REUSE_PREVENTION      = 24

_PW_REQUIREMENTS: list[tuple[str, Any, str, str]] = [
    # (policy_key, required_value, label, remediation_hint)
    ("MinimumPasswordLength",      _PW_MIN_LENGTH,       "minimum length ≥ 14 characters",     f"set MinimumPasswordLength to {_PW_MIN_LENGTH}"),
    ("RequireSymbols",             True,                  "requires symbols",                   "enable RequireSymbols"),
    ("RequireNumbers",             True,                  "requires numbers",                   "enable RequireNumbers"),
    ("RequireUppercaseCharacters", True,                  "requires uppercase letters",          "enable RequireUppercaseCharacters"),
    ("RequireLowercaseCharacters", True,                  "requires lowercase letters",          "enable RequireLowercaseCharacters"),
    ("AllowUsersToChangePassword", True,                  "allows users to change their password","enable AllowUsersToChangePassword"),
    ("MaxPasswordAge",             _PW_MAX_AGE_DAYS,     f"max password age ≤ {_PW_MAX_AGE_DAYS} days", f"set MaxPasswordAge to {_PW_MAX_AGE_DAYS}"),
    ("PasswordReusePrevention",    _PW_REUSE_PREVENTION, f"prevents reuse of last {_PW_REUSE_PREVENTION} passwords", f"set PasswordReusePrevention to {_PW_REUSE_PREVENTION}"),
]


def check_password_policy(iam_client) -> list[Finding]:
    """
    CIS 1.8–1.11 — Ensure a strong IAM account password policy is configured.

    Checks for: minimum length, symbol/number/case requirements, password
    expiry, and reuse prevention.  A missing policy entirely is also flagged.

    Severity: MEDIUM
    """
    findings = []

    try:
        policy = iam_client.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchEntity", "NoSuchEntityException"):
            findings.append(_finding(
                check_name=_CHECK_PASSWORD_POLICY,
                severity="MEDIUM",
                resource_type="AWSAccount",
                resource_name="password_policy",
                description=(
                    "No IAM account password policy is configured. "
                    "Without a policy, IAM users can set any password with no complexity, "
                    "expiry, or reuse restrictions."
                ),
                remediation=(
                    "Create a password policy: IAM console → Account settings → "
                    "Edit password policy, or via CLI: "
                    "aws iam update-account-password-policy --minimum-password-length 14 "
                    "--require-symbols --require-numbers --require-uppercase-characters "
                    "--require-lowercase-characters --max-password-age 90 "
                    "--password-reuse-prevention 24"
                ),
            ))
            return findings
        raise

    failures = []
    for key, required, label, hint in _PW_REQUIREMENTS:
        actual = policy.get(key)

        if key == "MaxPasswordAge":
            # MaxPasswordAge of 0 means disabled (no expiry) — that's a failure.
            # Otherwise must be ≤ required.
            if actual is None or actual == 0 or actual > required:
                failures.append((label, hint))
        elif key in ("MinimumPasswordLength", "PasswordReusePrevention"):
            if actual is None or actual < required:
                failures.append((label, hint))
        else:
            # Boolean requirements
            if not actual:
                failures.append((label, hint))

    for label, hint in failures:
        findings.append(_finding(
            check_name=_CHECK_PASSWORD_POLICY,
            severity="MEDIUM",
            resource_type="AWSAccount",
            resource_name="password_policy",
            description=(
                f"Account password policy does not meet CIS benchmark: missing '{label}'."
            ),
            remediation=(
                f"Update the password policy to {hint}. "
                "See: aws iam update-account-password-policy --help"
            ),
        ))

    return findings
