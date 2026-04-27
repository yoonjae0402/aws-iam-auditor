"""
Populate a moto-mocked AWS IAM environment with realistic test data.

Run standalone:
    python mock_data/generate_mock.py

Or import and call setup_mock_iam() from within a moto context in tests/CLI.
"""

import json
import boto3
from datetime import datetime, timezone, timedelta
from moto import mock_aws


# ---------------------------------------------------------------------------
# Scenario data
# ---------------------------------------------------------------------------

# (username, has_mfa, days_since_last_activity, access_key_age_days, notes)
USERS = [
    # Healthy users
    ("alice.johnson",   True,  5,   30,  "active dev, compliant"),
    ("bob.smith",       True,  12,  45,  "active dev, compliant"),
    # No MFA
    ("carol.white",     False, 3,   20,  "no MFA — HIGH finding"),
    ("dave.chen",       False, 8,   15,  "no MFA — HIGH finding"),
    # Old access keys (>90 days)
    ("eve.martinez",    True,  10,  120, "key 120d old — MEDIUM finding"),
    ("frank.lee",       True,  20,  180, "key 180d old — MEDIUM finding"),
    # Inactive users (no activity >90 days)
    ("grace.kim",       True,  95,  200, "inactive 95d + old key — two findings"),
    ("henry.nguyen",    False, 100, 210, "inactive + no MFA + old key — three findings"),
    # Privileged / service accounts
    ("svc.deploy",      False, 2,   365, "service acct, no MFA, ancient key"),
    ("admin.backup",    True,  60,  60,  "admin user, MFA ok, key ok"),
]

# (role_name, description, days_since_last_used)
ROLES = [
    ("EC2InstanceRole",       "Attached to EC2 instances for S3 read access",  5),
    ("LambdaExecutionRole",   "Lambda basic execution + CloudWatch logs",       1),
    ("DevOpsDeployRole",      "CI/CD pipeline deployment role",                14),
    ("DataScienceRole",       "S3 full access + SageMaker for ML team",        30),
    ("OrphanedOldRole",       "Legacy role from 2021 migration, unused",       400),
]

# (policy_name, is_overly_permissive, description, document)
POLICIES = [
    (
        "S3ReadOnlyAccess",
        False,
        "Read-only access to a specific S3 bucket",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    "arn:aws:s3:::my-company-data",
                    "arn:aws:s3:::my-company-data/*",
                ],
            }],
        },
    ),
    (
        "CloudWatchLogsWrite",
        False,
        "Write logs to a specific log group",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*",
            }],
        },
    ),
    (
        "EC2DescribeOnly",
        False,
        "Describe EC2 resources — read-only",
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["ec2:Describe*"],
                "Resource": "*",   # Describe actions require * resource — acceptable
            }],
        },
    ),
    (
        "AdminWildcardPolicy",
        True,
        "DANGEROUS: full wildcard admin access",  # CRITICAL finding
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        },
    ),
    (
        "S3WildcardAllBuckets",
        True,
        "DANGEROUS: all S3 actions on all buckets",  # HIGH finding
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            }],
        },
    ),
    (
        "IAMFullAccess",
        True,
        "DANGEROUS: full IAM control — privilege escalation risk",  # HIGH finding
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
            }],
        },
    ),
    (
        "DataScienceS3SageMaker",
        False,
        "Scoped access to ML team S3 prefix and SageMaker",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": [
                        "arn:aws:s3:::ml-datasets",
                        "arn:aws:s3:::ml-datasets/*",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["sagemaker:CreateTrainingJob", "sagemaker:DescribeTrainingJob"],
                    "Resource": "*",
                },
            ],
        },
    ),
    (
        "WildcardResourcePolicy",
        True,
        "DANGEROUS: specific actions but unrestricted resource scope",  # MEDIUM finding
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                ],
                "Resource": "*",  # should be scoped to specific ARNs
            }],
        },
    ),
]

# Which policies to attach to which users (username -> [policy_name, ...])
USER_POLICY_ATTACHMENTS = {
    "admin.backup":   ["AdminWildcardPolicy"],
    "svc.deploy":     ["S3WildcardAllBuckets", "IAMFullAccess"],
    "alice.johnson":  ["S3ReadOnlyAccess", "CloudWatchLogsWrite"],
    "bob.smith":      ["EC2DescribeOnly"],
    "grace.kim":      ["DataScienceS3SageMaker"],
    "henry.nguyen":   ["WildcardResourcePolicy"],
}

# Which policies to attach to which roles (role_name -> [policy_name, ...])
ROLE_POLICY_ATTACHMENTS = {
    "EC2InstanceRole":     ["S3ReadOnlyAccess"],
    "LambdaExecutionRole": ["CloudWatchLogsWrite"],
    "DevOpsDeployRole":    ["S3WildcardAllBuckets"],  # another finding on a role
    "DataScienceRole":     ["DataScienceS3SageMaker"],
    "OrphanedOldRole":     ["EC2DescribeOnly"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _days_ago(n: int) -> str:
    """Return an ISO-8601 UTC timestamp string n days in the past."""
    dt = datetime.now(timezone.utc) - timedelta(days=n)
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _trust_policy(service: str) -> str:
    """Return a JSON trust policy document for a given AWS service principal."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": f"{service}.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    return json.dumps(doc)


# ---------------------------------------------------------------------------
# Setup function — can be called inside any moto context
# ---------------------------------------------------------------------------

def setup_mock_iam(iam_client=None) -> dict:
    """
    Populate mocked IAM with users, roles, policies, keys, and group memberships.

    Args:
        iam_client: an already-created boto3 IAM client (must be inside a moto
                    mock context). If None, one is created — useful when running
                    this script standalone with @mock_aws applied by __main__.

    Returns:
        A summary dict describing what was created.
    """
    if iam_client is None:
        iam_client = boto3.client("iam", region_name="us-east-1")

    created = {"users": [], "roles": [], "policies": [], "keys": []}

    # -- Policies ------------------------------------------------------------
    policy_arns: dict[str, str] = {}
    for name, _, description, document in POLICIES:
        resp = iam_client.create_policy(
            PolicyName=name,
            PolicyDocument=json.dumps(document),
            Description=description,
        )
        arn = resp["Policy"]["Arn"]
        policy_arns[name] = arn
        created["policies"].append(name)
        print(f"  [policy]  {name}")

    # -- Users ---------------------------------------------------------------
    for username, has_mfa, last_active_days, key_age_days, notes in USERS:
        iam_client.create_user(UserName=username)

        # Create login profile (console access) for all non-service accounts
        if not username.startswith("svc."):
            iam_client.create_login_profile(
                UserName=username,
                Password="Temp@12345!",
                PasswordResetRequired=False,
            )

        # Virtual MFA device — moto supports create + enable
        if has_mfa:
            serial = f"arn:aws:iam::123456789012:mfa/{username}"
            iam_client.create_virtual_mfa_device(VirtualMFADeviceName=username)
            iam_client.enable_mfa_device(
                UserName=username,
                SerialNumber=serial,
                AuthenticationCode1="123456",
                AuthenticationCode2="789012",
            )

        # Access key — moto always creates with today's date; we tag age in metadata
        key_resp = iam_client.create_access_key(UserName=username)
        key_id = key_resp["AccessKey"]["AccessKeyId"]
        created["keys"].append({"user": username, "key_id": key_id, "age_days": key_age_days})

        # Tag users with synthetic metadata so the auditor can use them in checks
        iam_client.tag_user(
            UserName=username,
            Tags=[
                {"Key": "mock:last_active_days",  "Value": str(last_active_days)},
                {"Key": "mock:access_key_age_days", "Value": str(key_age_days)},
                {"Key": "mock:notes",              "Value": notes},
            ],
        )

        created["users"].append(username)
        print(f"  [user]    {username:20s}  mfa={str(has_mfa):<5}  inactive={last_active_days}d  key_age={key_age_days}d")

    # -- Attach policies to users --------------------------------------------
    for username, policy_names in USER_POLICY_ATTACHMENTS.items():
        for pname in policy_names:
            iam_client.attach_user_policy(
                UserName=username,
                PolicyArn=policy_arns[pname],
            )
            print(f"  [attach]  {pname} -> user:{username}")

    # -- Roles ---------------------------------------------------------------
    service_map = {
        "EC2InstanceRole":     "ec2",
        "LambdaExecutionRole": "lambda",
        "DevOpsDeployRole":    "ec2",
        "DataScienceRole":     "sagemaker",
        "OrphanedOldRole":     "ec2",
    }
    for role_name, description, last_used_days in ROLES:
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=_trust_policy(service_map[role_name]),
            Description=description,
        )
        iam_client.tag_role(
            RoleName=role_name,
            Tags=[
                {"Key": "mock:last_used_days", "Value": str(last_used_days)},
                {"Key": "mock:notes",          "Value": description},
            ],
        )
        created["roles"].append(role_name)
        print(f"  [role]    {role_name:25s}  last_used={last_used_days}d")

    # -- Attach policies to roles --------------------------------------------
    for role_name, policy_names in ROLE_POLICY_ATTACHMENTS.items():
        for pname in policy_names:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arns[pname],
            )
            print(f"  [attach]  {pname} -> role:{role_name}")

    # -- Groups --------------------------------------------------------------
    # Create two groups to show group-based policy risk surface
    iam_client.create_group(GroupName="Developers")
    iam_client.create_group(GroupName="DataScience")

    for username in ["alice.johnson", "bob.smith", "carol.white", "dave.chen"]:
        iam_client.add_user_to_group(GroupName="Developers", UserName=username)

    for username in ["grace.kim", "henry.nguyen"]:
        iam_client.add_user_to_group(GroupName="DataScience", UserName=username)

    print(f"  [group]   Developers (4 members), DataScience (2 members)")

    return {
        "summary": {
            "users":    len(created["users"]),
            "roles":    len(created["roles"]),
            "policies": len(created["policies"]),
            "keys":     len(created["keys"]),
        },
        "details": created,
        "policy_arns": policy_arns,
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint — wraps everything in @mock_aws and stays alive
# so other processes can connect to the same mock via environment variables.
# ---------------------------------------------------------------------------

@mock_aws
def main():
    print("\n=== Setting up moto mock IAM environment ===\n")
    result = setup_mock_iam()
    summary = result["summary"]
    print(f"\n=== Done ===")
    print(f"  Users:    {summary['users']}")
    print(f"  Roles:    {summary['roles']}")
    print(f"  Policies: {summary['policies']}")
    print(f"  Keys:     {summary['keys']}")
    print("\nMock environment is ready. Import setup_mock_iam() in your tests or auditor.\n")

    # Quick sanity check — list users back out
    iam = boto3.client("iam", region_name="us-east-1")
    users = iam.list_users()["Users"]
    print(f"Sanity check — IAM list_users returned {len(users)} users:")
    for u in users:
        print(f"  {u['UserName']}")


if __name__ == "__main__":
    main()
