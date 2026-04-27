# AWS IAM Security Auditor

**Automated IAM misconfiguration detection mapped to the CIS AWS Foundations Benchmark.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-33%20passed-brightgreen)

---

## Overview

AWS IAM Security Auditor scans an AWS account's IAM configuration and surfaces misconfigurations that commonly appear in security assessments — disabled MFA, stale access keys, wildcard policies, and weak password settings. It is designed for cloud security teams and AWS account administrators who need a repeatable, scriptable alternative to manually clicking through the IAM console. Manual IAM audits don't scale past a handful of users; this tool runs 6 CIS AWS Foundations Benchmark checks in seconds and produces both a machine-readable JSON report (for SIEM ingestion or ticketing pipelines) and a human-readable HTML dashboard. It runs against real AWS credentials or against a fully mocked environment via [moto](https://github.com/getmoto/moto), so there is no AWS account required to demo or test it.

---

## Architecture

![Architecture Diagram](docs/architecture.png)

<!-- Placeholder: draw.io diagram to be added. Will show: CLI → IAMAuditor → 6 check functions → boto3/moto IAM client → Reporter → JSON + HTML outputs -->

---

## Security Checks

| Check                      | Severity      | CIS Control  | Description                                                                                                                           |
| -------------------------- | ------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| Root account access keys   | HIGH          | CIS 1.4      | Flags if the root account has active programmatic access keys                                                                         |
| Root account MFA           | HIGH          | CIS 1.5      | Flags if multi-factor authentication is not enabled on root                                                                           |
| Console users without MFA  | HIGH          | CIS 1.10     | Finds IAM users with a console login profile but no MFA device                                                                        |
| Overly permissive policies | HIGH / MEDIUM | CIS 1.22     | Detects customer-managed policies with `Action:*`+`Resource:*` (HIGH) or service-level wildcards like `s3:*` on `Resource:*` (MEDIUM) |
| Stale access keys          | MEDIUM        | CIS 1.14     | Flags active access keys not rotated within a configurable threshold (default 90 days)                                                |
| Inactive console users     | LOW           | CIS 1.15     | Finds users who haven't logged in via the console within the configured threshold (default 180 days)                                  |
| Account password policy    | MEDIUM        | CIS 1.8–1.11 | Checks minimum length (14), complexity requirements, max age (90 days), and reuse prevention (24 passwords)                           |

---

## Quick Start

**Install dependencies**

```bash
pip install -r requirements.txt
```

**Run against mock data** (no AWS account needed)

```bash
python3 -m src.cli --mock
```

**Run against real AWS**

```bash
aws configure          # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
python3 -m src.cli
```

**Options**

```
--mock                  Use moto-mocked IAM instead of real AWS credentials
--output-dir DIR        Where to write reports (default: ./sample_output)
--format json|html|both Output format (default: both)
--key-days N            Flag access keys older than N days (default: 90)
--inactive-days N       Flag users inactive for more than N days (default: 180)
```

---

## Sample Output

### Console

```
  Scan time : 2026-04-27T20:03:19+00:00
  Account   : 123456789012 (mock)
  Findings  : 15 total  (5 HIGH / 8 MEDIUM / 2 LOW)

Severity    Resource              Check                       Description
----------  --------------------  --------------------------  ----------------------------------------
HIGH        root                  root_account_usage          The root account does not have MFA...
HIGH        carol.white           users_without_mfa           IAM user 'carol.white' has console...
HIGH        dave.chen             users_without_mfa           IAM user 'dave.chen' has console...
HIGH        henry.nguyen          users_without_mfa           IAM user 'henry.nguyen' has console...
HIGH        AdminWildcardPolicy   overly_permissive_policies  Customer-managed policy grants full...
MEDIUM      IAMFullAccess         overly_permissive_policies  ...
MEDIUM      S3WildcardAllBuckets  overly_permissive_policies  ...
...
```

### HTML Report

The generated HTML report (`sample_output/sample_report.html`) is a single self-contained file with no external dependencies. It shows summary cards by severity, a findings table grouped by severity with color-coded row stripes (red/orange/yellow), and full remediation guidance per finding.

The generated JSON report (`sample_output/sample_report.json`) follows this structure:

```json
{
  "metadata": {
    "scan_time": "2026-04-27T20:03:19+00:00",
    "account_id": "123456789012",
    "total_findings": 15,
    "findings_by_severity": { "HIGH": 5, "MEDIUM": 8, "LOW": 2 }
  },
  "findings": [
    {
      "severity": "HIGH",
      "check_name": "users_without_mfa",
      "resource_type": "IAMUser",
      "resource_name": "carol.white",
      "description": "IAM user 'carol.white' has console access but no MFA device is enabled.",
      "remediation": "Assign an MFA device: IAM console → Users → ..."
    }
  ]
}
```

---

## Project Structure

```
aws-iam-auditor/
├── requirements.txt          # boto3, moto[iam], tabulate, jinja2, click, python-dateutil
├── src/
│   ├── __init__.py
│   ├── auditor.py            # IAMAuditor class — orchestrates checks and aggregates results
│   ├── checks.py             # 6 individual check functions, each returning list[Finding]
│   ├── reporter.py           # generate_json(), generate_html(), print_table()
│   └── cli.py                # argparse entry point — python3 -m src.cli
├── tests/
│   └── test_checks.py        # 33 unit tests using moto-mocked IAM
├── sample_output/
│   ├── sample_report.json    # Generated by running: python3 -m src.cli --mock
│   └── sample_report.html    # Self-contained HTML dashboard, no CDN dependencies
└── mock_data/
    └── generate_mock.py      # Populates moto with 10 users, 5 roles, 8 policies
```

---

## Design Decisions

**Why moto for testing?**

The tool needs to be runnable without a live AWS account — useful both during development and for portfolio demos. Moto intercepts boto3 API calls at the HTTP layer and returns realistic IAM responses without hitting AWS. This means tests are fully deterministic and free: no AWS charges, no credential setup, no risk of accidentally modifying a real account. The mock data in `generate_mock.py` is designed to produce a predictable, representative set of findings, making it easy to verify the checks are working correctly.

**Why the CIS AWS Foundations Benchmark?**

CIS (Center for Internet Security) Foundations Benchmarks are the de facto baseline for AWS security assessments. AWS Security Hub's "AWS Foundational Security Best Practices" standard maps directly to many of the same controls. By referencing specific CIS control numbers (e.g. CIS 1.14 for key rotation), the findings are grounded in a published, vendor-neutral standard rather than arbitrary internal rules — which matters when presenting findings to a security team or during compliance reviews.

**Why JSON + HTML output?**

These serve different audiences. JSON is designed to be consumed downstream: ingested into a SIEM, imported into a ticketing system (Jira, ServiceNow), or processed by a follow-up remediation script. HTML is for the human reviewing the results — a self-contained file that can be emailed or shared without any server or renderer. Having both means the same audit run is useful to both an engineer automating remediation and a security manager reviewing the dashboard.

---

## Roadmap

These are the natural next checks after the current 6:

- **S3 bucket security** — public access block settings, server-side encryption, bucket policies that allow `s3:*` to `*`
- **CloudTrail configuration audit** — verify trail is enabled, multi-region, log file validation is on, and logs are delivered to an S3 bucket with restricted access
- **AWS Security Hub findings format (ASFF)** — output findings as ASFF-compliant JSON so they can be imported directly into Security Hub alongside native AWS findings
- **Multi-account scanning via AWS Organizations** — assume a role in each member account and aggregate findings centrally, which is how this kind of tool is deployed at scale

---

## Built With

- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK for Python
- [moto](https://github.com/getmoto/moto) — mock AWS services for local development and testing
- [Jinja2](https://jinja.palletsprojects.com/) — HTML report templating
- [tabulate](https://github.com/astanin/python-tabulate) — console table formatting
- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services) — security control reference

---

## Author

**Yunjae Jung**

- GitHub: [github.com/YOUR_USERNAME](https://github.com/yoonjae0402)
- LinkedIn: [linkedin.com/in/YOUR_PROFILE](https://linkedin.com/in/yunjae-jung-99a13b221)

---

_MIT License_
