"""
Report generation — JSON and HTML outputs from IAMAuditor results.

Public API:
    generate_json(audit_dict, output_path)  -> pathlib.Path
    generate_html(audit_dict, output_path)  -> pathlib.Path
    print_table(audit_dict)                 -> None  (console tabulate output)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader
from tabulate import tabulate


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json(audit_dict: dict[str, Any], output_path: str | Path) -> Path:
    """
    Write a pretty-printed JSON report.

    The report adds a top-level ``metadata`` key derived from audit_dict['summary']
    plus any extra context passed in (account_id etc.).

    Returns the resolved output path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "metadata": {
            "scan_time":          audit_dict.get("ran_at"),
            "account_id":         audit_dict.get("account_id", "mock-account"),
            "total_findings":     audit_dict["summary"]["total"],
            "findings_by_severity": {
                "HIGH":   audit_dict["summary"]["HIGH"],
                "MEDIUM": audit_dict["summary"]["MEDIUM"],
                "LOW":    audit_dict["summary"]["LOW"],
            },
        },
        "findings": audit_dict["findings"],
    }

    output_path.write_text(json.dumps(report, indent=2, default=str))
    return output_path


# ---------------------------------------------------------------------------
# HTML report — Jinja2 template (self-contained, no external deps)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AWS IAM Security Audit Report</title>
  <style>
    /* ---- Reset & base ---- */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      background: #f0f2f5;
      color: #1a1a2e;
    }

    /* ---- Layout ---- */
    .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

    /* ---- Header ---- */
    .header {
      background: #1a1a2e;
      color: #fff;
      border-radius: 8px;
      padding: 28px 32px;
      margin-bottom: 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    .header h1 { font-size: 22px; font-weight: 600; letter-spacing: 0.3px; }
    .header h1 span { color: #f59e0b; }
    .header-meta { text-align: right; font-size: 13px; color: #a0aec0; }
    .header-meta strong { color: #e2e8f0; }

    /* ---- Summary cards ---- */
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      padding: 20px 24px;
      border-top: 4px solid #cbd5e0;
      box-shadow: 0 1px 3px rgba(0,0,0,.08);
    }
    .card .card-value {
      font-size: 36px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 6px;
    }
    .card .card-label { font-size: 13px; color: #718096; text-transform: uppercase;
                        letter-spacing: 0.6px; font-weight: 500; }
    .card.total   { border-color: #4a5568; }
    .card.total   .card-value { color: #2d3748; }
    .card.high    { border-color: #e53e3e; }
    .card.high    .card-value { color: #c53030; }
    .card.medium  { border-color: #ed8936; }
    .card.medium  .card-value { color: #c05621; }
    .card.low     { border-color: #ecc94b; }
    .card.low     .card-value { color: #975a16; }

    /* ---- Section headings ---- */
    .section-title {
      font-size: 15px;
      font-weight: 600;
      letter-spacing: 0.4px;
      margin-bottom: 10px;
      padding-left: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .badge.HIGH   { background: #fff5f5; color: #c53030; border: 1px solid #feb2b2; }
    .badge.MEDIUM { background: #fffaf0; color: #c05621; border: 1px solid #fbd38d; }
    .badge.LOW    { background: #fffff0; color: #975a16; border: 1px solid #faf089; }

    /* ---- Findings table ---- */
    .findings-section { margin-bottom: 32px; }
    .table-wrap {
      background: #fff;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,.08);
    }
    table { width: 100%; border-collapse: collapse; }
    thead th {
      background: #2d3748;
      color: #e2e8f0;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 12px 16px;
      text-align: left;
    }
    tbody tr { border-bottom: 1px solid #edf2f7; }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: #f7fafc; }
    tbody td { padding: 12px 16px; vertical-align: top; }

    /* Severity stripe on left edge */
    tbody tr.HIGH   td:first-child { border-left: 3px solid #e53e3e; }
    tbody tr.MEDIUM td:first-child { border-left: 3px solid #ed8936; }
    tbody tr.LOW    td:first-child { border-left: 3px solid #ecc94b; }

    .col-resource { width: 14%; font-family: "SF Mono", "Fira Code", monospace;
                    font-size: 12px; color: #2d3748; font-weight: 500; }
    .col-check    { width: 18%; font-family: "SF Mono", "Fira Code", monospace;
                    font-size: 12px; color: #4a5568; }
    .col-desc     { width: 38%; color: #2d3748; }
    .col-fix      { width: 30%; color: #718096; font-size: 13px; }

    /* ---- Empty state ---- */
    .empty {
      text-align: center;
      padding: 32px;
      color: #a0aec0;
      font-size: 15px;
    }

    /* ---- Footer ---- */
    .footer {
      text-align: center;
      font-size: 12px;
      color: #a0aec0;
      margin-top: 40px;
    }
  </style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div>
      <h1>AWS IAM <span>Security Audit</span> Report</h1>
    </div>
    <div class="header-meta">
      <div>Scan time: <strong>{{ metadata.scan_time }}</strong></div>
      <div>Account:&nbsp;&nbsp; <strong>{{ metadata.account_id }}</strong></div>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="cards">
    <div class="card total">
      <div class="card-value">{{ metadata.total_findings }}</div>
      <div class="card-label">Total Findings</div>
    </div>
    <div class="card high">
      <div class="card-value">{{ metadata.findings_by_severity.HIGH }}</div>
      <div class="card-label">High</div>
    </div>
    <div class="card medium">
      <div class="card-value">{{ metadata.findings_by_severity.MEDIUM }}</div>
      <div class="card-label">Medium</div>
    </div>
    <div class="card low">
      <div class="card-value">{{ metadata.findings_by_severity.LOW }}</div>
      <div class="card-label">Low</div>
    </div>
  </div>

  <!-- Findings grouped by severity -->
  {% for severity in ["HIGH", "MEDIUM", "LOW"] %}
  {% set group = findings | selectattr("severity", "equalto", severity) | list %}
  {% if group %}
  <div class="findings-section">
    <div class="section-title">
      <span class="badge {{ severity }}">{{ severity }}</span>
      {{ group | length }} finding{{ "s" if group | length != 1 else "" }}
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th class="col-resource">Resource</th>
            <th class="col-check">Check</th>
            <th class="col-desc">Description</th>
            <th class="col-fix">Remediation</th>
          </tr>
        </thead>
        <tbody>
          {% for f in group %}
          <tr class="{{ f.severity }}">
            <td class="col-resource">{{ f.resource_name }}</td>
            <td class="col-check">{{ f.check_name }}</td>
            <td class="col-desc">{{ f.description }}</td>
            <td class="col-fix">{{ f.remediation }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}
  {% endfor %}

  {% if metadata.total_findings == 0 %}
  <div class="empty">&#10003; No findings — your IAM configuration looks clean.</div>
  {% endif %}

  <div class="footer">
    Generated by <strong>aws-iam-auditor</strong> &middot;
    CIS AWS Foundations Benchmark v2.0
  </div>

</div>
</body>
</html>
"""


def generate_html(audit_dict: dict[str, Any], output_path: str | Path) -> Path:
    """
    Render a self-contained HTML report from audit results.

    Returns the resolved output path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=BaseLoader())
    template = env.from_string(_HTML_TEMPLATE)

    metadata = {
        "scan_time":          audit_dict.get("ran_at", "N/A"),
        "account_id":         audit_dict.get("account_id", "mock-account"),
        "total_findings":     audit_dict["summary"]["total"],
        "findings_by_severity": {
            "HIGH":   audit_dict["summary"]["HIGH"],
            "MEDIUM": audit_dict["summary"]["MEDIUM"],
            "LOW":    audit_dict["summary"]["LOW"],
        },
    }

    html = template.render(
        metadata=metadata,
        findings=audit_dict["findings"],
    )
    output_path.write_text(html, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Console table output
# ---------------------------------------------------------------------------

_SEV_PREFIX = {"HIGH": "HIGH  ", "MEDIUM": "MEDIUM", "LOW": "LOW   "}


def print_table(audit_dict: dict[str, Any]) -> None:
    """
    Print a formatted findings table to stdout using tabulate.

    Findings are shown sorted HIGH → MEDIUM → LOW (auditor already sorts them).
    """
    findings = audit_dict.get("findings", [])

    if not findings:
        print("\n  No findings.\n")
        return

    summary = audit_dict["summary"]
    ran_at = audit_dict.get("ran_at", "N/A")
    account = audit_dict.get("account_id", "mock-account")

    print(f"\n  Scan time : {ran_at}")
    print(f"  Account   : {account}")
    print(f"  Findings  : {summary['total']} total  "
          f"({summary['HIGH']} HIGH / {summary['MEDIUM']} MEDIUM / {summary['LOW']} LOW)\n")

    rows = []
    for f in findings:
        sev = f["severity"]
        # Truncate long descriptions for the table view
        desc = f["description"]
        if len(desc) > 90:
            desc = desc[:87] + "..."
        rows.append([
            _SEV_PREFIX.get(sev, sev),
            f["resource_name"],
            f["check_name"],
            desc,
        ])

    print(tabulate(
        rows,
        headers=["Severity", "Resource", "Check", "Description"],
        tablefmt="simple",
        colalign=("left", "left", "left", "left"),
    ))
    print()
