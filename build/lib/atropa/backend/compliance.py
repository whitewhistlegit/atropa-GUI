"""
atropa.backend.compliance
------------------------------
A categorized, scored security-posture report, built on top of
hardening.run_audit()'s existing checks (plus two more: login lockout and
sudoers) rather than duplicating any detection logic.

Important framing: this is modeled on common CIS-style benchmark
categories for convenient organization - it is NOT an official CIS
Benchmark assessment, and passing every check here is not a certification
of regulatory compliance. That distinction is stated in every export this
module produces, not just in this docstring, since an enterprise reader
handing this to an auditor needs to see it on the report itself.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import account_hygiene, hardening, inventory, security

DISCLAIMER = (
    "This report is modeled on common CIS-style security benchmark categories "
    "for convenient organization. It is NOT an official CIS Benchmark assessment "
    "or a certification of regulatory compliance - treat it as a structured "
    "summary of Atropa's own hardening checks, not a substitute for a real "
    "compliance audit."
)

# Maps each AuditCheck.name (from hardening.run_audit(), plus the two
# extra checks this module adds) to a benchmark-style category. A name not
# in this map falls into "Other" rather than being dropped silently.
_CATEGORY_MAP: dict[str, str] = {
    "Firewall": "Network & Firewall",
    "fail2ban": "Network & Firewall",
    "SSH root login": "Authentication & Access Control",
    "SSH password auth": "Authentication & Access Control",
    "Login lockout (faillock)": "Authentication & Access Control",
    "Sudoers configuration": "Authentication & Access Control",
    "AppArmor": "Mandatory Access Control",
    "SELinux": "Mandatory Access Control",
    "USBGuard": "Device Control",
    "auditd": "Logging & Auditing",
    "Kernel sysctl hardening": "Kernel & Network Hardening",
    "Known CVEs (arch-audit)": "Patch Management",
}

# pass/warn/fail contribute to the score; "info" checks (feature not
# installed and genuinely optional, e.g. AppArmor when the user runs
# SELinux instead) are excluded entirely rather than scored as a failure.
_SCORE = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


@dataclass
class CategoryScore:
    name: str
    checks: list = field(default_factory=list)  # list[hardening.AuditCheck]
    score: float | None = None  # 0.0-1.0, or None if nothing in this category was scorable


@dataclass
class ComplianceReport:
    generated_at: str
    hostname: str
    categories: list[CategoryScore]
    overall_score: float  # 0.0-1.0
    scored_check_count: int
    total_check_count: int


def _extra_checks() -> list:
    checks = []

    if hardening.faillock_wired_into_pam():
        status = hardening.faillock_status()
        checks.append(
            hardening.AuditCheck(
                "Login lockout (faillock)", "pass",
                f"Wired into PAM - deny={status.get('deny', '?')}, unlock_time={status.get('unlock_time', '?')}",
            )
        )
    else:
        checks.append(
            hardening.AuditCheck("Login lockout (faillock)", "warn", "pam_faillock isn't wired into PAM")
        )

    try:
        result = security.sudoers_check()
        if "parsed ok" in result.lower():
            checks.append(hardening.AuditCheck("Sudoers configuration", "pass", result.strip()))
        else:
            checks.append(hardening.AuditCheck("Sudoers configuration", "warn", result.strip()[:150]))
    except Exception as exc:  # noqa: BLE001 - surfaced as an info row, not a crash
        checks.append(hardening.AuditCheck("Sudoers configuration", "info", str(exc)))

    return checks


def _inventory_checks() -> list:
    # inventory.ServiceFinding is (key, title, status, detail) - same shape as
    # AuditCheck's (name, status, detail), title standing in for name.
    return [hardening.AuditCheck(f.title, f.status, f.detail) for f in inventory.scan_all()]


def _account_hygiene_checks() -> list:
    return [hardening.AuditCheck(f.title, f.status, f.detail) for f in account_hygiene.scan_all()]


def generate_report() -> ComplianceReport:
    checks = hardening.run_audit() + _extra_checks()

    by_category: dict[str, list] = {}
    for check in checks:
        category = _CATEGORY_MAP.get(check.name, "Other")
        by_category.setdefault(category, []).append(check)

    # Service Inventory (CIS 2.2/2.3-style) and Account & File Hygiene (CIS
    # 6.1/6.2-style) each get their own category directly, rather than going
    # through _CATEGORY_MAP - their check names are per-entry/per-account
    # (e.g. one row per installed service, one per user's home directory), so
    # a fixed name->category mapping doesn't fit the same way it does for the
    # fixed, small set of hardening.run_audit() checks.
    by_category["Service Inventory"] = _inventory_checks()
    by_category["Account & File Hygiene"] = _account_hygiene_checks()

    categories: list[CategoryScore] = []
    scored_total = 0.0
    scored_count = 0
    for name, cat_checks in by_category.items():
        scorable = [c for c in cat_checks if c.status in _SCORE]
        cat_score = (sum(_SCORE[c.status] for c in scorable) / len(scorable)) if scorable else None
        categories.append(CategoryScore(name=name, checks=cat_checks, score=cat_score))
        scored_total += sum(_SCORE[c.status] for c in scorable)
        scored_count += len(scorable)

    overall = (scored_total / scored_count) if scored_count else 0.0

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        hostname=socket.gethostname(),
        categories=sorted(categories, key=lambda c: c.name),
        overall_score=overall,
        scored_check_count=scored_count,
        total_check_count=len(checks),
    )


def render_markdown_report(report: ComplianceReport) -> str:
    lines = [
        "# Atropa Security Baseline Report",
        "",
        f"> {DISCLAIMER}",
        "",
        f"- Host: `{report.hostname}`",
        f"- Generated: {report.generated_at}",
        f"- Overall score: {report.overall_score * 100:.0f}% ({report.scored_check_count} scored checks, "
        f"{report.total_check_count} total)",
        "",
    ]
    for category in report.categories:
        score_text = f"{category.score * 100:.0f}%" if category.score is not None else "N/A"
        lines.append(f"## {category.name} — {score_text}")
        lines.append("")
        lines.append("| Check | Status | Detail |")
        lines.append("|---|---|---|")
        for check in category.checks:
            detail = check.detail.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {check.name} | {check.status.upper()} | {detail} |")
        lines.append("")
    return "\n".join(lines)


def save_report_to_file(report: ComplianceReport, path: str) -> None:
    Path(path).write_text(render_markdown_report(report), encoding="utf-8")
