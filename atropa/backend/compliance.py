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

from . import account_hygiene, boot_security, hardening, inventory, security

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
    "Disk encryption": "Boot & Disk Security",
    "Secure Boot": "Boot & Disk Security",
}

# pass/warn/fail contribute to the score; "info" checks (feature not
# installed and genuinely optional, e.g. AppArmor when the user runs
# SELinux instead) are excluded entirely rather than scored as a failure.
_SCORE = {"pass": 1.0, "warn": 0.5, "fail": 0.0}

# Read directly (no `ss` dependency) so the exposure summary works on a bare
# install. Tests redirect both to empty files - /proc/net/tcp is live.
PROC_NET_TCP = Path("/proc/net/tcp")
PROC_NET_TCP6 = Path("/proc/net/tcp6")

EXPOSURE_NOTE = (
    "The percentage is the share of Atropa's posture checks that hold, read as exposure: "
    "100% means nothing Atropa checked is currently exposing this machine. It is not a "
    "CIS score, an audit result, or a promise that the machine is unbreakable."
)


@dataclass
class CategoryScore:
    name: str
    checks: list = field(default_factory=list)  # list[hardening.AuditCheck]
    score: float | None = None  # 0.0-1.0, or None if nothing in this category was scorable


@dataclass
class ExposureSignal:
    label: str
    status: str  # "pass" | "warn" | "fail" | "info"
    detail: str


@dataclass
class Exposure:
    level: str  # "low" | "moderate" | "high" | "unknown"
    summary: str
    signals: list[ExposureSignal] = field(default_factory=list)


@dataclass
class ComplianceReport:
    generated_at: str
    hostname: str
    categories: list[CategoryScore]
    overall_score: float  # 0.0-1.0
    scored_check_count: int
    total_check_count: int
    # Default keeps older callers (and tests that build a report by hand)
    # working without knowing about the exposure framing.
    exposure: Exposure = field(default_factory=lambda: Exposure("unknown", ""))


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
        output = (result.stdout or result.stderr).strip()
        if result.ok:
            checks.append(hardening.AuditCheck("Sudoers configuration", "pass", output or "Syntax OK"))
        elif result.returncode in (126, 127):
            # pkexec's own exit codes: authentication dismissed (126) or not
            # obtained / couldn't run visudo (127). The check didn't happen,
            # so it's info (unscored), not a finding about sudoers itself.
            detail = f"Not checked - couldn't run visudo as root: {output[:150]}"
            checks.append(hardening.AuditCheck("Sudoers configuration", "info", detail))
        else:
            checks.append(hardening.AuditCheck("Sudoers configuration", "fail", output[:150] or "visudo reported a problem"))
    except Exception as exc:  # noqa: BLE001 - surfaced as an info row, not a crash
        checks.append(hardening.AuditCheck("Sudoers configuration", "info", str(exc)))

    return checks


def _inventory_checks() -> list:
    # inventory.ServiceFinding is (key, title, status, detail) - same shape as
    # AuditCheck's (name, status, detail), title standing in for name.
    return [hardening.AuditCheck(f.title, f.status, f.detail) for f in inventory.scan_all()]


def _account_hygiene_checks() -> list:
    return [hardening.AuditCheck(f.title, f.status, f.detail) for f in account_hygiene.scan_all()]


def _boot_checks() -> list:
    """Encryption and Secure Boot - reusing boot_security's own verdicts."""
    return [
        hardening.AuditCheck(check.name, check.status, check.detail)
        for check in boot_security.security_checks()
    ]


def _is_loopback(local_address: str) -> bool:
    """
    /proc/net/tcp stores the address little-endian, so 127.0.0.1 is
    "0100007F". A service bound only to loopback is not part of the
    machine's network exposure, and counting it would make every desktop
    with a local helper look "moderate".
    """
    host = local_address.rsplit(":", 1)[0]
    try:
        value = int(host, 16)
    except ValueError:
        return False
    if len(host) <= 8:  # IPv4: the low byte is 127
        return value & 0xFF == 0x7F
    return value == 1  # IPv6 ::1


def _listening_tcp_ports() -> list[int] | None:
    """
    Ports in LISTEN state on non-loopback addresses, straight from /proc (no
    `ss` dependency). None when neither table could be read, so the summary
    says "unknown" instead of claiming zero open ports on a machine where
    /proc isn't accessible.
    """
    ports: set[int] = set()
    readable = False
    for path in (PROC_NET_TCP, PROC_NET_TCP6):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        readable = True
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3].upper() != "0A":
                continue
            if _is_loopback(fields[1]):
                continue
            try:
                ports.add(int(fields[1].rsplit(":", 1)[-1], 16))
            except ValueError:
                continue
    return sorted(ports) if readable else None


def _check_named(checks: list, name: str):
    return next((check for check in checks if check.name == name), None)


def _exposure_signals(checks: list) -> list[ExposureSignal]:
    """
    The handful of facts that decide how exposed this machine is, in plain
    terms - not a second audit. Each signal reuses a verdict the report
    already computed, except the listening-socket count, which is its own
    cheap read.
    """
    signals: list[ExposureSignal] = []

    firewall = _check_named(checks, "Firewall")
    if firewall is not None:
        signals.append(ExposureSignal("Incoming network connections", firewall.status, firewall.detail))

    # SSH gets its own wording rather than the audit's: "key-only login" is a
    # pass in a CIS-style audit but still a reachable login surface, which is
    # exactly the distinction this framing is about.
    root_login = _check_named(checks, "SSH root login")
    password_auth = _check_named(checks, "SSH password auth")
    if root_login is not None:
        if root_login.status == "info":
            signals.append(
                ExposureSignal(
                    "Remote login (SSH)",
                    "pass",
                    "No SSH server is installed, so nothing accepts remote logins.",
                )
            )
        elif root_login.status == "fail":
            signals.append(ExposureSignal("Remote login (SSH)", "fail", root_login.detail))
        elif password_auth is not None and password_auth.status in ("warn", "fail"):
            signals.append(
                ExposureSignal(
                    "Remote login (SSH)",
                    "warn",
                    f"An SSH server accepts password logins over the network ({password_auth.detail}).",
                )
            )
        else:
            signals.append(
                ExposureSignal(
                    "Remote login (SSH)",
                    "warn",
                    "An SSH server is reachable over the network, even with keys only - that login "
                    "surface is not exposed by a desktop with no remote access.",
                )
            )

    ports = _listening_tcp_ports()
    if ports is None:
        signals.append(
            ExposureSignal("Listening TCP sockets", "info", "Couldn't read /proc/net/tcp.")
        )
    elif not ports:
        signals.append(ExposureSignal("Listening TCP sockets", "pass", "No TCP sockets are listening."))
    else:
        shown = ", ".join(str(port) for port in ports[:8]) + ("…" if len(ports) > 8 else "")
        signals.append(
            ExposureSignal(
                "Listening TCP sockets",
                "warn",
                f"{len(ports)} socket(s) listening on a non-loopback address ({shown}). Any of them "
                "is reachable unless the firewall blocks it.",
            )
        )

    for label, name in (
        ("Root filesystem encryption", "Disk encryption"),
        ("Secure Boot", "Secure Boot"),
    ):
        check = _check_named(checks, name)
        if check is not None:
            signals.append(ExposureSignal(label, check.status, check.detail))

    return signals


def _exposure(signals: list[ExposureSignal]) -> Exposure:
    if not signals or all(signal.status == "info" for signal in signals):
        return Exposure("unknown", "Atropa couldn't read enough of this machine to judge exposure.", signals)

    fails = sum(1 for signal in signals if signal.status == "fail")
    warns = sum(1 for signal in signals if signal.status == "warn")
    critical = any(
        signal.status == "fail" and signal.label in ("Incoming network connections", "Root filesystem encryption")
        for signal in signals
    )

    if critical or fails >= 3:
        level = "high"
        summary = (
            "Something that directly exposes this machine is open: an unfiltered network, an "
            "unencrypted disk, or several smaller gaps at once."
        )
    elif fails or warns:
        level = "moderate"
        summary = (
            "The machine isn't wide open, but at least one door is: a reachable service, a disabled "
            "boot safeguard, or a policy that only partly holds."
        )
    else:
        level = "low"
        summary = "Nothing Atropa checked is currently exposing this machine in a meaningful way."

    return Exposure(level, summary, signals)


def generate_report() -> ComplianceReport:
    checks = hardening.run_audit() + _extra_checks() + _boot_checks()

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
        # Every check in the report - this used to count only the run_audit()
        # ones, so the header could claim "29 scored checks, 3 total".
        total_check_count=sum(len(cat_checks) for cat_checks in by_category.values()),
        exposure=_exposure(_exposure_signals(checks)),
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
        f"## Exposure — {report.exposure.level.capitalize()}",
        "",
        f"> {EXPOSURE_NOTE}",
        "",
        report.exposure.summary,
        "",
    ]
    if report.exposure.signals:
        lines.append("| Signal | Status | Detail |")
        lines.append("|---|---|---|")
        for signal in report.exposure.signals:
            detail = signal.detail.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {signal.label} | {signal.status.upper()} | {detail} |")
        lines.append("")
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
