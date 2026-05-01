"""
APIGuard - Webhook Notification System
========================================
Sends scan results to Slack, Discord, Microsoft Teams, and Email.
Configurable severity thresholds determine when notifications fire.
"""

import json
import os
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

import requests

from core.config import settings
from core.logging_config import get_logger

logger = get_logger("webhooks")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _should_notify(findings: list[dict]) -> bool:
    """Check if any finding meets the minimum severity threshold."""
    min_sev = SEVERITY_ORDER.get(settings.WEBHOOK_MIN_SEVERITY.upper(), 3)
    for f in findings:
        sev = f.get("severity", "INFO")
        if SEVERITY_ORDER.get(sev, 0) >= min_sev:
            return True
    return False


def _extract_findings(report: dict) -> list[dict]:
    """Extract all findings from a scan report."""
    findings = []
    for mod_data in report.get("modules", {}).values():
        if isinstance(mod_data, dict):
            findings.extend(mod_data.get("findings", []))
    return findings


def _build_summary(report: dict) -> dict:
    """Build a notification summary from a report."""
    findings = _extract_findings(report)
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")

    return {
        "target": report.get("target", "Unknown"),
        "scan_date": report.get("scan_date", ""),
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "findings": findings,
    }


# ─────────────────────────────────────────────
# Slack
# ─────────────────────────────────────────────

def send_slack(report: dict) -> bool:
    """Send scan results to Slack via webhook."""
    url = settings.WEBHOOK_SLACK_URL
    if not url:
        return False

    summary = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    # Build Slack Block Kit message
    severity_emoji = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
    }

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ APIGuard Security Scan Report"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Target:*\n`{summary['target']}`"},
                {"type": "mrkdwn", "text": f"*Date:*\n{summary['scan_date']}"},
                {"type": "mrkdwn", "text": f"*Total Findings:*\n{summary['total_findings']}"},
                {"type": "mrkdwn", "text": f"*Breakdown:*\n🔴 {summary['critical']} | 🟠 {summary['high']} | 🟡 {summary['medium']} | 🟢 {summary['low']}"},
            ]
        },
        {"type": "divider"},
    ]

    # Top 5 critical findings
    top_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)[:5]
    for f in top_findings:
        sev = f.get("severity", "INFO")
        emoji = severity_emoji.get(sev, "⚪")
        ftype = f.get("vulnerability_type", f.get("finding_type", "UNKNOWN"))
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *[{sev}] {ftype}*\n{f.get('description', '')[:200]}\n`{f.get('endpoint', '')}`"
            }
        })

    payload = {"blocks": blocks}

    try:
        resp = requests.post(url, json=payload, timeout=10)
        success = resp.status_code == 200
        if success:
            logger.info("slack_notification_sent", target=summary["target"])
        else:
            logger.warning("slack_notification_failed", status=resp.status_code)
        return success
    except Exception as e:
        logger.error("slack_notification_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# Discord
# ─────────────────────────────────────────────

def send_discord(report: dict) -> bool:
    """Send scan results to Discord via webhook."""
    url = settings.WEBHOOK_DISCORD_URL
    if not url:
        return False

    summary = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    embed = {
        "title": "🛡️ APIGuard Security Scan Report",
        "color": 0xFF0000 if summary["critical"] > 0 else (0xFF8800 if summary["high"] > 0 else 0x00FF00),
        "fields": [
            {"name": "Target", "value": f"`{summary['target']}`", "inline": True},
            {"name": "Date", "value": summary["scan_date"], "inline": True},
            {"name": "Total Findings", "value": str(summary["total_findings"]), "inline": True},
            {"name": "🔴 Critical", "value": str(summary["critical"]), "inline": True},
            {"name": "🟠 High", "value": str(summary["high"]), "inline": True},
            {"name": "🟡 Medium", "value": str(summary["medium"]), "inline": True},
        ],
        "footer": {"text": "APIGuard Enterprise v2.0"},
        "timestamp": summary["scan_date"],
    }

    # Add top findings
    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)[:3]
    finding_text = "\n".join([
        f"**[{f.get('severity')}]** {f.get('vulnerability_type', f.get('finding_type', ''))}"
        for f in top
    ])
    if finding_text:
        embed["fields"].append({"name": "Top Findings", "value": finding_text, "inline": False})

    payload = {"embeds": [embed]}

    try:
        resp = requests.post(url, json=payload, timeout=10)
        success = resp.status_code in (200, 204)
        if success:
            logger.info("discord_notification_sent", target=summary["target"])
        return success
    except Exception as e:
        logger.error("discord_notification_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# Microsoft Teams
# ─────────────────────────────────────────────

def send_teams(report: dict) -> bool:
    """Send scan results to Microsoft Teams via webhook."""
    url = settings.WEBHOOK_TEAMS_URL
    if not url:
        return False

    summary = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000" if summary["critical"] > 0 else "FF8800",
        "summary": f"APIGuard Scan: {summary['target']}",
        "sections": [{
            "activityTitle": "🛡️ APIGuard Security Scan Report",
            "facts": [
                {"name": "Target", "value": summary["target"]},
                {"name": "Date", "value": summary["scan_date"]},
                {"name": "Critical", "value": str(summary["critical"])},
                {"name": "High", "value": str(summary["high"])},
                {"name": "Medium", "value": str(summary["medium"])},
                {"name": "Total", "value": str(summary["total_findings"])},
            ],
            "markdown": True,
        }],
    }

    try:
        resp = requests.post(url, json=card, timeout=10)
        success = resp.status_code == 200
        if success:
            logger.info("teams_notification_sent", target=summary["target"])
        return success
    except Exception as e:
        logger.error("teams_notification_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# Email
# ─────────────────────────────────────────────

def send_email(report: dict) -> bool:
    """Send scan results via email."""
    if not all([settings.WEBHOOK_EMAIL_SMTP_HOST, settings.WEBHOOK_EMAIL_FROM, settings.WEBHOOK_EMAIL_TO]):
        return False

    summary = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    subject = f"🛡️ APIGuard Scan: {summary['target']} — {summary['critical']} Critical, {summary['high']} High"

    html_body = f"""
    <html>
    <body style="font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #16213e; border-radius: 12px; padding: 24px;">
            <h1 style="color: #00f5d4;">🛡️ APIGuard Security Report</h1>
            <p><strong>Target:</strong> <code>{summary['target']}</code></p>
            <p><strong>Date:</strong> {summary['scan_date']}</p>
            <hr style="border-color: #333;">
            <table style="width: 100%; text-align: center;">
                <tr>
                    <td style="color: #ff4444;"><h2>{summary['critical']}</h2><p>Critical</p></td>
                    <td style="color: #ff8800;"><h2>{summary['high']}</h2><p>High</p></td>
                    <td style="color: #ffcc00;"><h2>{summary['medium']}</h2><p>Medium</p></td>
                    <td style="color: #00cc44;"><h2>{summary['low']}</h2><p>Low</p></td>
                </tr>
            </table>
            <hr style="border-color: #333;">
            <h3>Top Findings</h3>
            <ul>
    """

    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)[:10]
    for f in top:
        sev = f.get("severity", "INFO")
        color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00"}.get(sev, "#00cc44")
        ftype = f.get("vulnerability_type", f.get("finding_type", ""))
        html_body += f'<li><span style="color:{color};">[{sev}]</span> <strong>{ftype}</strong> — {f.get("description", "")[:150]}</li>'

    html_body += """
            </ul>
            <p style="color: #888; font-size: 12px;">Generated by APIGuard Enterprise v2.0</p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.WEBHOOK_EMAIL_FROM
    msg["To"] = settings.WEBHOOK_EMAIL_TO
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(settings.WEBHOOK_EMAIL_SMTP_HOST, settings.WEBHOOK_EMAIL_SMTP_PORT) as server:
            server.starttls()
            if settings.WEBHOOK_EMAIL_PASSWORD:
                server.login(settings.WEBHOOK_EMAIL_FROM, settings.WEBHOOK_EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info("email_notification_sent", target=summary["target"])
        return True
    except Exception as e:
        logger.error("email_notification_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# Jira Cloud
# ─────────────────────────────────────────────

def send_jira(report: dict) -> bool:
    """Create a Jira issue with scan findings via REST API v3."""
    jira_url = getattr(settings, "WEBHOOK_JIRA_URL", "") or os.environ.get("APIGUARD_JIRA_URL", "")
    jira_email = getattr(settings, "WEBHOOK_JIRA_EMAIL", "") or os.environ.get("APIGUARD_JIRA_EMAIL", "")
    jira_token = getattr(settings, "WEBHOOK_JIRA_TOKEN", "") or os.environ.get("APIGUARD_JIRA_TOKEN", "")
    jira_project = getattr(settings, "WEBHOOK_JIRA_PROJECT", "") or os.environ.get("APIGUARD_JIRA_PROJECT", "SEC")

    if not all([jira_url, jira_email, jira_token]):
        return False

    summary_data = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    title = f"[APIGuard] {summary_data['critical']} Critical, {summary_data['high']} High — {summary_data['target']}"

    # Build ADF (Atlassian Document Format) description
    desc_lines = [
        f"🛡️ **APIGuard Security Scan Report**\n",
        f"**Target:** `{summary_data['target']}`",
        f"**Date:** {summary_data['scan_date']}",
        f"**Total Findings:** {summary_data['total_findings']}",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {summary_data['critical']} |",
        f"| 🟠 High | {summary_data['high']} |",
        f"| 🟡 Medium | {summary_data['medium']} |",
        f"| 🟢 Low | {summary_data['low']} |",
        f"",
        f"**Top Findings:**",
    ]

    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)[:5]
    for f in top:
        ftype = f.get("vulnerability_type", f.get("finding_type", "Unknown"))
        desc_lines.append(f"- [{f.get('severity')}] {ftype}: {f.get('description', '')[:150]}")

    desc_lines.append(f"\n_Generated by APIGuard Enterprise v4.0_")

    priority_map = {True: "Highest", False: "High"}
    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": title,
            "description": "\n".join(desc_lines),
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority_map.get(summary_data["critical"] > 0, "High")},
            "labels": ["security", "apiguard", "automated"],
        }
    }

    try:
        resp = requests.post(
            f"{jira_url}/rest/api/3/issue",
            json=payload,
            auth=(jira_email, jira_token),
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        success = resp.status_code in (200, 201)
        if success:
            issue_key = resp.json().get("key", "?")
            logger.info("jira_issue_created", target=summary_data["target"], issue=issue_key)
        else:
            logger.warning("jira_create_failed", status=resp.status_code, body=resp.text[:200])
        return success
    except Exception as e:
        logger.error("jira_notification_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# GitHub Issues
# ─────────────────────────────────────────────

def send_github_issue(report: dict) -> bool:
    """Create a GitHub Issue with scan findings."""
    gh_repo = os.environ.get("APIGUARD_GITHUB_REPO", "")  # owner/repo
    gh_token = os.environ.get("APIGUARD_GITHUB_TOKEN", "")

    if not all([gh_repo, gh_token]):
        return False

    summary_data = _build_summary(report)
    findings = _extract_findings(report)
    if not _should_notify(findings):
        return False

    title = f"[APIGuard] Security Scan: {summary_data['critical']}C / {summary_data['high']}H — {summary_data['target']}"

    body_lines = [
        f"## 🛡️ APIGuard Security Scan Report\n",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{summary_data['target']}` |",
        f"| **Date** | {summary_data['scan_date']} |",
        f"| **Critical** | {summary_data['critical']} |",
        f"| **High** | {summary_data['high']} |",
        f"| **Medium** | {summary_data['medium']} |",
        f"| **Low** | {summary_data['low']} |",
        f"\n### Top Findings\n",
    ]

    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 0), reverse=True)[:5]
    for f in top:
        sev = f.get("severity", "INFO")
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "🟢")
        ftype = f.get("vulnerability_type", f.get("finding_type", "Unknown"))
        body_lines.append(f"- {emoji} **[{sev}] {ftype}** — {f.get('description', '')[:150]}")

    body_lines.append(f"\n---\n_Generated by APIGuard Enterprise v4.0_")

    labels = ["security", "apiguard"]
    if summary_data["critical"] > 0:
        labels.append("critical")

    payload = {
        "title": title,
        "body": "\n".join(body_lines),
        "labels": labels,
    }

    try:
        resp = requests.post(
            f"https://api.github.com/repos/{gh_repo}/issues",
            json=payload,
            headers={"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github+json"},
            timeout=15
        )
        success = resp.status_code == 201
        if success:
            issue_url = resp.json().get("html_url", "")
            logger.info("github_issue_created", target=summary_data["target"], url=issue_url)
        else:
            logger.warning("github_issue_failed", status=resp.status_code)
        return success
    except Exception as e:
        logger.error("github_issue_error", error=str(e))
        return False


# ─────────────────────────────────────────────
# Unified Dispatcher
# ─────────────────────────────────────────────

def notify_all(report: dict) -> dict[str, bool]:
    """
    Send notifications to all configured channels.
    Returns a dict of {channel: success_bool}.
    """
    results = {}
    channels = [
        ("slack", send_slack),
        ("discord", send_discord),
        ("teams", send_teams),
        ("email", send_email),
        ("jira", send_jira),
        ("github", send_github_issue),
    ]

    for name, sender in channels:
        try:
            results[name] = sender(report)
        except Exception as e:
            logger.error("notification_dispatch_error", channel=name, error=str(e))
            results[name] = False

    active = [k for k, v in results.items() if v]
    if active:
        logger.info("notifications_sent", channels=active)

    return results

