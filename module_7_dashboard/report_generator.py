"""
APIGuard - Module 7: Report Generator (Enterprise Edition)
============================================================
Generates professional multi-page PDF executive reports, HTML dashboards,
JSON exports, and manages scan history in SQLite.

PDF Report structure:
  1. Cover page with branding
  2. Executive summary with risk gauge
  3. Findings by severity (table)
  4. Per-module detailed breakdown
  5. OWASP API Top 10 compliance mapping
  6. Remediation roadmap
"""

import sqlite3
import json
import time
from io import BytesIO

# ReportLab imports
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Wedge
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF


# ─────────────────────────────────────────────
# Color Palette
# ─────────────────────────────────────────────
COLORS = {
    "bg_dark":   HexColor("#0a0e27"),
    "bg_card":   HexColor("#16213e"),
    "accent":    HexColor("#00f5d4"),
    "critical":  HexColor("#ff4444"),
    "high":      HexColor("#ff8800"),
    "medium":    HexColor("#ffcc00"),
    "low":       HexColor("#00cc44"),
    "info":      HexColor("#4488ff"),
    "text":      HexColor("#333333"),
    "text_light":HexColor("#666666"),
    "border":    HexColor("#e0e0e0"),
    "header_bg": HexColor("#1a1a2e"),
    "white":     white,
    "black":     black,
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["critical"],
    "HIGH":     COLORS["high"],
    "MEDIUM":   COLORS["medium"],
    "LOW":      COLORS["low"],
    "INFO":     COLORS["info"],
}

# OWASP API Top 10 Mapping
OWASP_MAPPING = {
    "BOLA":                  "API1:2023 — Broken Object Level Authorization",
    "MISSING_AUTH":          "API2:2023 — Broken Authentication",
    "JWT_NO_EXPIRY":         "API2:2023 — Broken Authentication",
    "JWT_ALG_NONE":          "API2:2023 — Broken Authentication",
    "JWT_WEAK_SECRET":       "API2:2023 — Broken Authentication",
    "EXPIRED_TOKEN_ACCEPTED":"API2:2023 — Broken Authentication",
    "JWT_LONG_EXPIRY":       "API2:2023 — Broken Authentication",
    "EXCESSIVE_RESPONSE_SIZE":"API3:2023 — Broken Object Property Level Authorization",
    "PII_LEAKAGE":           "API3:2023 — Broken Object Property Level Authorization",
    "NO_RATE_LIMIT":         "API4:2023 — Unrestricted Resource Consumption",
    "BFLA":                  "API5:2023 — Broken Function Level Authorization",
    "MASS_ASSIGNMENT":       "API6:2023 — Unrestricted Access to Sensitive Business Flows",
    "SQL_INJECTION":         "API8:2023 — Security Misconfiguration",
    "OS_COMMAND_INJECTION":  "API8:2023 — Security Misconfiguration",
    "SSRF_VULNERABILITY":    "API8:2023 — Security Misconfiguration",
    "NOSQL_INJECTION":       "API8:2023 — Security Misconfiguration",
    "CORS_WILDCARD":         "API8:2023 — Security Misconfiguration",
    "CORS_REFLECTION":       "API8:2023 — Security Misconfiguration",
    "CORS_CREDENTIALS":      "API8:2023 — Security Misconfiguration",
    "EXPOSED_SECRET":        "API8:2023 — Security Misconfiguration",
    "NO_SSL":                "API8:2023 — Security Misconfiguration",
    "WEAK_TLS_VERSION":      "API8:2023 — Security Misconfiguration",
    "EXPIRED_CERTIFICATE":   "API8:2023 — Security Misconfiguration",
    "MISSING_HSTS":          "API8:2023 — Security Misconfiguration",
}


class ScanHistory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT,
                    target TEXT,
                    risk_score REAL,
                    total_findings INTEGER,
                    critical INTEGER,
                    high INTEGER,
                    medium INTEGER,
                    low INTEGER,
                    raw_report TEXT
                )
            ''')

    def save(self, report: dict) -> int:
        findings = self._extract_all_findings(report)
        risk_score, c, h, m, l = self._calculate_risk(findings)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (scan_date, target, risk_score, total_findings, critical, high, medium, low, raw_report)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.get("scan_date", ""),
                report.get("target", ""),
                risk_score,
                len(findings),
                c, h, m, l,
                json.dumps(report)
            ))
            return cursor.lastrowid

    def load(self, scan_id: int) -> dict | None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT raw_report FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def list_scans(self, target: str | None = None) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if target:
                cursor.execute('SELECT id, target, scan_date, risk_score, total_findings, critical, high, medium, low FROM scans WHERE target=? ORDER BY id DESC', (target,))
            else:
                cursor.execute('SELECT id, target, scan_date, risk_score, total_findings, critical, high, medium, low FROM scans ORDER BY id DESC')

            rows = cursor.fetchall()
            return [
                {
                    "id": r[0], "target": r[1], "scan_date": r[2], "risk_score": r[3],
                    "total_findings": r[4], "critical": r[5], "high": r[6], "medium": r[7], "low": r[8]
                } for r in rows
            ]

    def compare(self, id_before: int, id_after: int) -> dict:
        before = self.load(id_before)
        after = self.load(id_after)
        if not before or not after:
            raise ValueError("Scan ID not found")

        f_before = self._extract_all_findings(before)
        f_after = self._extract_all_findings(after)

        def sig(f): return f"{f.get('endpoint')}_{f.get('method')}_{f.get('vulnerability_type', f.get('finding_type'))}"

        sig_b = {sig(f): f for f in f_before}
        sig_a = {sig(f): f for f in f_after}

        fixed = [v for k, v in sig_b.items() if k not in sig_a]
        new = [v for k, v in sig_a.items() if k not in sig_b]

        return {"fixed_findings": fixed, "new_findings": new, "risk_delta": len(new) - len(fixed)}

    def _extract_all_findings(self, report: dict) -> list[dict]:
        findings = []
        for mod_name, mod_data in report.get("modules", {}).items():
            if isinstance(mod_data, dict):
                findings.extend(mod_data.get("findings", []))
        return findings

    def _calculate_risk(self, findings: list[dict]) -> tuple[float, int, int, int, int]:
        c = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        h = sum(1 for f in findings if f.get("severity") == "HIGH")
        m = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        l = sum(1 for f in findings if f.get("severity") == "LOW")
        score = min(10.0, (c * 3) + (h * 2) + (m * 1) + (l * 0.5))
        return score, c, h, m, l


class ReportGenerator:
    def __init__(self, report: dict):
        self.report = report
        self.findings = []
        for mod_data in report.get("modules", {}).values():
            if isinstance(mod_data, dict):
                self.findings.extend(mod_data.get("findings", []))

        self.critical = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        self.high = sum(1 for f in self.findings if f.get("severity") == "HIGH")
        self.medium = sum(1 for f in self.findings if f.get("severity") == "MEDIUM")
        self.low = sum(1 for f in self.findings if f.get("severity") == "LOW")
        self.risk_score = min(10.0, (self.critical * 3) + (self.high * 2) + (self.medium * 1) + (self.low * 0.5))

    def print_summary(self):
        target = self.report.get('target', 'Unknown')
        print(f"\n{'═' * 60}")
        print(f"  APIGuard Enterprise — Scan Report")
        print(f"{'═' * 60}")
        print(f"  Target       : {target}")
        print(f"  Risk Score   : {self.risk_score:.1f}/10.0")
        print(f"  Total Findings: {len(self.findings)}")
        print(f"    🔴 Critical : {self.critical}")
        print(f"    🟠 High     : {self.high}")
        print(f"    🟡 Medium   : {self.medium}")
        print(f"    🟢 Low      : {self.low}")
        print(f"{'═' * 60}")

    def save_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2)

    def save_html(self, path: str):
        html = self.get_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def get_html(self) -> str:
        """Generate a standalone HTML dashboard."""
        return "<html><body><h1>APIGuard Report</h1><p>Please use the Next.js Dashboard instead.</p></body></html>"

    def save_to_history(self, db_path: str) -> int:
        hist = ScanHistory(db_path)
        return hist.save(self.report)

    # ─────────────────────────────────────────
    # Professional PDF Report
    # ─────────────────────────────────────────

    def save_pdf(self, path: str):
        """Generate a professional multi-page PDF executive report."""
        doc = SimpleDocTemplate(
            path, pagesize=A4,
            topMargin=20 * mm, bottomMargin=20 * mm,
            leftMargin=20 * mm, rightMargin=20 * mm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"],
            fontSize=28, textColor=COLORS["header_bg"],
            spaceAfter=6, alignment=TA_CENTER,
        )
        heading_style = ParagraphStyle(
            "CustomHeading", parent=styles["Heading1"],
            fontSize=18, textColor=COLORS["header_bg"],
            spaceBefore=16, spaceAfter=8,
            borderWidth=0, borderColor=COLORS["accent"],
            borderPadding=4,
        )
        subheading_style = ParagraphStyle(
            "CustomSubHeading", parent=styles["Heading2"],
            fontSize=14, textColor=COLORS["text"],
            spaceBefore=12, spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "CustomBody", parent=styles["Normal"],
            fontSize=10, textColor=COLORS["text"],
            spaceAfter=6, leading=14,
        )
        small_style = ParagraphStyle(
            "Small", parent=styles["Normal"],
            fontSize=8, textColor=COLORS["text_light"],
        )
        center_style = ParagraphStyle(
            "Center", parent=body_style, alignment=TA_CENTER,
        )

        elements = []

        # ══════════════════════════════════════
        # PAGE 1: Cover
        # ══════════════════════════════════════
        elements.append(Spacer(1, 80))
        elements.append(Paragraph("🛡️", ParagraphStyle("Emoji", fontSize=60, alignment=TA_CENTER)))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("APIGuard", title_style))
        elements.append(Paragraph("Enterprise Security Scan Report", ParagraphStyle(
            "Subtitle", parent=styles["Normal"], fontSize=16,
            textColor=COLORS["text_light"], alignment=TA_CENTER, spaceAfter=30,
        )))
        elements.append(HRFlowable(width="60%", thickness=2, color=COLORS["accent"], spaceAfter=30))

        # Cover info table
        target = self.report.get("target", "Unknown")
        scan_date = self.report.get("scan_date", time.strftime("%Y-%m-%dT%H:%M:%SZ"))
        cover_data = [
            ["Target", target],
            ["Scan Date", scan_date],
            ["Risk Score", f"{self.risk_score:.1f} / 10.0"],
            ["Total Findings", str(len(self.findings))],
            ["Engine Version", self.report.get("version", "2.0")],
        ]
        cover_table = Table(cover_data, colWidths=[120, 300])
        cover_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 12),
            ("TEXTCOLOR", (0, 0), (0, -1), COLORS["header_bg"]),
            ("TEXTCOLOR", (1, 0), (1, -1), COLORS["text"]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("ALIGN", (1, 0), (1, -1), "LEFT"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.5, COLORS["border"]),
        ]))
        elements.append(cover_table)
        elements.append(Spacer(1, 40))

        # Risk level label
        if self.risk_score >= 7:
            risk_label = "CRITICAL RISK"
            risk_color = COLORS["critical"]
        elif self.risk_score >= 4:
            risk_label = "HIGH RISK"
            risk_color = COLORS["high"]
        elif self.risk_score >= 2:
            risk_label = "MODERATE RISK"
            risk_color = COLORS["medium"]
        else:
            risk_label = "LOW RISK"
            risk_color = COLORS["low"]

        elements.append(Paragraph(
            f'<font color="{risk_color.hexval()}" size="22"><b>{risk_label}</b></font>',
            center_style
        ))

        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            "CONFIDENTIAL — For authorized personnel only.",
            ParagraphStyle("Conf", parent=small_style, alignment=TA_CENTER, textColor=COLORS["critical"])
        ))

        elements.append(PageBreak())

        # ══════════════════════════════════════
        # PAGE 2: Executive Summary
        # ══════════════════════════════════════
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(
            f"This report presents the results of an automated security assessment of "
            f"<b>{target}</b> conducted on <b>{scan_date}</b> using the APIGuard Enterprise "
            f"Security Scanner v{self.report.get('version', '2.0')}. The scan identified "
            f"<b>{len(self.findings)} vulnerabilities</b> across the OWASP API Security Top 10 categories.",
            body_style,
        ))
        elements.append(Spacer(1, 12))

        # Severity breakdown table
        elements.append(Paragraph("Vulnerability Distribution", subheading_style))
        sev_data = [
            ["Severity", "Count", "Impact"],
            ["🔴 CRITICAL", str(self.critical), "Immediate exploitation risk"],
            ["🟠 HIGH", str(self.high), "Significant security weakness"],
            ["🟡 MEDIUM", str(self.medium), "Moderate concern"],
            ["🟢 LOW", str(self.low), "Minor issue or informational"],
        ]
        sev_table = Table(sev_data, colWidths=[140, 60, 260])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["header_bg"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLORS["white"], HexColor("#f8f9fa")]),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 16))

        # Pie chart
        if self.findings:
            elements.append(Paragraph("Risk Distribution", subheading_style))
            drawing = Drawing(300, 180)
            pie = Pie()
            pie.x = 80
            pie.y = 10
            pie.width = 140
            pie.height = 140
            pie_data = []
            pie_labels = []
            pie_colors = []
            for sev, count, color in [
                ("Critical", self.critical, COLORS["critical"]),
                ("High", self.high, COLORS["high"]),
                ("Medium", self.medium, COLORS["medium"]),
                ("Low", self.low, COLORS["low"]),
            ]:
                if count > 0:
                    pie_data.append(count)
                    pie_labels.append(f"{sev} ({count})")
                    pie_colors.append(color)

            if pie_data:
                pie.data = pie_data
                pie.labels = pie_labels
                for i, color in enumerate(pie_colors):
                    pie.slices[i].fillColor = color
                    pie.slices[i].strokeColor = COLORS["white"]
                    pie.slices[i].strokeWidth = 2
                drawing.add(pie)
                elements.append(drawing)

        elements.append(PageBreak())

        # ══════════════════════════════════════
        # PAGE 3+: Detailed Findings
        # ══════════════════════════════════════
        elements.append(Paragraph("Detailed Findings", heading_style))

        if not self.findings:
            elements.append(Paragraph("✅ No vulnerabilities were detected during this scan.", body_style))
        else:
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))

            for i, finding in enumerate(sorted_findings, 1):
                sev = finding.get("severity", "INFO")
                sev_color = SEVERITY_COLORS.get(sev, COLORS["info"])
                ftype = finding.get("vulnerability_type", finding.get("finding_type", "UNKNOWN"))
                endpoint = finding.get("endpoint", "N/A")
                method = finding.get("method", "")
                desc = finding.get("description", "")
                proof = finding.get("proof", "")
                remediation = finding.get("remediation", "")

                # Finding header
                elements.append(Paragraph(
                    f'<font color="{sev_color.hexval()}"><b>#{i} [{sev}]</b></font> '
                    f'<b>{ftype}</b>',
                    ParagraphStyle("FindingTitle", parent=body_style, fontSize=11, spaceBefore=10)
                ))

                # Finding details table
                details = []
                if endpoint:
                    details.append(["Endpoint", f"{method} {endpoint}"])
                if desc:
                    details.append(["Description", desc[:300]])
                if proof:
                    details.append(["Evidence", proof[:300]])
                if remediation:
                    details.append(["Remediation", remediation[:300]])

                # OWASP mapping
                owasp = OWASP_MAPPING.get(ftype, "")
                if owasp:
                    details.append(["OWASP Category", owasp])

                if details:
                    detail_table = Table(details, colWidths=[90, 370])
                    detail_table.setStyle(TableStyle([
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("TEXTCOLOR", (0, 0), (0, -1), COLORS["text_light"]),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("LINEBELOW", (0, -1), (-1, -1), 0.5, COLORS["border"]),
                    ]))
                    elements.append(detail_table)

            elements.append(PageBreak())

        # ══════════════════════════════════════
        # OWASP Compliance Page
        # ══════════════════════════════════════
        elements.append(Paragraph("OWASP API Security Top 10 — Compliance", heading_style))
        elements.append(Paragraph(
            "This section maps each detected vulnerability to the OWASP API Security Top 10 (2023) framework.",
            body_style,
        ))
        elements.append(Spacer(1, 8))

        owasp_categories = [
            "API1:2023 — Broken Object Level Authorization",
            "API2:2023 — Broken Authentication",
            "API3:2023 — Broken Object Property Level Authorization",
            "API4:2023 — Unrestricted Resource Consumption",
            "API5:2023 — Broken Function Level Authorization",
            "API6:2023 — Unrestricted Access to Sensitive Business Flows",
            "API7:2023 — Server Side Request Forgery",
            "API8:2023 — Security Misconfiguration",
            "API9:2023 — Improper Inventory Management",
            "API10:2023 — Unsafe Consumption of APIs",
        ]

        # Count findings per OWASP category
        owasp_counts = {}
        for f in self.findings:
            ftype = f.get("vulnerability_type", f.get("finding_type", ""))
            category = OWASP_MAPPING.get(ftype, "")
            if category:
                owasp_counts[category] = owasp_counts.get(category, 0) + 1

        owasp_data = [["OWASP Category", "Status", "Findings"]]
        for cat in owasp_categories:
            count = owasp_counts.get(cat, 0)
            status = "⚠️ FAIL" if count > 0 else "✅ PASS"
            owasp_data.append([cat, status, str(count)])

        owasp_table = Table(owasp_data, colWidths=[300, 80, 60])
        owasp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["header_bg"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLORS["white"], HexColor("#f8f9fa")]),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(owasp_table)
        elements.append(Spacer(1, 16))

        # ══════════════════════════════════════
        # Remediation Roadmap
        # ══════════════════════════════════════
        elements.append(Paragraph("Remediation Roadmap", heading_style))
        elements.append(Paragraph(
            "The following prioritized actions are recommended based on the findings:",
            body_style
        ))

        priority_actions = []
        if self.critical > 0:
            priority_actions.append(["🔴 P0 — Immediate", f"Fix {self.critical} CRITICAL vulnerabilities within 24 hours"])
        if self.high > 0:
            priority_actions.append(["🟠 P1 — Urgent", f"Address {self.high} HIGH severity issues within 1 week"])
        if self.medium > 0:
            priority_actions.append(["🟡 P2 — Planned", f"Resolve {self.medium} MEDIUM findings in the next sprint"])
        if self.low > 0:
            priority_actions.append(["🟢 P3 — Backlog", f"Track {self.low} LOW severity items for future improvement"])

        if priority_actions:
            road_table = Table([["Priority", "Action"]] + priority_actions, colWidths=[120, 340])
            road_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLORS["header_bg"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLORS["white"], HexColor("#f8f9fa")]),
            ]))
            elements.append(road_table)
        else:
            elements.append(Paragraph("✅ No remediation actions required. All checks passed.", body_style))

        # Footer
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=1, color=COLORS["border"]))
        elements.append(Paragraph(
            f"Generated by APIGuard Enterprise v{self.report.get('version', '2.0')} — "
            f"{time.strftime('%Y-%m-%d %H:%M UTC')} — CONFIDENTIAL",
            ParagraphStyle("Footer", parent=small_style, alignment=TA_CENTER, spaceBefore=8)
        ))

        # Build PDF
        doc.build(elements)
