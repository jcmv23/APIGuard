"""
APIGuard Enterprise — Custom Rules Engine
============================================
YAML-based custom security rules that users define.
Rules are evaluated against scan results post-scan to flag custom patterns.

Example rule YAML:
  name: Flag password fields
  severity: HIGH
  condition:
    type: response_contains_field
    field: password
  message: "API response contains 'password' field"
"""

import sqlite3
import time
import json
import re
import yaml  # type: ignore
from typing import Optional


DB_FILE = "apiguard_rules.db"


def init_rules_db(db_path: str = DB_FILE):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            yaml_content TEXT NOT NULL,
            severity TEXT DEFAULT 'MEDIUM',
            enabled INTEGER DEFAULT 1,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    # Insert default rules if empty
    if c.execute("SELECT COUNT(*) FROM custom_rules").fetchone()[0] == 0:
        defaults = [
            {
                "name": "Flag Sensitive Fields in Response",
                "description": "Detects API responses containing password, secret, or token fields",
                "severity": "HIGH",
                "yaml": """
name: Flag Sensitive Fields
condition:
  type: response_contains_field
  fields: [password, secret, api_key, access_token, private_key, ssn, credit_card]
message: "Response contains sensitive field: {matched_field}"
"""
            },
            {
                "name": "Excessive Response Size",
                "description": "Flags responses larger than 500KB",
                "severity": "MEDIUM",
                "yaml": """
name: Excessive Response Size
condition:
  type: response_size_exceeds
  max_bytes: 512000
message: "Response size exceeds 500KB ({actual_size} bytes)"
"""
            },
            {
                "name": "No Authentication Required",
                "description": "Flags endpoints that return 200 without any authentication",
                "severity": "HIGH",
                "yaml": """
name: No Auth Required
condition:
  type: status_without_auth
  expected_status: 200
message: "Endpoint returns 200 without authentication"
"""
            },
            {
                "name": "Version in URL Path",
                "description": "Warns if API doesn't use versioned paths",
                "severity": "LOW",
                "yaml": """
name: Missing API Versioning
condition:
  type: path_missing_pattern
  pattern: "/v[0-9]+"
message: "Endpoint path does not include API versioning"
"""
            },
        ]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for rule in defaults:
            c.execute(
                "INSERT INTO custom_rules (name, description, yaml_content, severity, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
                (rule["name"], rule["description"], rule["yaml"].strip(), rule["severity"], now, now)
            )

    conn.commit()
    conn.close()

init_rules_db()


class RulesEngine:
    """Evaluate custom rules against scan findings."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def list_rules(self) -> list:
        conn = self._conn()
        rows = conn.execute(
            "SELECT id, name, description, yaml_content, severity, enabled, created_at FROM custom_rules ORDER BY id"
        ).fetchall()
        conn.close()
        return [{
            "id": r[0], "name": r[1], "description": r[2],
            "yaml_content": r[3], "severity": r[4],
            "enabled": bool(r[5]), "created_at": r[6]
        } for r in rows]

    def create_rule(self, name: str, yaml_content: str, severity: str = "MEDIUM",
                    description: str = "", created_by: str = None) -> dict:
        """Create a new custom rule."""
        # Validate YAML
        try:
            parsed = yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict) or 'condition' not in parsed:
                raise ValueError("Rule YAML must contain a 'condition' key")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = self._conn()
        c = conn.execute(
            "INSERT INTO custom_rules (name, description, yaml_content, severity, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
            (name, description, yaml_content, severity.upper(), created_by, now, now)
        )
        rule_id = c.lastrowid
        conn.commit()
        conn.close()
        return {"id": rule_id, "name": name, "severity": severity, "enabled": True}

    def update_rule(self, rule_id: int, yaml_content: str = None, enabled: bool = None, name: str = None):
        conn = self._conn()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if yaml_content is not None:
            conn.execute("UPDATE custom_rules SET yaml_content = ?, updated_at = ? WHERE id = ?", (yaml_content, now, rule_id))
        if enabled is not None:
            conn.execute("UPDATE custom_rules SET enabled = ?, updated_at = ? WHERE id = ?", (int(enabled), now, rule_id))
        if name is not None:
            conn.execute("UPDATE custom_rules SET name = ?, updated_at = ? WHERE id = ?", (name, now, rule_id))
        conn.commit()
        conn.close()

    def delete_rule(self, rule_id: int):
        conn = self._conn()
        conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()

    def evaluate(self, report: dict) -> list:
        """Evaluate all enabled rules against a scan report. Returns list of custom findings."""
        rules = [r for r in self.list_rules() if r["enabled"]]
        custom_findings = []

        for rule in rules:
            try:
                parsed = yaml.safe_load(rule["yaml_content"])
                condition = parsed.get("condition", {})
                ctype = condition.get("type", "")
                message_template = parsed.get("message", rule["name"])

                findings = self._eval_condition(ctype, condition, report, message_template)
                for f in findings:
                    f["rule_id"] = rule["id"]
                    f["rule_name"] = rule["name"]
                    f["severity"] = rule["severity"]
                    f["source"] = "custom_rule"
                    custom_findings.append(f)
            except Exception:
                pass

        return custom_findings

    def _eval_condition(self, ctype: str, condition: dict, report: dict, msg_template: str) -> list:
        """Evaluate a single condition type."""
        findings = []

        if ctype == "response_contains_field":
            fields = condition.get("fields", [condition.get("field", "")])
            for mod_name, mod_data in report.get("modules", {}).items():
                if not isinstance(mod_data, dict):
                    continue
                for finding in mod_data.get("findings", []):
                    desc = str(finding.get("description", "")) + str(finding.get("proof", ""))
                    for field in fields:
                        if field.lower() in desc.lower():
                            findings.append({
                                "vulnerability_type": "CUSTOM_RULE_MATCH",
                                "endpoint": finding.get("endpoint", ""),
                                "description": msg_template.replace("{matched_field}", field),
                                "matched_field": field
                            })

        elif ctype == "path_missing_pattern":
            pattern = condition.get("pattern", "")
            for mod_name, mod_data in report.get("modules", {}).items():
                if not isinstance(mod_data, dict):
                    continue
                for finding in mod_data.get("findings", []):
                    ep = finding.get("endpoint", "")
                    if ep and not re.search(pattern, ep):
                        findings.append({
                            "vulnerability_type": "CUSTOM_RULE_MATCH",
                            "endpoint": ep,
                            "description": msg_template
                        })

        return findings


rules_engine = RulesEngine()
