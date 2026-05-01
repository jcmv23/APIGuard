"""
Tests for Module 7 - Dashboard
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from module_7_dashboard.report_generator import ScanHistory, ReportGenerator
import pytest
import os

def test_scan_history_save_and_load(tmp_path):
    db = str(tmp_path / "test.db")
    history = ScanHistory(db)
    
    report = {
        "target": "https://api.test",
        "modules": {
            "test": {
                "findings": [
                    {"severity": "CRITICAL", "finding_type": "TEST"}
                ]
            }
        }
    }
    scan_id = history.save(report)
    assert scan_id == 1
    
    loaded = history.load(scan_id)
    assert loaded["target"] == "https://api.test"

def test_compare(tmp_path):
    db = str(tmp_path / "test2.db")
    history = ScanHistory(db)
    r1 = {
        "modules": {"m": {"findings": [{"endpoint":"/a", "method":"GET", "finding_type":"T1"}]}}
    }
    r2 = {
        "modules": {"m": {"findings": [{"endpoint":"/b", "method":"GET", "finding_type":"T2"}]}}
    }
    id1 = history.save(r1)
    id2 = history.save(r2)
    
    comp = history.compare(id1, id2)
    assert len(comp["fixed_findings"]) == 1
    assert len(comp["new_findings"]) == 1
