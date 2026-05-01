"""
APIGuard - Async Scan Manager
================================
Manages background scan execution with real-time progress tracking
via WebSocket connections.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logging_config import get_logger

logger = get_logger("scan_manager")


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanProgress:
    """Tracks the state of an individual scan."""
    scan_id: str
    status: ScanStatus = ScanStatus.QUEUED
    progress: int = 0  # 0-100
    current_module: str = ""
    modules_completed: list[str] = field(default_factory=list)
    total_modules: int = 6
    started_at: float | None = None
    completed_at: float | None = None
    error: str | None = None
    report: dict | None = None


class ScanManager:
    """
    In-memory scan state manager with WebSocket broadcast support.
    
    Usage:
        manager = ScanManager()
        scan_id = manager.create_scan()
        manager.update_progress(scan_id, module="BOLA", progress=33)
        state = manager.get_scan(scan_id)
    """

    def __init__(self):
        self._scans: dict[str, ScanProgress] = {}
        self._websocket_clients: dict[str, set] = {}  # scan_id -> set of ws connections
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None

    def create_scan(self) -> str:
        """Register a new scan and return its unique ID."""
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        self._scans[scan_id] = ScanProgress(scan_id=scan_id)
        logger.info("scan_created", scan_id=scan_id)
        return scan_id

    def start_scan(self, scan_id: str):
        """Mark a scan as running."""
        scan = self._scans.get(scan_id)
        if scan:
            scan.status = ScanStatus.RUNNING
            scan.started_at = time.time()
            logger.info("scan_started", scan_id=scan_id)

    def update_progress(self, scan_id: str, module: str, progress: int):
        """Update the progress of a running scan."""
        scan = self._scans.get(scan_id)
        if scan:
            scan.current_module = module
            scan.progress = min(progress, 100)
            if module and module not in scan.modules_completed:
                scan.modules_completed.append(module)
            logger.info("scan_progress", scan_id=scan_id, module=module, progress=progress)

    def complete_scan(self, scan_id: str, report: dict):
        """Mark a scan as completed with results."""
        scan = self._scans.get(scan_id)
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.completed_at = time.time()
            scan.report = report
            logger.info("scan_completed", scan_id=scan_id,
                        duration=f"{scan.completed_at - (scan.started_at or 0):.1f}s")

    def fail_scan(self, scan_id: str, error: str):
        """Mark a scan as failed."""
        scan = self._scans.get(scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = time.time()
            scan.error = error
            logger.error("scan_failed", scan_id=scan_id, error=error)

    def get_scan(self, scan_id: str) -> dict | None:
        """Get the current state of a scan as a dict."""
        scan = self._scans.get(scan_id)
        if not scan:
            return None
        result = {
            "scan_id": scan.scan_id,
            "status": scan.status.value,
            "progress": scan.progress,
            "current_module": scan.current_module,
            "modules_completed": scan.modules_completed,
            "total_modules": scan.total_modules,
        }
        if scan.started_at:
            result["started_at"] = scan.started_at
        if scan.completed_at:
            result["completed_at"] = scan.completed_at
            result["duration_seconds"] = round(scan.completed_at - (scan.started_at or 0), 2)
        if scan.error:
            result["error"] = scan.error
        if scan.report:
            result["report"] = scan.report
        return result

    def list_scans(self) -> list[dict]:
        """List all tracked scans with summary info."""
        return [
            {
                "scan_id": s.scan_id,
                "status": s.status.value,
                "progress": s.progress,
                "current_module": s.current_module,
            }
            for s in self._scans.values()
        ]

    # ── WebSocket management ─────────────────

    def register_ws(self, scan_id: str, ws):
        """Register a WebSocket client for scan updates."""
        if scan_id not in self._websocket_clients:
            self._websocket_clients[scan_id] = set()
        self._websocket_clients[scan_id].add(ws)

    def unregister_ws(self, scan_id: str, ws):
        """Remove a WebSocket client from scan updates."""
        clients = self._websocket_clients.get(scan_id, set())
        clients.discard(ws)

    async def broadcast(self, scan_id: str, message: dict):
        """Broadcast a message to all WebSocket clients for a scan."""
        import json
        clients = self._websocket_clients.get(scan_id, set())
        dead = set()
        for ws in clients:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.add(ws)
        for ws in dead:
            clients.discard(ws)

    def cleanup_old_scans(self, max_age_seconds: int = 3600):
        """Remove completed/failed scans older than max_age."""
        now = time.time()
        to_remove = [
            sid for sid, scan in self._scans.items()
            if scan.completed_at and (now - scan.completed_at) > max_age_seconds
        ]
        for sid in to_remove:
            del self._scans[sid]
            self._websocket_clients.pop(sid, None)


# Global singleton
scan_manager = ScanManager()
