"""
APIGuard - Web API Server (Enterprise Edition v4.0)
======================================================
FastAPI server with async scanning, WebSocket progress, persistent rate limiting,
structured logging, RBAC, AI vulnerability analysis, and comprehensive security hardening.

Endpoints:
  POST /api/v1/scan           → Start async scan, returns scan_id
  GET  /api/v1/scan/{id}      → Get scan status/results
  GET  /api/v1/scans          → List all past scans
  POST /api/v1/scan/compare   → Compare two scans
  GET  /api/v1/report/{id}/pdf      → Download PDF report
  GET  /api/v1/report/{id}/markdown  → Download Markdown report
  POST /api/v1/explain        → AI vulnerability explainer
  WS   /ws/scan/{id}          → WebSocket for real-time scan progress
  GET  /health                → Health check

Run:
  uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

from core.config import settings
from core.logging_config import setup_logging, get_logger
from core.scan_manager import scan_manager, ScanStatus

from module_1_parser.parser import OpenAPIParser
from module_2_bola.bola_scanner import BOLAScanner
from module_3_bfla.bfla_scanner import BFLAScanner
from module_4_auth.auth_scanner import AuthScanner
from module_5_ratelimit.rate_scanner import RateLimitScanner
from module_6_injection.injection_scanner import InjectionScanner
from module_7_dashboard.report_generator import ReportGenerator, ScanHistory
from module_8_ssl.ssl_scanner import SSLScanner
from module_9_graphql.graphql_scanner import GraphQLScanner
from module_10_data_exposure.data_scanner import DataExposureScanner
from module_11_fuzzer.advanced_fuzzer import AdvancedFuzzer
from module_12_jwt.jwt_analyzer import JWTAnalyzer
from module_13_secrets.secret_scanner import SecretScanner
from module_14_waf.waf_detector import WAFDetector
from module_15_spec.spec_validator import SpecValidator
from user_management import auth_router, get_current_user
from terminal_handler import TerminalExecutor
from integrations.webhooks import notify_all
from core.scheduler import scan_scheduler
from core.remediation import remediation_tracker
from core.rules_engine import rules_engine
from core.api_discovery import APIDiscovery
from core.ci_integration import SARIFExporter, compute_exit_code, format_ci_summary
from core.rate_limiter import persistent_limiter
from core.database import db
from core.oauth import oauth_router
from core.ai_explainer import explain_finding, explain_scan_findings

# ─────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────

setup_logging(level="DEBUG" if settings.DEBUG else "INFO", json_format=settings.ENV == "production")
logger = get_logger("api_server")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="APIGuard Enterprise",
    description="REST API Security Scanner — detects OWASP API Top 10 vulnerabilities.",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
)

# ── Security Headers Middleware ──
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if settings.ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

app.include_router(auth_router, prefix="/api")
app.include_router(oauth_router, prefix="/api")

terminal_executor = TerminalExecutor()
thread_pool = ThreadPoolExecutor(max_workers=4)

HISTORY_DB = settings.HISTORY_DB

# ── Start Scheduler Background Thread ──
def _scheduler_scan_callback(target_url, modules, timeout, notify):
    """Called by the scheduler when a scan is due. Uses globals defined later in this file."""
    logger.info("scheduler_executing_scan", target=target_url)
    sid = scan_manager.create_scan()
    scan_manager.start_scan(sid)
    try:
        # ScanRequest and _run_scan_sync are defined later in this module
        req_cls = globals()["ScanRequest"]
        run_fn = globals()["_run_scan_sync"]
        req = req_cls(url=target_url, modules=modules, timeout=timeout)
        run_fn(req, sid)
    except Exception as e:
        scan_manager.fail_scan(sid, str(e))
        raise
    return sid

scan_scheduler.set_scan_callback(_scheduler_scan_callback)
scan_scheduler.start()


# ─────────────────────────────────────────────
# Request / Response Models
# ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str = Field(..., description="Base URL of the API to scan",
                     json_schema_extra={"example": "https://api.example.com"})
    spec: str | None = Field(None, description="OpenAPI/Swagger spec as JSON string or file path.")
    token_a: str | None = Field(None, description="Auth token for User A (used in BOLA check)")
    id_a: str = Field("1", description="Object ID belonging to User A")
    id_b: str = Field("2", description="Object ID belonging to User B")
    low_priv_token: str | None = Field(None, description="Low-privilege token (BFLA check)")
    admin_token: str | None = Field(None, description="Admin token (optional, improves BFLA)")
    auth_token: str | None = Field(None, description="JWT to analyse in Module 4")
    modules: list[str] = Field(
        default=["bola", "bfla", "auth", "rate", "injection", "ssl", "graphql", "data_exposure", "fuzzer", "jwt", "secrets", "waf", "spec"],
        description="Scanner modules to run",
    )
    rate_requests: int = Field(50, description="Requests per burst for rate-limit check")
    timeout: int = Field(10, description="HTTP timeout per request (seconds)")
    delay: float = Field(0.1, description="Delay between requests (seconds)")
    notify: bool = Field(True, description="Send webhook notifications after scan")


class CompareRequest(BaseModel):
    scan_id_before: int
    scan_id_after: int


class ScheduleRequest(BaseModel):
    name: str = Field(..., description="Schedule name")
    target_url: str = Field(..., description="Target API URL")
    cron_expr: str = Field("0 3 * * 1", description="Cron expression")
    modules: list[str] = Field(default=["bola","bfla","auth","rate","injection","ssl","graphql","data_exposure","fuzzer","jwt","secrets","waf","spec"])
    timeout: int = Field(10)
    notify: bool = Field(True)
    start_at: str | None = Field(None, description="ISO datetime for first run (e.g. 2026-05-01T08:30:00Z)")
    repeat_interval_min: int = Field(0, description="Repeat interval in minutes (0 = use cron)")
    max_runs: int = Field(0, description="Max number of runs (0 = unlimited)")


class FindingUpdateRequest(BaseModel):
    status: str = Field(..., description="New status: open, in_progress, fixed, accepted_risk, false_positive")
    note: str = Field("", description="Optional note")
    assigned_to: str | None = Field(None, description="Assign to user email")


class CustomRuleRequest(BaseModel):
    name: str
    yaml_content: str
    severity: str = Field("MEDIUM")
    description: str = Field("")


class CIScanRequest(BaseModel):
    url: str
    modules: str = Field("bola,bfla,auth,rate,injection,ssl,graphql,data_exposure")
    fail_on: str = Field("HIGH")
    timeout: int = Field(15)


class TerminalRequest(BaseModel):
    command: str
    context: str | None = None
    token: str | None = None


class ScanSummary(BaseModel):
    id: int
    target: str
    scan_date: str
    risk_score: float
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int


# ─────────────────────────────────────────────
# Core Scan Logic (runs in background thread)
# ─────────────────────────────────────────────

def _run_scan_sync(req: ScanRequest, scan_id: str) -> dict:
    """Execute all requested scanner modules and return the combined report."""
    report: dict[str, Any] = {
        "tool": "APIGuard Enterprise",
        "version": settings.APP_VERSION,
        "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": req.url,
        "scan_id": scan_id,
        "modules": {},
        "errors": [],
    }

    scan_manager.start_scan(scan_id)

    # ── 1. Parse ──────────────────────────────
    scan_manager.update_progress(scan_id, "Parser", 5)
    try:
        parser = OpenAPIParser(base_url=req.url, spec=req.spec, timeout=req.timeout)
        endpoints = parser.parse()
        report["modules"]["parser"] = parser.to_dict()
        logger.info("parser_complete", endpoints=len(endpoints))
    except Exception as exc:
        report["errors"].append(f"Parser: {exc}")
        scan_manager.fail_scan(scan_id, f"Could not parse API spec: {exc}")
        return report

    mods = {m.lower() for m in req.modules}
    total_mods = len(mods)
    completed = 0

    def _progress(mod_name: str):
        nonlocal completed
        completed += 1
        pct = int(10 + (completed / max(total_mods, 1)) * 85)
        scan_manager.update_progress(scan_id, mod_name, pct)

    # ── 2. BOLA ───────────────────────────────
    if "bola" in mods:
        try:
            if req.token_a:
                r = BOLAScanner(
                    token_user_a=req.token_a, id_user_a=req.id_a, id_user_b=req.id_b,
                    timeout=req.timeout, delay_between_requests=req.delay,
                ).scan(endpoints)
                report["modules"]["module_2_bola"] = r.to_dict()
            else:
                report["modules"]["module_2_bola"] = {"skipped": True, "reason": "token_a not provided", "findings": []}
        except Exception as exc:
            report["errors"].append(f"BOLA: {exc}")
            report["modules"]["module_2_bola"] = {"error": str(exc), "findings": []}
        _progress("BOLA")

    # ── 3. BFLA ───────────────────────────────
    if "bfla" in mods:
        try:
            if req.low_priv_token:
                r = BFLAScanner(
                    low_priv_token=req.low_priv_token, admin_token=req.admin_token,
                    timeout=req.timeout, delay_between_requests=req.delay,
                ).scan(endpoints)
                report["modules"]["module_3_bfla"] = r.to_dict()
            else:
                report["modules"]["module_3_bfla"] = {"skipped": True, "reason": "low_priv_token not provided", "findings": []}
        except Exception as exc:
            report["errors"].append(f"BFLA: {exc}")
            report["modules"]["module_3_bfla"] = {"error": str(exc), "findings": []}
        _progress("BFLA")

    # ── 4. Auth/JWT ───────────────────────────
    if "auth" in mods:
        try:
            r = AuthScanner(
                valid_token=req.auth_token or req.token_a,
                timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_4_auth"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Auth: {exc}")
            report["modules"]["module_4_auth"] = {"error": str(exc), "findings": []}
        _progress("Auth/JWT")

    # ── 5. Rate Limiting ──────────────────────
    if "rate" in mods:
        try:
            r = RateLimitScanner(
                token=req.token_a, timeout=req.timeout,
                requests_to_send=req.rate_requests,
            ).scan(endpoints)
            report["modules"]["module_5_ratelimit"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Rate: {exc}")
            report["modules"]["module_5_ratelimit"] = {"error": str(exc), "findings": []}
        _progress("Rate Limit")

    # ── 6. Injection/CORS ─────────────────────
    if "injection" in mods:
        try:
            r = InjectionScanner(
                token=req.token_a, timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_6_injection"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Injection: {exc}")
            report["modules"]["module_6_injection"] = {"error": str(exc), "findings": []}
        _progress("Injection/CORS")

    # ── 7. SSL/TLS (NEW) ─────────────────────
    if "ssl" in mods:
        try:
            r = SSLScanner(timeout=req.timeout).scan(req.url)
            report["modules"]["module_8_ssl"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"SSL: {exc}")
            report["modules"]["module_8_ssl"] = {"error": str(exc), "findings": []}
        _progress("SSL/TLS")

    # ── 8. GraphQL (NEW) ─────────────────────
    if "graphql" in mods:
        try:
            r = GraphQLScanner(token=req.token_a, timeout=req.timeout).scan(req.url)
            report["modules"]["module_9_graphql"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"GraphQL: {exc}")
            report["modules"]["module_9_graphql"] = {"error": str(exc), "findings": []}
        _progress("GraphQL")

    # ── 9. Data Exposure (NEW) ────────────────
    if "data_exposure" in mods:
        try:
            r = DataExposureScanner(
                token=req.token_a, timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_10_data_exposure"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Data Exposure: {exc}")
            report["modules"]["module_10_data_exposure"] = {"error": str(exc), "findings": []}
        _progress("Data Exposure")

    # ── 10. Advanced Fuzzer (v4.0) ────────────
    if "fuzzer" in mods:
        try:
            r = AdvancedFuzzer(
                token=req.token_a, timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_11_fuzzer"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Fuzzer: {exc}")
            report["modules"]["module_11_fuzzer"] = {"error": str(exc), "findings": []}
        _progress("Advanced Fuzzer")

    # ── 11. JWT Analyzer (v4.0) ───────────────
    if "jwt" in mods:
        try:
            jwt_token = req.auth_token or req.token_a
            r = JWTAnalyzer(
                token=jwt_token, target_url=req.url, timeout=req.timeout,
            ).scan()
            report["modules"]["module_12_jwt"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"JWT: {exc}")
            report["modules"]["module_12_jwt"] = {"error": str(exc), "findings": []}
        _progress("JWT Analyzer")

    # ── 12. Secret Scanner (v4.0) ─────────────
    if "secrets" in mods:
        try:
            r = SecretScanner(
                token=req.token_a, timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_13_secrets"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Secrets: {exc}")
            report["modules"]["module_13_secrets"] = {"error": str(exc), "findings": []}
        _progress("Secret Scanner")

    # ── 13. WAF Detector (v4.0) ───────────────
    if "waf" in mods:
        try:
            r = WAFDetector(
                token=req.token_a, timeout=req.timeout,
            ).scan(endpoints)
            report["modules"]["module_14_waf"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"WAF: {exc}")
            report["modules"]["module_14_waf"] = {"error": str(exc), "findings": []}
        _progress("WAF Detector")

    # ── 14. Spec Validator (v4.0) ─────────────
    if "spec" in mods:
        try:
            r = SpecValidator(
                token=req.token_a, timeout=req.timeout, delay=req.delay,
            ).scan(endpoints)
            report["modules"]["module_15_spec"] = r.to_dict()
        except Exception as exc:
            report["errors"].append(f"Spec: {exc}")
            report["modules"]["module_15_spec"] = {"error": str(exc), "findings": []}
        _progress("Spec Validator")

    # ── Save & Notify ─────────────────────────
    scan_manager.update_progress(scan_id, "Generating Reports", 95)

    try:
        gen = ReportGenerator(report)
        history_id = gen.save_to_history(HISTORY_DB)
        report["history_id"] = history_id
    except Exception as exc:
        report["errors"].append(f"History: {exc}")

    # Send webhook notifications
    if req.notify:
        try:
            notify_all(report)
        except Exception:
            pass

    scan_manager.complete_scan(scan_id, report)
    logger.info("scan_completed", scan_id=scan_id, target=req.url,
                findings=sum(len(m.get("findings", [])) for m in report["modules"].values() if isinstance(m, dict)))

    return report


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "tool": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENV,
    }


@app.post("/api/v1/scan", summary="Start an async security scan")
@limiter.limit(settings.RATE_LIMIT_SCAN)
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks, request: Request) -> JSONResponse:
    """
    Start a security scan in the background. Returns immediately with a scan_id.
    Use GET /api/v1/scan/{scan_id} to check progress, or connect via WebSocket at /ws/scan/{scan_id}.
    """
    scan_id = scan_manager.create_scan()

    # Run scan in background thread
    background_tasks.add_task(_run_scan_in_thread, req, scan_id)

    logger.info("scan_queued", scan_id=scan_id, target=req.url, modules=req.modules)

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan queued. Track progress at GET /api/v1/scan/{scan_id} or WS /ws/scan/{scan_id}",
        }
    )


def _run_scan_in_thread(req: ScanRequest, scan_id: str):
    """Wrapper to run the synchronous scan in a background thread."""
    try:
        _run_scan_sync(req, scan_id)
    except Exception as exc:
        scan_manager.fail_scan(scan_id, str(exc))
        logger.error("scan_thread_error", scan_id=scan_id, error=str(exc))


@app.post("/api/v1/scan/sync", summary="Run a synchronous scan (blocks until complete)")
@limiter.limit(settings.RATE_LIMIT_SCAN)
def scan_sync(req: ScanRequest, request: Request) -> JSONResponse:
    """Run a full scan synchronously. Blocks until all modules have completed."""
    scan_id = scan_manager.create_scan()
    report = _run_scan_sync(req, scan_id)
    return JSONResponse(content=report)


@app.get("/api/v1/scan/{scan_id}", summary="Get scan status and results")
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def get_scan_status(scan_id: str, request: Request):
    """Get the current status and results of a scan."""
    state = scan_manager.get_scan(scan_id)
    if state:
        return JSONResponse(content=state)

    # Fallback: try numeric ID from history DB
    try:
        numeric_id = int(scan_id)
        history = ScanHistory(HISTORY_DB)
        report = history.load(numeric_id)
        if report:
            return JSONResponse(content=report)
    except (ValueError, TypeError):
        pass

    raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")


@app.get("/api/v1/scans", summary="List past scans", response_model=list[ScanSummary])
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def list_scans(target: str | None = None, request: Request = None):
    """Return a list of all past scans, optionally filtered by target URL."""
    history = ScanHistory(HISTORY_DB)
    return history.list_scans(target=target)


@app.post("/api/v1/scan/compare", summary="Compare two scans")
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def compare_scans(req: CompareRequest, request: Request):
    """Compare two scan IDs to see what was fixed and what regressed."""
    history = ScanHistory(HISTORY_DB)
    try:
        return history.compare(req.scan_id_before, req.scan_id_after)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/v1/report/{scan_id}/pdf", summary="Download PDF report")
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def get_pdf_report(scan_id: int, request: Request):
    """Generate and download a professional PDF executive report."""
    history = ScanHistory(HISTORY_DB)
    report = history.load(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")

    gen = ReportGenerator(report)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        tmp_path = f.name
    gen.save_pdf(tmp_path)

    pdf_bytes = open(tmp_path, "rb").read()
    os.unlink(tmp_path)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="apiguard_scan_{scan_id}.pdf"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.get("/api/v1/report/{scan_id}/html", summary="Download HTML report", response_class=HTMLResponse)
def get_html_report(scan_id: int):
    history = ScanHistory(HISTORY_DB)
    report = history.load(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
    gen = ReportGenerator(report)
    return HTMLResponse(content=gen.get_html())


# ── WebSocket for real-time scan progress ────

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress updates."""
    await websocket.accept()
    scan_manager.register_ws(scan_id, websocket)
    logger.info("ws_connected", scan_id=scan_id)

    try:
        while True:
            state = scan_manager.get_scan(scan_id)
            if state:
                await websocket.send_text(json.dumps(state))
                if state["status"] in ("completed", "failed"):
                    break
            else:
                await websocket.send_text(json.dumps({"error": "Scan not found"}))
                break
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        logger.info("ws_disconnected", scan_id=scan_id)
    except Exception as e:
        logger.error("ws_error", scan_id=scan_id, error=str(e))
    finally:
        scan_manager.unregister_ws(scan_id, websocket)


# ── Terminal (kept for backward compat) ──────

@app.post("/api/terminal/execute", summary="Interactive telemetry console")
def execute_terminal_command(req: TerminalRequest):
    user_info = None
    if req.token:
        from core.security import decode_token
        payload = decode_token(req.token)
        if payload:
            user_info = {"name": payload.get("name", "user"), "role": payload.get("role", "guest")}

    res = terminal_executor.execute(req.command, req.context, user_info)
    return JSONResponse(content=res)


# ── Legacy endpoints (backward compatibility) ──

@app.post("/scan", summary="Run scan (legacy)", include_in_schema=False)
def scan_legacy(req: ScanRequest):
    """Legacy endpoint — redirects to sync scan."""
    scan_id = scan_manager.create_scan()
    report = _run_scan_sync(req, scan_id)
    return JSONResponse(content=report)


@app.get("/scans", summary="List scans (legacy)", include_in_schema=False)
def list_scans_legacy(target: str | None = None):
    history = ScanHistory(HISTORY_DB)
    return history.list_scans(target=target)


@app.get("/scan/{scan_id}", summary="Get scan (legacy)", include_in_schema=False)
def get_scan_legacy(scan_id: int):
    history = ScanHistory(HISTORY_DB)
    report = history.load(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
    return JSONResponse(content=report)


# ─────────────────────────────────────────────
# Scan Scheduler Endpoints
# ─────────────────────────────────────────────

@app.post("/api/v1/schedules", summary="Create a scheduled scan")
def create_schedule(req: ScheduleRequest, request: Request):
    result = scan_scheduler.create_schedule(
        name=req.name, target_url=req.target_url, cron_expr=req.cron_expr,
        modules=req.modules, timeout=req.timeout, notify=req.notify,
        start_at=req.start_at, repeat_interval_min=req.repeat_interval_min,
        max_runs=req.max_runs
    )
    return JSONResponse(status_code=201, content=result)


@app.get("/api/v1/schedules", summary="List all scheduled scans")
def list_schedules(request: Request):
    return scan_scheduler.list_schedules()


@app.delete("/api/v1/schedules/{schedule_id}", summary="Delete a schedule")
def delete_schedule(schedule_id: str, request: Request):
    scan_scheduler.delete_schedule(schedule_id)
    return {"status": "deleted", "id": schedule_id}


@app.patch("/api/v1/schedules/{schedule_id}/toggle", summary="Enable/disable a schedule")
def toggle_schedule(schedule_id: str, enabled: bool, request: Request):
    scan_scheduler.toggle_schedule(schedule_id, enabled)
    return {"status": "updated", "id": schedule_id, "enabled": enabled}


# ─────────────────────────────────────────────
# Remediation Tracking Endpoints
# ─────────────────────────────────────────────

@app.get("/api/v1/findings", summary="List tracked findings")
def list_findings(scan_id: str | None = None, status: str | None = None,
                  severity: str | None = None, request: Request = None):
    return remediation_tracker.list_findings(scan_id=scan_id, status=status, severity=severity)


@app.patch("/api/v1/findings/{finding_id}", summary="Update finding status")
def update_finding(finding_id: int, req: FindingUpdateRequest, request: Request):
    try:
        result = remediation_tracker.update_status(finding_id, req.status, note=req.note)
        if req.assigned_to:
            remediation_tracker.assign_finding(finding_id, req.assigned_to)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/metrics", summary="Get remediation and trend metrics")
def get_metrics(request: Request = None):
    rem_metrics = remediation_tracker.get_metrics()

    # Add scan trend data
    history = ScanHistory(HISTORY_DB)
    all_scans = history.list_scans()

    # Monthly aggregation
    monthly = {}
    for s in all_scans:
        month = s.get("scan_date", "")[:7]  # YYYY-MM
        if month not in monthly:
            monthly[month] = {"scans": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "avg_risk": 0}
        monthly[month]["scans"] += 1
        monthly[month]["critical"] += s.get("critical", 0)
        monthly[month]["high"] += s.get("high", 0)
        monthly[month]["medium"] += s.get("medium", 0)
        monthly[month]["low"] += s.get("low", 0)
        monthly[month]["avg_risk"] += s.get("risk_score", 0)

    for m in monthly.values():
        m["avg_risk"] = round(m["avg_risk"] / max(m["scans"], 1), 1)

    trend = [{"month": k, **v} for k, v in sorted(monthly.items())]

    return {
        **rem_metrics,
        "total_scans": len(all_scans),
        "monthly_trend": trend,
    }


# ─────────────────────────────────────────────
# Custom Rules Engine Endpoints
# ─────────────────────────────────────────────

@app.get("/api/v1/rules", summary="List custom security rules")
def list_rules(request: Request = None):
    return rules_engine.list_rules()


@app.post("/api/v1/rules", summary="Create a custom rule")
def create_rule(req: CustomRuleRequest, request: Request):
    try:
        return rules_engine.create_rule(name=req.name, yaml_content=req.yaml_content,
                                         severity=req.severity, description=req.description)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/v1/rules/{rule_id}", summary="Delete a custom rule")
def delete_rule(rule_id: int, request: Request):
    rules_engine.delete_rule(rule_id)
    return {"status": "deleted", "id": rule_id}


@app.patch("/api/v1/rules/{rule_id}/toggle", summary="Enable/disable a rule")
def toggle_rule(rule_id: int, enabled: bool, request: Request):
    rules_engine.update_rule(rule_id, enabled=enabled)
    return {"status": "updated", "id": rule_id, "enabled": enabled}


# ─────────────────────────────────────────────
# API Discovery Endpoint
# ─────────────────────────────────────────────

@app.post("/api/v1/discover", summary="Auto-discover API specs and endpoints")
@limiter.limit(settings.RATE_LIMIT_SCAN)
def discover_api(url: str, request: Request):
    """Probe common paths to find API specs, GraphQL endpoints, docs, and admin panels."""
    discovery = APIDiscovery(timeout=5)
    return discovery.discover(url)


# ─────────────────────────────────────────────
# CI/CD Integration Endpoint
# ─────────────────────────────────────────────

@app.post("/api/v1/ci/scan", summary="CI/CD scan gate — returns SARIF + exit code")
def ci_scan(req: CIScanRequest, request: Request):
    """Run a scan and return SARIF output + exit code for CI pipelines."""
    modules_list = [m.strip() for m in req.modules.split(",")]

    scan_req = ScanRequest(
        url=req.url, modules=modules_list, timeout=req.timeout, notify=False
    )
    scan_id = scan_manager.create_scan()
    report = _run_scan_sync(scan_req, scan_id)

    # Generate SARIF
    sarif = SARIFExporter(report).to_sarif()
    exit_code = compute_exit_code(report, fail_on=req.fail_on)
    summary = format_ci_summary(report)

    # Ingest findings into remediation tracker
    remediation_tracker.ingest_scan_findings(scan_id, report)

    return {
        "exit_code": exit_code,
        "summary": summary,
        "sarif": sarif,
        "scan_id": scan_id,
        "target": req.url,
        "total_findings": sum(len(m.get("findings", [])) for m in report.get("modules", {}).values() if isinstance(m, dict)),
    }


# ─────────────────────────────────────────────
# Rate Limit Analytics
# ─────────────────────────────────────────────

@app.get("/api/v1/rate-limit/stats")
def get_rate_limit_stats():
    """Get rate limiting statistics."""
    return persistent_limiter.get_stats()


# ─────────────────────────────────────────────
# AI Vulnerability Explainer (v4.0)
# ─────────────────────────────────────────────

class ExplainRequest(BaseModel):
    vulnerability_type: str = Field(..., description="Type of vulnerability e.g. BOLA, SQL_INJECTION")
    severity: str = Field("MEDIUM")
    endpoint: str = Field("")
    description: str = Field("")


@app.post("/api/v1/explain", summary="AI-powered vulnerability explanation")
def explain_vulnerability(req: ExplainRequest):
    """Get an AI-generated explanation, impact analysis, and fix suggestion for a vulnerability."""
    finding = {
        "vulnerability_type": req.vulnerability_type,
        "severity": req.severity,
        "endpoint": req.endpoint,
        "description": req.description,
    }
    return explain_finding(finding)


@app.get("/api/v1/report/{scan_id}/explain", summary="Explain all findings from a scan")
def explain_scan(scan_id: int):
    """Generate AI explanations for all findings in a scan."""
    history = ScanHistory(HISTORY_DB)
    report = history.load(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
    return {"scan_id": scan_id, "explanations": explain_scan_findings(report)}


# ─────────────────────────────────────────────
# API Key Management (v4.0)
# ─────────────────────────────────────────────

from core.api_keys import api_key_manager

class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., description="Friendly name for the key, e.g. 'CI Pipeline'")
    scopes: str = Field("*", description="Comma-separated scopes: *, scan, read, ci")
    expires_days: int | None = Field(None, description="Days until expiration, null = never")

@app.post("/api/v1/keys", summary="Create API key", tags=["API Keys"])
def create_api_key(req: APIKeyCreateRequest, user: dict = Depends(get_current_user)):
    """Generate a new API key. The raw key is returned ONLY in this response."""
    result = api_key_manager.create(user["id"], req.name, req.scopes, req.expires_days)
    return result

@app.get("/api/v1/keys", summary="List API keys", tags=["API Keys"])
def list_api_keys(user: dict = Depends(get_current_user)):
    """List all API keys for the current user (keys are masked)."""
    return api_key_manager.list_keys(user["id"])

@app.delete("/api/v1/keys/{key_id}", summary="Revoke API key", tags=["API Keys"])
def revoke_api_key(key_id: int, user: dict = Depends(get_current_user)):
    """Revoke an API key. The key can no longer be used for authentication."""
    if api_key_manager.revoke(key_id, user["id"]):
        return {"status": "revoked", "key_id": key_id}
    raise HTTPException(status_code=404, detail="Key not found or not owned by you")

@app.get("/api/v1/keys/validate", summary="Validate API key", tags=["API Keys"])
def validate_api_key(key: str):
    """Validate an API key and return user info (for external integrations)."""
    result = api_key_manager.validate(key)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid, expired, or revoked API key")
    return {"valid": True, "user_id": result["user_id"], "scopes": result["scopes"]}


# ─────────────────────────────────────────────
# Markdown Report Export (v4.0)
# ─────────────────────────────────────────────

@app.get("/api/v1/report/{scan_id}/markdown", summary="Download Markdown report")
def get_markdown_report(scan_id: int):
    """Generate a Markdown-formatted security report for GitHub Issues/PRs."""
    history = ScanHistory(HISTORY_DB)
    report = history.load(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
    
    lines = [
        f"# 🛡️ APIGuard Security Report",
        f"",
        f"**Target:** `{report.get('target', 'N/A')}`  ",
        f"**Date:** {report.get('scan_date', 'N/A')}  ",
        f"**Scanner:** APIGuard Enterprise v{report.get('version', '4.0')}",
        f"",
        f"---",
        f"",
    ]
    
    total_findings = 0
    for mod_name, mod_data in report.get("modules", {}).items():
        if not isinstance(mod_data, dict) or not mod_data.get("findings"):
            continue
        findings = mod_data["findings"]
        total_findings += len(findings)
        clean_name = mod_name.replace('module_', '').replace('_', ' ').title()
        lines.append(f"## {clean_name} ({len(findings)} findings)")
        lines.append(f"")
        for f in findings:
            sev = f.get('severity', 'INFO')
            emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(sev, '⚪')
            lines.append(f"### {emoji} {sev}: {f.get('vulnerability_type', f.get('finding_type', 'Unknown'))}")
            lines.append(f"")
            lines.append(f"- **Endpoint:** `{f.get('method', 'ANY')} {f.get('endpoint', f.get('path', 'N/A'))}`")
            if f.get('description'):
                lines.append(f"- **Description:** {f['description']}")
            if f.get('remediation'):
                lines.append(f"- **Fix:** {f['remediation']}")
            lines.append(f"")
    
    lines.insert(7, f"**Total Findings:** {total_findings}")
    
    md_content = "\n".join(lines)
    return StreamingResponse(
        io.BytesIO(md_content.encode('utf-8')),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="apiguard_scan_{scan_id}.md"'}
    )


@app.middleware("http")
async def rate_limit_tracking(request: Request, call_next):
    """Track all requests through the persistent rate limiter with per-endpoint sensitivity."""
    client_ip = request.client.host if request.client else "unknown"
    endpoint = request.url.path

    # Check if IP is blocked
    if persistent_limiter.is_blocked(client_ip):
        return JSONResponse(status_code=429, content={
            "detail": "Too many requests. Your IP has been temporarily rate-limited.",
            "retry_after": 60
        })

    # Per-endpoint rate limits (stricter for sensitive endpoints)
    endpoint_limits = {
        "/api/v1/scan": (10, 60),       # 10 scans/min
        "/api/auth/login": (10, 60),     # 10 login attempts/min
        "/api/auth/register": (5, 60),   # 5 registrations/min
        "/api/v1/explain": (30, 60),     # 30 explain requests/min
        "/api/v1/ci/scan": (5, 60),      # 5 CI scans/min
        "/api/v1/discover": (10, 60),    # 10 discovery probes/min
    }

    max_req, window = endpoint_limits.get(endpoint, (100, 60))  # default: 100/min
    persistent_limiter.is_allowed(client_ip, endpoint, max_requests=max_req, window_seconds=window)

    response = await call_next(request)
    return response