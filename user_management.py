"""
APIGuard - Auth & Multi-Tenancy Module (Enterprise Edition)
=============================================================
Handles B2B Multi-Tenancy Authentication with bcrypt password hashing,
JWT access/refresh tokens, role-based access control, and audit logging.
"""

import sqlite3
import uuid
import time
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel, EmailStr

from core.config import settings
from core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
)
from core.logging_config import get_logger

logger = get_logger("auth")
auth_router = APIRouter()
DB_FILE = settings.AUTH_DB


# ─────────────────────────────────────────────
# Database Initialization
# ─────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            name TEXT,
            role TEXT,
            company_id TEXT,
            created_at TEXT,
            last_login TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id TEXT PRIMARY KEY,
            name TEXT,
            join_code TEXT UNIQUE,
            created_by TEXT,
            plan TEXT DEFAULT 'free',
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT,
            detail TEXT,
            ip_address TEXT,
            timestamp TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            token_hash TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0
        )
    """)
    # ── Migration: add missing columns to existing tables ──
    migrations = [
        ("users", "created_at", "TEXT"),
        ("users", "last_login", "TEXT"),
        ("users", "company_id", "TEXT"),
        ("users", "org_role", "TEXT DEFAULT 'analyst'"),
        ("companies", "plan", "TEXT DEFAULT 'free'"),
        ("companies", "created_at", "TEXT"),
    ]
    for table, col, col_type in migrations:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass  # Column already exists

    conn.commit()
    conn.close()

init_db()

# ─────────────────────────────────────────────
# RBAC System
# ─────────────────────────────────────────────

RBAC_PERMISSIONS = {
    "viewer": {"view_scans", "view_reports", "view_findings", "view_metrics"},
    "analyst": {"view_scans", "view_reports", "view_findings", "view_metrics",
                "run_scans", "update_findings", "use_terminal", "run_discovery"},
    "admin": {"view_scans", "view_reports", "view_findings", "view_metrics",
              "run_scans", "update_findings", "use_terminal", "run_discovery",
              "manage_schedules", "manage_rules", "manage_users", "manage_company",
              "export_reports", "ci_integration"},
    "individual": {"view_scans", "view_reports", "view_findings", "view_metrics",
                   "run_scans", "update_findings", "use_terminal", "run_discovery",
                   "manage_schedules", "manage_rules", "export_reports", "ci_integration"},
    "enterprise_admin": {"view_scans", "view_reports", "view_findings", "view_metrics",
                         "run_scans", "update_findings", "use_terminal", "run_discovery",
                         "manage_schedules", "manage_rules", "manage_users", "manage_company",
                         "export_reports", "ci_integration"},
}

def has_permission(user: dict, permission: str) -> bool:
    """Check if a user role has the required permission."""
    role = user.get("role", "viewer")
    org_role = user.get("org_role", role)
    # Use most specific role
    effective_role = org_role if org_role in RBAC_PERMISSIONS else role
    return permission in RBAC_PERMISSIONS.get(effective_role, set())

def require_permission(permission: str):
    """FastAPI dependency factory for permission checks."""
    def checker(user: dict = Depends(get_current_user)):
        if not has_permission(user, permission):
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission} required")
        return user
    return checker


# ─────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────

class AuthRequest(BaseModel):
    email: str
    password: str
    name: str = ""

class EnterpriseRequest(BaseModel):
    email: str
    password: str
    name: str
    action: str          # "create" or "join"
    company_name: str = ""
    join_code: str = ""

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


# ─────────────────────────────────────────────
# Helper: Audit Logging
# ─────────────────────────────────────────────

def _audit(user_id: str, action: str, detail: str = "", ip: str = ""):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, action, detail, ip, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _build_user_response(user_id: str, name: str, email: str, role: str,
                          company_name: str = None, join_code: str = None, plan: str = None) -> dict:
    """Build a standardized token response."""
    access = create_access_token({"sub": user_id, "email": email, "role": role, "name": name})
    refresh = create_refresh_token({"sub": user_id})

    user_data = {"name": name, "email": email, "role": role}
    if company_name:
        user_data["company"] = company_name
    if join_code and role == "enterprise_admin":
        user_data["join_code"] = join_code
    if plan:
        user_data["plan"] = plan

    return {
        "status": "success",
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": user_data,
    }


# ─────────────────────────────────────────────
# Token Dependency
# ─────────────────────────────────────────────

def get_current_user(authorization: str = Header(None)) -> dict:
    """FastAPI dependency to extract and validate the current user from JWT."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {
        "id": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role"),
        "name": payload.get("name"),
    }


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@auth_router.post("/auth/register/individual")
def register_individual(req: AuthRequest):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    c.execute(
        "INSERT INTO users (id, email, password_hash, name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, req.email, hash_password(req.password), req.name, "individual",
         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    )
    conn.commit()
    conn.close()

    _audit(user_id, "REGISTER", f"Individual registration: {req.email}")
    logger.info("user_registered", user_id=user_id, email=req.email, role="individual")

    return _build_user_response(user_id, req.name, req.email, "individual")


@auth_router.post("/auth/register/enterprise")
def register_enterprise(req: EnterpriseRequest):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())

    if req.action == "create":
        import secrets
        company_id = str(uuid.uuid4())
        join_code = f"AG-{secrets.token_hex(3).upper()}"

        c.execute(
            "INSERT INTO companies (id, name, join_code, created_by, plan, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (company_id, req.company_name, join_code, user_id, "pro",
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        )
        c.execute(
            "INSERT INTO users (id, email, password_hash, name, role, company_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, req.email, hash_password(req.password), req.name,
             "enterprise_admin", company_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        )
        conn.commit()
        conn.close()
        _audit(user_id, "REGISTER", f"Enterprise admin + company '{req.company_name}'")
        logger.info("enterprise_created", user_id=user_id, company=req.company_name)

        return _build_user_response(user_id, req.name, req.email, "enterprise_admin",
                                     company_name=req.company_name, join_code=join_code, plan="pro")

    elif req.action == "join":
        c.execute("SELECT id, name, plan FROM companies WHERE join_code = ?", (req.join_code,))
        company = c.fetchone()
        if not company:
            conn.close()
            raise HTTPException(status_code=404, detail="Invalid Join Code")

        company_id, company_name, plan = company
        c.execute(
            "INSERT INTO users (id, email, password_hash, name, role, company_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, req.email, hash_password(req.password), req.name,
             "enterprise_user", company_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        )
        conn.commit()
        conn.close()
        _audit(user_id, "REGISTER", f"Joined company '{company_name}'")
        logger.info("user_joined_company", user_id=user_id, company=company_name)

        return _build_user_response(user_id, req.name, req.email, "enterprise_user",
                                     company_name=company_name, plan=plan)

    raise HTTPException(status_code=400, detail="Invalid action. Use 'create' or 'join'.")


@auth_router.post("/auth/login")
def login(req: AuthRequest):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, email, password_hash, role, company_id FROM users WHERE email = ?", (req.email,))
    user = c.fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    uid, name, email, pw_hash, role, comp_id = user

    if not verify_password(req.password, pw_hash):
        conn.close()
        _audit(uid, "LOGIN_FAILED", f"Bad password for {email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    company_name, join_code, plan = None, None, None
    if comp_id:
        c.execute("SELECT name, join_code, plan FROM companies WHERE id = ?", (comp_id,))
        comp_data = c.fetchone()
        if comp_data:
            company_name, join_code, plan = comp_data

    # Update last login
    c.execute("UPDATE users SET last_login = ? WHERE id = ?",
              (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), uid))
    conn.commit()
    conn.close()

    _audit(uid, "LOGIN", f"Successful login from {email}")
    logger.info("user_login", user_id=uid, email=email)

    return _build_user_response(uid, name, email, role, company_name,
                                 join_code if role == "enterprise_admin" else None, plan)


@auth_router.post("/auth/refresh")
def refresh_token(req: TokenRefreshRequest):
    """Exchange a refresh token for a new access token."""
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id = payload.get("sub")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, email, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    uid, name, email, role = user
    new_access = create_access_token({"sub": uid, "email": email, "role": role, "name": name})
    return {"access_token": new_access, "token_type": "bearer"}


@auth_router.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile from JWT."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, name, email, role, company_id, created_at, last_login FROM users WHERE id = ?",
              (current_user["id"],))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    uid, name, email, role, comp_id, created_at, last_login = user

    company_name, join_code, plan = None, None, None
    if comp_id:
        c.execute("SELECT name, join_code, plan FROM companies WHERE id = ?", (comp_id,))
        comp_data = c.fetchone()
        if comp_data:
            company_name, join_code, plan = comp_data

    conn.close()
    return {
        "id": uid, "name": name, "email": email, "role": role,
        "company": company_name,
        "join_code": join_code if role == "enterprise_admin" else None,
        "plan": plan,
        "created_at": created_at, "last_login": last_login,
    }


@auth_router.get("/auth/audit")
def get_audit_log(current_user: dict = Depends(get_current_user)):
    """Get audit log (admin only)."""
    if current_user["role"] not in ("enterprise_admin", "individual"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT action, detail, timestamp FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 50",
              (current_user["id"],))
    rows = c.fetchall()
    conn.close()
    return [{"action": r[0], "detail": r[1], "timestamp": r[2]} for r in rows]


@auth_router.get("/auth/company/members")
def get_company_members(current_user: dict = Depends(get_current_user)):
    """List members of the current user's company."""
    if current_user["role"] not in ("enterprise_admin", "enterprise_user"):
        raise HTTPException(status_code=403, detail="Not part of a company")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT company_id FROM users WHERE id = ?", (current_user["id"],))
    row = c.fetchone()
    if not row or not row[0]:
        conn.close()
        raise HTTPException(status_code=404, detail="No company found")

    c.execute("SELECT id, name, email, role, last_login FROM users WHERE company_id = ?", (row[0],))
    members = c.fetchall()
    conn.close()
    return [
        {"id": m[0], "name": m[1], "email": m[2], "role": m[3], "last_login": m[4]}
        for m in members
    ]
