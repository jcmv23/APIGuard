"""
APIGuard Enterprise — OAuth/SSO Integration
==============================================
Supports Google OAuth2 and GitHub OAuth2 for enterprise SSO.

Setup:
  Set environment variables:
    GOOGLE_CLIENT_ID=your-google-client-id
    GOOGLE_CLIENT_SECRET=your-google-client-secret
    GITHUB_CLIENT_ID=your-github-client-id
    GITHUB_CLIENT_SECRET=your-github-client-secret

Flow:
  1. Frontend redirects user to /api/auth/oauth/{provider}
  2. User authenticates with Google/GitHub
  3. Callback at /api/auth/oauth/{provider}/callback
  4. Server creates/finds user, returns JWT tokens
"""

import os
import uuid
import time
import secrets
import sqlite3
from urllib.parse import urlencode

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from core.config import settings
from core.security import create_access_token, create_refresh_token, hash_password
from core.logging_config import get_logger

logger = get_logger("oauth")
oauth_router = APIRouter()

DB_FILE = settings.AUTH_DB

# ─────────────────────────────────────────────
# OAuth Provider Configs
# ─────────────────────────────────────────────

OAUTH_PROVIDERS = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        "scopes": "openid email profile",
    },
    "github": {
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "client_id": os.environ.get("GITHUB_CLIENT_ID", ""),
        "client_secret": os.environ.get("GITHUB_CLIENT_SECRET", ""),
        "scopes": "read:user user:email",
    },
}

# State tokens for CSRF protection (in-memory, short-lived)
_oauth_states: dict[str, dict] = {}


# ─────────────────────────────────────────────
# OAuth Routes
# ─────────────────────────────────────────────

@oauth_router.get("/auth/oauth/providers")
def list_oauth_providers():
    """List available OAuth providers with their configured status."""
    providers = []
    for name, config in OAUTH_PROVIDERS.items():
        providers.append({
            "name": name,
            "configured": bool(config["client_id"] and config["client_secret"]),
            "auth_url": f"/api/auth/oauth/{name}",
        })
    return {"providers": providers}


@oauth_router.get("/auth/oauth/{provider}")
def oauth_redirect(provider: str, request: Request):
    """Redirect user to OAuth provider's login page."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    config = OAUTH_PROVIDERS[provider]
    if not config["client_id"] or not config["client_secret"]:
        raise HTTPException(status_code=503, detail=f"{provider} OAuth not configured. Set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET.")

    # Generate CSRF state token
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = {
        "provider": provider,
        "created_at": time.time(),
    }

    # Cleanup old states (> 10 min)
    old_states = [k for k, v in _oauth_states.items() if time.time() - v["created_at"] > 600]
    for k in old_states:
        del _oauth_states[k]

    # Build redirect URL
    callback_url = str(request.base_url).rstrip("/") + f"/api/auth/oauth/{provider}/callback"
    params = {
        "client_id": config["client_id"],
        "redirect_uri": callback_url,
        "state": state,
        "response_type": "code",
    }

    if provider == "google":
        params["scope"] = config["scopes"]
        params["access_type"] = "offline"
        params["prompt"] = "consent"
    elif provider == "github":
        params["scope"] = config["scopes"]

    auth_url = f"{config['auth_url']}?{urlencode(params)}"
    return RedirectResponse(url=auth_url)


@oauth_router.get("/auth/oauth/{provider}/callback")
def oauth_callback(provider: str, code: str, state: str, request: Request):
    """Handle OAuth callback, create/find user, redirect to frontend with token."""
    # Validate state (CSRF protection)
    if state not in _oauth_states or _oauth_states[state]["provider"] != provider:
        raise HTTPException(status_code=400, detail="Invalid OAuth state. Possible CSRF attack.")
    del _oauth_states[state]

    config = OAUTH_PROVIDERS[provider]
    callback_url = str(request.base_url).rstrip("/") + f"/api/auth/oauth/{provider}/callback"

    # Exchange code for access token
    token_data = _exchange_code(provider, config, code, callback_url)
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Failed to get access token from provider")

    # Get user info from provider
    user_info = _get_user_info(provider, config, access_token)

    email = user_info.get("email")
    name = user_info.get("name", email.split("@")[0] if email else "User")

    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by OAuth provider")

    # Find or create user in our database
    user_data = _find_or_create_oauth_user(email, name, provider)

    # Generate our JWT tokens
    jwt_access = create_access_token({
        "sub": user_data["id"],
        "email": email,
        "role": user_data["role"],
        "name": name,
    })
    jwt_refresh = create_refresh_token({"sub": user_data["id"]})

    logger.info("oauth_login", provider=provider, email=email, user_id=user_data["id"])

    # Redirect to frontend with token
    frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:3000")
    redirect_url = f"{frontend_url}?oauth_token={jwt_access}&refresh_token={jwt_refresh}&provider={provider}"
    return RedirectResponse(url=redirect_url)


# ─────────────────────────────────────────────
# OAuth Helpers
# ─────────────────────────────────────────────

def _exchange_code(provider: str, config: dict, code: str, redirect_uri: str) -> dict:
    """Exchange authorization code for access token."""
    data = {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": redirect_uri,
    }

    if provider == "google":
        data["grant_type"] = "authorization_code"
    elif provider == "github":
        pass  # GitHub doesn't need grant_type

    headers = {"Accept": "application/json"}
    r = requests.post(config["token_url"], data=data, headers=headers, timeout=10)

    if r.status_code != 200:
        logger.error("oauth_token_exchange_failed", provider=provider, status=r.status_code)
        raise HTTPException(status_code=400, detail="Failed to exchange code for token")

    return r.json()


def _get_user_info(provider: str, config: dict, access_token: str) -> dict:
    """Fetch user info from OAuth provider."""
    headers = {"Authorization": f"Bearer {access_token}"}

    r = requests.get(config["userinfo_url"], headers=headers, timeout=10)
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch user info from provider")

    user_info = r.json()

    # GitHub special case: email might be private
    if provider == "github" and not user_info.get("email"):
        emails_r = requests.get(config["emails_url"], headers=headers, timeout=10)
        if emails_r.status_code == 200:
            emails = emails_r.json()
            primary = next((e for e in emails if e.get("primary")), None)
            if primary:
                user_info["email"] = primary["email"]

    return user_info


def _find_or_create_oauth_user(email: str, name: str, provider: str) -> dict:
    """Find existing user by email or create a new OAuth user."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT id, role FROM users WHERE email = ?", (email,))
    row = c.fetchone()

    if row:
        # Existing user — update last login
        user_id, role = row
        c.execute("UPDATE users SET last_login = ? WHERE id = ?",
                  (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), user_id))
        conn.commit()
        conn.close()
        return {"id": user_id, "role": role}

    # New user — create account
    user_id = str(uuid.uuid4())
    # Generate a random password hash (user will use OAuth, not password)
    random_pass = hash_password(secrets.token_urlsafe(32))
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    c.execute(
        "INSERT INTO users (id, email, password_hash, name, role, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, email, random_pass, name, "individual", now, now)
    )
    conn.commit()
    conn.close()

    logger.info("oauth_user_created", email=email, provider=provider, user_id=user_id)
    return {"id": user_id, "role": "individual"}
