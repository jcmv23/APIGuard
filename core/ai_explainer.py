"""
APIGuard v4.0 — AI Vulnerability Explainer
============================================
Uses Groq API (free tier) or falls back to local heuristic analysis.
Provides human-readable explanations, fix suggestions, and code snippets.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional


# ── Local Knowledge Base (no API needed) ──
VULN_KB = {
    "BOLA": {
        "explain": "Broken Object Level Authorization (BOLA) allows an attacker to access resources belonging to other users by manipulating object IDs in API requests. This is the #1 API vulnerability according to OWASP.",
        "impact": "An attacker can read, modify, or delete data belonging to any user by simply changing the ID parameter in the request.",
        "fix": "Implement object-level authorization checks in every endpoint that accesses resources by ID.",
        "code": """# Python/FastAPI fix example
@app.get("/api/items/{item_id}")
def get_item(item_id: int, current_user = Depends(get_current_user)):
    item = db.get_item(item_id)
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return item""",
    },
    "BFLA": {
        "explain": "Broken Function Level Authorization (BFLA) occurs when an API doesn't properly verify that the authenticated user has the required role/permission to perform the requested action.",
        "impact": "A regular user can access admin endpoints or perform privileged operations like deleting users, changing configurations, or accessing sensitive data.",
        "fix": "Implement role-based access control (RBAC) with explicit permission checks on every sensitive endpoint.",
        "code": """# Python/FastAPI RBAC example
from functools import wraps

def require_role(required_role: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, current_user=Depends(get_current_user), **kwargs):
            if current_user.role != required_role:
                raise HTTPException(403, "Insufficient permissions")
            return func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.delete("/api/admin/users/{user_id}")
@require_role("admin")
def delete_user(user_id: int, current_user = Depends(get_current_user)):
    ...""",
    },
    "MISSING_AUTH": {
        "explain": "This endpoint accepts requests without any authentication token. Anyone on the internet can access it.",
        "impact": "Sensitive data or functionality is exposed to unauthenticated users, potentially leaking PII, financial data, or allowing unauthorized actions.",
        "fix": "Add authentication middleware to all endpoints that handle sensitive data or actions.",
        "code": """# Add JWT validation middleware
@app.get("/api/sensitive-data")
def get_sensitive_data(token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(401, "Invalid or expired token")
    return {"data": "protected_content"}""",
    },
    "JWT_NO_EXPIRY": {
        "explain": "The JWT token does not have an expiration claim (exp). This means once issued, the token is valid forever.",
        "impact": "If a token is leaked or stolen, the attacker has permanent access to the user's account with no way to invalidate it.",
        "fix": "Always set an expiration time on JWT tokens. Use short-lived access tokens (15-60 min) with refresh tokens.",
        "code": """import jwt, datetime

token = jwt.encode({
    "sub": user_id,
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    "iat": datetime.datetime.utcnow()
}, SECRET_KEY, algorithm="HS256")""",
    },
    "JWT_ALG_NONE": {
        "explain": "The API accepts JWT tokens with the 'none' algorithm, which means no signature verification is performed.",
        "impact": "An attacker can forge valid JWT tokens with any payload, gaining access to any account or role.",
        "fix": "Explicitly specify allowed algorithms when verifying JWTs. Never accept 'none'.",
        "code": """# SECURE: Explicitly specify algorithm
payload = jwt.decode(
    token, 
    SECRET_KEY, 
    algorithms=["HS256"]  # Only accept HS256
)
# NEVER do: algorithms=["none"] or algorithms=jwt.get_unverified_header(token)["alg"]""",
    },
    "NO_RATE_LIMIT": {
        "explain": "This endpoint doesn't enforce rate limiting. An attacker can send unlimited requests, enabling brute-force attacks, credential stuffing, or denial of service.",
        "impact": "Resource exhaustion (DoS), successful brute-force of credentials, and API abuse leading to infrastructure costs.",
        "fix": "Implement rate limiting per IP and per user. Use sliding window or token bucket algorithms.",
        "code": """# Using SlowAPI with FastAPI
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/login")
@limiter.limit("5/minute")  # Max 5 login attempts per minute
def login(request: Request):
    ...""",
    },
    "SQL_INJECTION": {
        "explain": "SQL Injection allows attackers to insert malicious SQL code through input parameters, potentially reading, modifying, or deleting the entire database.",
        "impact": "Complete database compromise: data theft, data manipulation, authentication bypass, and potentially remote code execution.",
        "fix": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
        "code": """# VULNERABLE (never do this):
query = f"SELECT * FROM users WHERE id = {user_input}"

# SECURE (parameterized query):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))

# SECURE (SQLAlchemy ORM):
user = session.query(User).filter(User.id == user_input).first()""",
    },
    "CORS_WILDCARD": {
        "explain": "The API returns 'Access-Control-Allow-Origin: *' which allows any website to make requests to it from a browser.",
        "impact": "Malicious websites can make authenticated requests to your API using the victim's cookies/tokens, potentially stealing data.",
        "fix": "Restrict CORS to only your trusted origins. Never use wildcard (*) with credentials.",
        "code": """# FastAPI CORS configuration
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.yourdomain.com"],  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization"],
)""",
    },
    "NO_SSL": {
        "explain": "The API is served over HTTP without TLS/SSL encryption. All data, including credentials and tokens, is transmitted in plaintext.",
        "impact": "Man-in-the-middle attackers can intercept credentials, tokens, and sensitive data.",
        "fix": "Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
        "code": """# Nginx configuration for HTTPS redirect
server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
}""",
    },
    "PII_LEAKAGE": {
        "explain": "The API response contains Personally Identifiable Information (PII) such as emails, phone numbers, SSNs, or credit card numbers that should be masked or removed.",
        "impact": "Exposure of user personal data violates privacy regulations (GDPR, CCPA) and can lead to identity theft.",
        "fix": "Implement response filtering to mask or remove sensitive fields. Only return data the client actually needs.",
        "code": """# Response filtering with Pydantic
from pydantic import BaseModel

class UserPublic(BaseModel):  # Only expose safe fields
    id: int
    username: str
    avatar_url: str | None
    # Do NOT include: email, phone, ssn, address

@app.get("/api/users/{id}", response_model=UserPublic)
def get_user(id: int):
    return db.get_user(id)  # Pydantic filters the response""",
    },
    "XSS": {
        "explain": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into API responses that execute in victim browsers.",
        "impact": "Session hijacking, credential theft, keylogging, and defacement of web applications consuming this API.",
        "fix": "Sanitize/encode all user input before including in responses. Set Content-Security-Policy headers.",
        "code": """# Use DOMPurify on the client side
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);

# Set CSP header on the server
response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
""",
    },
    "SSTI": {
        "explain": "Server-Side Template Injection (SSTI) allows attackers to inject template directives that execute on the server, often leading to Remote Code Execution.",
        "impact": "Full server compromise. Attackers can read files, execute commands, and pivot to internal networks.",
        "fix": "Never pass user input to template engines. Use logic-less templates or sandboxed rendering.",
        "code": """# VULNERABLE (Jinja2):
template = Template(user_input)  # NEVER do this

# SECURE:
template = env.get_template("page.html")
result = template.render(name=user_input)  # Input is data, not template code""",
    },
    "PATH_TRAVERSAL": {
        "explain": "Path Traversal allows attackers to read arbitrary files on the server by manipulating file path parameters with ../ sequences.",
        "impact": "Exposure of sensitive files: /etc/passwd, source code, configuration files with database passwords, .env files.",
        "fix": "Validate file paths against a whitelist. Use os.path.realpath() to resolve and check the final path stays within allowed directories.",
        "code": """import os

SAFE_DIR = "/app/uploads"

def safe_read(filename):
    # Resolve the real path
    real_path = os.path.realpath(os.path.join(SAFE_DIR, filename))
    # Verify it's inside allowed directory
    if not real_path.startswith(SAFE_DIR):
        raise ValueError("Path traversal detected!")
    return open(real_path).read()""",
    },
    "JWT_WEAK_SECRET": {
        "explain": "The JWT token is signed with a weak/common secret that was cracked via dictionary attack. Any attacker can forge valid tokens.",
        "impact": "Complete authentication bypass. Attackers can create tokens for any user, including admin accounts.",
        "fix": "Use a cryptographically random secret of at least 256 bits. Rotate the secret immediately.",
        "code": """import secrets

# Generate a strong random secret (256 bits)
JWT_SECRET = secrets.token_hex(32)  # 64-character hex string

# Or use openssl:
# openssl rand -hex 32""",
    },
    "WAF_BYPASS": {
        "explain": "The Web Application Firewall is not blocking all attack payloads. Attackers can bypass the WAF using encoding tricks or payload variants.",
        "impact": "False sense of security. The WAF provides incomplete protection, allowing real attacks to reach the application.",
        "fix": "Update WAF rules to cover OWASP Top 10 attack patterns. Enable paranoia level 2+ in ModSecurity.",
        "code": """# ModSecurity recommended config
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "text/xml" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
# Enable OWASP Core Rule Set (CRS)
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf""",
    },
    "EXPOSED_SECRET": {
        "explain": "API responses contain exposed credentials such as API keys, database passwords, cloud provider keys, or private keys.",
        "impact": "Direct compromise of connected services. AWS keys = full cloud account takeover. Database passwords = data breach.",
        "fix": "Implement response filtering. Never return secrets in API responses. Use environment variables and secret managers.",
        "code": """# Use environment variables, never hardcode
import os
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")

# Filter sensitive fields from responses
SENSITIVE_FIELDS = {"password", "secret", "api_key", "token"}
def filter_response(data: dict) -> dict:
    return {k: v for k, v in data.items() if k not in SENSITIVE_FIELDS}""",
    },
    "UNDOCUMENTED_ENDPOINT": {
        "explain": "An endpoint exists on the server that is not documented in the OpenAPI specification. This could be a debug, admin, or internal endpoint.",
        "impact": "Undocumented endpoints often lack proper security controls and may expose sensitive functionality or data.",
        "fix": "Document all endpoints in the OpenAPI spec. Disable or restrict access to debug/admin endpoints in production.",
        "code": """# Disable debug endpoints in production
import os

if os.getenv("ENVIRONMENT") == "production":
    # Don't register debug/admin routes
    pass
else:
    app.include_router(debug_router)
    app.include_router(admin_router)""",
    },
}


def explain_finding(finding: dict) -> dict:
    """Generate an AI-powered explanation for a security finding."""
    vuln_type = finding.get("vulnerability_type", finding.get("finding_type", "UNKNOWN"))
    severity = finding.get("severity", "MEDIUM")
    endpoint = finding.get("endpoint", finding.get("path", "N/A"))
    description = finding.get("description", "")
    
    # Look up in knowledge base
    kb_entry = VULN_KB.get(vuln_type, None)
    
    if kb_entry:
        return {
            "finding_type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "explanation": kb_entry["explain"],
            "impact": kb_entry["impact"],
            "fix_suggestion": kb_entry["fix"],
            "code_example": kb_entry["code"],
            "confidence": "high",
            "source": "knowledge_base",
        }
    
    # Fallback: generate generic explanation
    return {
        "finding_type": vuln_type,
        "severity": severity,
        "endpoint": endpoint,
        "explanation": f"A {severity.lower()}-severity {vuln_type} vulnerability was detected at {endpoint}. {description}",
        "impact": f"This {severity.lower()}-level issue could potentially be exploited by attackers to compromise the security of the API.",
        "fix_suggestion": "Review the endpoint implementation and apply security best practices relevant to this vulnerability type. Consult OWASP guidelines.",
        "code_example": "# Refer to OWASP API Security Top 10 for specific remediation guidance.",
        "confidence": "medium",
        "source": "heuristic",
    }


def explain_scan_findings(report: dict) -> list[dict]:
    """Process all findings from a scan report and generate explanations."""
    results = []
    for mod_name, mod_data in report.get("modules", {}).items():
        if isinstance(mod_data, dict) and mod_data.get("findings"):
            for finding in mod_data["findings"]:
                explanation = explain_finding(finding)
                explanation["module"] = mod_name
                results.append(explanation)
    return results
