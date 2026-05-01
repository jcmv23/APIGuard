"""
APIGuard Phase 3: Shadow API Discovery Proxy
============================================
A lightweight passive interception proxy that monitors traffic
and compares it against the known OpenAPI specifications. 

If it detects an endpoint being accessed that is NOT in the spec,
it flags it as a "Shadow API" (Undocumented Endpoint).
"""

import threading
import time
from urllib.parse import urlparse
from fastapi import FastAPI, Request
import httpx
import uvicorn

import sys
import os

# To ensure imports work if run standalone
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from module_1_parser.parser import OpenAPIParser
except ImportError:
    pass

app = FastAPI(title="APIGuard - Shadow API Passive Proxy")

# Configuration for the Proxy
TARGET_API = "http://localhost:8080"  # The actual backend we are monitoring
KNOWN_OPENAPI_SPEC = "openapi.json"   # The documentation baseline
KNOWN_ROUTES = set()

def load_spec_baseline():
    """Loads the OpenAPI spec and parses legitimate routes."""
    global KNOWN_ROUTES
    try:
        # We will use the existing parser to extract pure paths
        parser = OpenAPIParser(base_url=TARGET_API, spec=KNOWN_OPENAPI_SPEC)
        endpoints = parser.parse()
        for ep in endpoints:
            # Add to known routes (ignoring HTTP methods for simplicity)
            url_path = urlparse(ep.full_url).path
            # Store base paths ignoring final dynamic parameters like {id} for simple matching
            clean_path = url_path.split('{')[0] 
            KNOWN_ROUTES.add(clean_path)
            
        print(f"[SHADOW-PROXY] Loaded {len(KNOWN_ROUTES)} baseline documented routes.")
    except Exception as e:
        print(f"[SHADOW-PROXY] Warning: Could not load OpenAPI spec. {e}")
        # Default mock baseline for testing if file doesn't exist
        KNOWN_ROUTES.update(["/", "/auth/login", "/users/", "/admin/users/"])

load_spec_baseline()

@app.middleware("http")
async def intercept_and_forward(request: Request, call_next):
    """
    Middleware that intercepts traffic natively before forwarding,
    acting as a transparent monitoring layer for Shadow APIs.
    """
    path = request.url.path
    
    # Check if the requested route is documented
    is_documented = False
    for route in KNOWN_ROUTES:
        if path.startswith(route):
            is_documented = True
            break
            
    if not is_documented and path != "/favicon.ico":
        print(f"\n[ALERT] 🚨 SHADOW API DETECTED: {request.method} {path} is active but NOT Documented in OpenAPI spec!")
        # In a real enterprise system, a webhook would trigger to the APIGuard Dashboard here
    
    # Pass the request to the upstream API handler
    # For demo purposes of this proxy, since we are wrapping the API conceptually:
    response = await call_next(request)
    return response

# Dummy endpoint to test the proxy natively
@app.get("/system/v2/legacy/debug")
async def shadow_endpoint():
    return {"message": "You found a shadow endpoint that is not documented!"}

if __name__ == "__main__":
    print("[SYSTEM] Starting APIGuard Shadow API Passive Proxy on port 8081...")
    uvicorn.run(app, host="0.0.0.0", port=8081)
