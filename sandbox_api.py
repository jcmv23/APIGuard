from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import uvicorn
import httpx

app = FastAPI(title="Vulnerable Sandbox API for APIGuard")

# --------- MOCK DATABASE ---------
db_users = {
    "1": {"id": "1", "name": "Admin User", "role": "admin", "secret": "super_secret_admin_data"},
    "2": {"id": "2", "name": "Alice", "role": "user", "secret": "alice_private_data"},
    "3": {"id": "3", "name": "Bob", "role": "user", "secret": "bob_private_data"}
}

# --------- MODELS ---------
class UserUpdate(BaseModel):
    name: str

class LoginRequest(BaseModel):
    username: str
    password: str

# --------- ENDPOINTS ---------

@app.get("/")
def read_root():
    return {"message": "Sandbox API is running. Start scanning!"}

@app.post("/auth/login")
def login(creds: dict):
    # Vulnerable to NoSQL injection: {"username": {"$ne": 1}, "password": {"$ne": 1}}
    username = creds.get("username", "")
    if isinstance(username, dict) and "$ne" in username:
        return {"token": "Bearer admin_token_no_sql_bypass_success"}
    
    if username == "admin":
        return {"token": "Bearer admin_token"}
    return {"token": f"Bearer token_{username}"}

@app.get("/users/{user_id}")
def get_user(user_id: str, authorization: Optional[str] = Header(None)):
    """ BOLA Vulnerability """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    
    if user_id not in db_users:
        raise HTTPException(status_code=404, detail="User not found")
    return db_users[user_id]

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: str, authorization: Optional[str] = Header(None)):
    """ BFLA Vulnerability """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
        
    if user_id in db_users:
        del db_users[user_id]
        return {"message": f"User {user_id} deleted."}
    return {"message": "User not found"}

@app.post("/system/query")
def execute_query(query: str, authorization: Optional[str] = Header(None)):
    """ SQL Injection (Mock) """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    if "SELECT" in query.upper() or "DROP" in query.upper():
        return {"result": f"sql syntax error near {query}"} 
    return {"result": f"Executed: {query}"}

@app.get("/system/exec")
def OS_command_exec(cmd: str, authorization: Optional[str] = Header(None)):
    """ Command Injection Vulnerability """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    
    # Simulate an OS command injection returning standard expected payloads
    if "id" in cmd or "/etc/passwd" in cmd or "whoami" in cmd:
        return {"output": "uid=0(root) gid=0(root) groups=0(root)"}
    
    return {"output": f"Executed local binary with {cmd}"}

@app.get("/proxy/fetch")
def ssrf_fetch(url: str, authorization: Optional[str] = Header(None)):
    """ SSRF Vulnerability via URL parameter """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
        
    if "169.254.169.254" in url or "127.0.0.1" in url:
        return {"data": "ami-id: i-0abc12345 security-credentials: [...]"}
        
    return {"data": f"Fetched external data from {url}"}

@app.get("/data/limited")
def expensive_data():
    """ Rate Limiting Vulnerability """
    return {"data": "This is expensive data to compute."}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
