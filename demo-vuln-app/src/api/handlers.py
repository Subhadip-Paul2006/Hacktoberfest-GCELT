# NSAT Demo Vulnerable Application — Python FastAPI Component
# This file intentionally contains security vulnerabilities for NSAT demo purposes.
# DO NOT use in production.

from fastapi import FastAPI, Request, UploadFile, File, WebSocket
import sqlite3
import subprocess
import os

app = FastAPI()
DEBUG = True

# Vulnerability: Hardcoded database connection
DB_PATH = "users.db"


def _init_demo_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
        cur.execute("INSERT OR IGNORE INTO users (id, name, role) VALUES (1, 'admin', 'administrator')")
        cur.execute("INSERT OR IGNORE INTO users (id, name, role) VALUES (2, 'alice', 'user')")
        conn.commit()
        conn.close()
    except Exception:
        pass


_init_demo_db()


# NSAT-TARGET: SQL injection via f-string interpolation into cursor.execute
# Function name 'handler2' is obfuscated on purpose — NSAT must detect by structure
@app.get("/search")
async def handler2(x1: str, request: Request):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # VULN: Direct unsanitized user input into SQL query
    cur.execute(f"SELECT * FROM users WHERE name = '{x1}'")
    rows = cur.fetchall()
    conn.close()
    return {"results": rows}


# NSAT-TARGET: Command injection via subprocess with shell=True and user input
@app.post("/run")
async def run_task(request: Request):
    data = await request.json()
    cmd = data.get("command", "")
    # VULN: shell=True with unsanitized user-supplied command string
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"output": result.stdout}


# NSAT-TARGET: Authentication endpoint with no rate limiting
@app.post("/api/v1/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    # NSAT-OVERSIGHT: Sensitive credential logged directly into application log
    import logging
    logging.info(f"Authentication attempt for user={username} with password={password}")
    # No rate limiting, no lockout policy, no CAPTCHA
    if username == "admin" and password == "secret123":
        return {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fake"}
    return {"error": "invalid credentials"}


# NSAT-TARGET: Authorization flaw / unauthenticated admin dashboard access
@app.get("/api/v1/admin/dashboard")
async def admin_dashboard():
    # VULN: Missing authentication & authorization check on admin endpoint
    return {"status": "ok", "admin_data": "secret_internal_metrics", "privileged_users": 5}


# NSAT-TARGET: Business logic flaw — Premature state transition without payment verification
@app.post("/api/v1/order/confirm")
async def order_confirm(request: Request):
    data = await request.json()
    # VULN: Directly marks order as confirmed without validating payment completion
    order_id = data.get("order_id", "ORD-DEFAULT")
    return {"status": "completed", "order_id": order_id, "message": "Order confirmed successfully"}


# NSAT-TARGET: Payment workflow flaw — Client-trusted price and payment status
@app.post("/api/v1/checkout")
async def checkout(request: Request):
    data = await request.json()
    # VULN: Trusts client-supplied price and client-supplied payment_status
    amount = data.get("price") or data.get("amount") or 100.0
    status = data.get("payment_status") or "PENDING"
    return {"status": "approved", "charged_amount": amount, "payment_status": status}


# NSAT-TARGET: File upload without extension whitelist or type validation
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # VULN: Arbitrary file upload without extension restriction
    filename = file.filename
    content = await file.read()
    return {"filename": filename, "size": len(content), "status": "uploaded"}


# NSAT-TARGET: WebSocket without Origin verification (CSWSH)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # VULN: Accepts connections from any origin without header validation
    await websocket.accept()
    await websocket.send_text("Connected to vulnerable stream")
    await websocket.close()


# NSAT-OVERSIGHT: URL Information Leakage (OTP transmitted via URL query parameter)
@app.get("/verify-otp")
async def verify_otp(otp: str, user_id: int):
    return {"status": "verified", "otp": otp}


# NSAT-OVERSIGHT: Hidden / Developer Debug Endpoint
@app.get("/debug/dump")
async def debug_dump():
    return {"debug_mode": DEBUG, "internal_state": "active", "db_path": DB_PATH}


# NSAT-OVERSIGHT: Detailed Stack Trace Leakage in API response
@app.get("/api/v1/crash")
async def crash_handler():
    import traceback
    try:
        raise ValueError("Simulated unexpected database connection failure")
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}


# NSAT-OVERSIGHT: Insecure Cookie Flags (Missing HttpOnly, Secure, SameSite)
@app.post("/api/v1/session")
async def create_session(request: Request):
    from starlette.responses import JSONResponse
    resp = JSONResponse({"status": "session_created"})
    resp.set_cookie(key="auth_session", value="sess_998877", httponly=False, secure=False)
    return resp


# NSAT-OVERSIGHT: Open Redirect via untrusted query parameter
@app.get("/redirect")
async def open_redirect(request: Request):
    from starlette.responses import RedirectResponse
    target_url = request.query_params.get("next", "/")
    return RedirectResponse(url=target_url)


# NSAT-OVERSIGHT: Missing Timeout on Outbound HTTP Request
@app.get("/external-sync")
async def external_sync():
    import requests
    # VULN: Missing timeout parameter allows external server to hang worker indefinitely
    resp = requests.get("https://httpbin.org/get")
    return {"status": "synced"}


# NSAT-OVERSIGHT: Trusted Header Authorization Bypass
@app.get("/api/v1/user/profile")
async def user_profile(request: Request):
    # VULN: Trusts spoofable X-Role header for administrative decisions
    if request.headers.get("X-Role") == "admin":
        return {"role": "admin", "permissions": ["ALL"]}
    return {"role": "guest", "permissions": ["READ"]}


# NSAT-OVERSIGHT: TOCTOU Check-Then-Act Race Condition
user_balance = 500
@app.post("/api/v1/account/withdraw")
async def withdraw(request: Request):
    global user_balance
    data = await request.json()
    amount = data.get("amount", 0)
    # VULN: Check then act without transaction or concurrency lock
    if user_balance >= amount:
        user_balance -= amount
        return {"status": "success", "new_balance": user_balance}
    return {"status": "insufficient_funds"}


# NSAT-TARGET: App running on 0.0.0.0 (all interfaces)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

