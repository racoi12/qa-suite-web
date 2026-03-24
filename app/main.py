"""QA Suite Web — Site audit SaaS."""

import asyncio
import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from database import init_db, get_db
from auth import (
    authenticate, create_jwt, verify_jwt, create_user,
    list_users, delete_user, bootstrap_admin,
)
from scanner import run_scan

app = FastAPI(title="QA Suite Web", version="1.0.0")

# Background tasks tracking
_running_tasks: dict[int, asyncio.Task] = {}


@app.on_event("startup")
def startup():
    init_db()
    bootstrap_admin()


# ──────────────── Auth helpers ────────────────


def get_user(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    data = verify_jwt(auth[7:])
    if not data:
        raise HTTPException(401, "Invalid or expired token")
    return data


# ──────────────── Auth routes ────────────────


class LoginReq(BaseModel):
    username: str
    password: str


class CreateUserReq(BaseModel):
    username: str
    password: str
    role: str = "user"


@app.post("/api/login")
def login(req: LoginReq):
    user = authenticate(req.username, req.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    token = create_jwt(user["id"], user["username"], user["role"])
    return {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}


@app.get("/api/users")
def get_users(request: Request):
    u = get_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return list_users()


@app.post("/api/users")
def add_user(req: CreateUserReq, request: Request):
    u = get_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    try:
        uid = create_user(req.username, req.password, req.role)
        return {"id": uid, "username": req.username, "role": req.role}
    except Exception:
        raise HTTPException(400, "Username already exists")


@app.delete("/api/users/{user_id}")
def remove_user(user_id: int, request: Request):
    u = get_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    if not delete_user(user_id):
        raise HTTPException(400, "Cannot delete (admin or not found)")
    return {"ok": True}


# ──────────────── Scan routes ────────────────


class ScanReq(BaseModel):
    url: str
    config: dict = {}


DEFAULT_CONFIG = {
    "smoke_enabled": True,
    "security_enabled": True,
    "seo_enabled": True,
    "accessibility_enabled": True,
    "performance_enabled": True,
    "responsive_enabled": True,
    "links_enabled": True,
    "images_enabled": True,
    "faces_enabled": True,
    "face_api_url": "https://faces.uat.argitic.com",
    "face_api_token": "",
    "max_pages": 15,
}


@app.post("/api/scans")
async def create_scan(req: ScanReq, request: Request):
    u = get_user(request)

    # Validate URL
    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Merge config
    config = {**DEFAULT_CONFIG, **req.config}

    with get_db() as db:
        cur = db.execute(
            "INSERT INTO scans (user_id, url, config) VALUES (?, ?, ?)",
            (u["sub"], url, json.dumps(config)),
        )
        scan_id = cur.lastrowid

    # Launch background scan
    task = asyncio.create_task(run_scan(scan_id, url, config))
    _running_tasks[scan_id] = task
    task.add_done_callback(lambda t: _running_tasks.pop(scan_id, None))

    return {"id": scan_id, "url": url, "status": "queued"}


@app.get("/api/scans")
def list_scans(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, url, status, progress, score, summary, created_at, finished_at "
            "FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
            (u["sub"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        scan = db.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, u["sub"])).fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        results = db.execute(
            "SELECT category, test_name, status, severity, message, details FROM results WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
    return {**dict(scan), "results": [dict(r) for r in results]}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM results WHERE scan_id = ? AND scan_id IN (SELECT id FROM scans WHERE user_id = ?)",
                   (scan_id, u["sub"]))
        db.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, u["sub"]))
    # Cancel if running
    task = _running_tasks.pop(scan_id, None)
    if task:
        task.cancel()
    return {"ok": True}


# ──────────────── Config route ────────────────


@app.get("/api/config/default")
def default_config(request: Request):
    get_user(request)
    return DEFAULT_CONFIG


# ──────────────── Health ────────────────


@app.get("/health")
def health():
    return {"status": "ok"}


# ──────────────── Web UI ────────────────


@app.get("/", response_class=HTMLResponse)
async def web_ui():
    with open("static/index.html") as f:
        return f.read()
