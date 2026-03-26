"""QA Suite Web — Site audit SaaS."""

import asyncio
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel
import croniter

from database import init_db, get_db, get_artifacts
from auth import (
    authenticate, create_jwt, verify_jwt, create_user,
    list_users, delete_user, reset_password, bootstrap_admin, verify_api_key,
)
from scanner import run_scan

app = FastAPI(title="QA Suite Web", version="1.0.0")

# Background tasks tracking
_running_tasks: dict[int, asyncio.Task] = {}

# Serve artifact files (screenshots, videos, console logs)
ARTIFACTS_DIR = Path(os.getenv("ARTIFACTS_DIR", "/data/artifacts"))
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/artifacts", StaticFiles(directory=str(ARTIFACTS_DIR)), name="artifacts")


@app.on_event("startup")
def startup():
    init_db()
    bootstrap_admin()
    asyncio.create_task(scheduler_loop())


# ──────────────── Background Scheduler ────────────────

def _compute_next_run(cron_expr: str, from_time: datetime = None) -> str:
    """Compute next run ISO timestamp from cron expression."""
    try:
        now = from_time or datetime.now(timezone.utc)
        cron = croniter.croniter(cron_expr, now)
        return datetime.fromtimestamp(cron.get_next(), tz=timezone.utc).isoformat()
    except Exception:
        return None


async def _run_schedule(schedule_id: int):
    """Trigger a scheduled scan for all its URLs."""
    with get_db() as db:
        sched = db.execute("SELECT * FROM schedules WHERE id = ? AND enabled = 1", (schedule_id,)).fetchone()
        if not sched:
            return
        sched = dict(sched)

    urls = json.loads(sched.get("urls", "[]"))
    config = json.loads(sched.get("config", "{}"))

    # Merge DEFAULT_CONFIG to ensure all required fields
    cfg = {**DEFAULT_CONFIG, **config}

    scan_ids = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO scans (user_id, name, url, config, batch_id) VALUES (?, ?, ?, ?, ?)",
                (sched["user_id"], f"{sched['name']} — {url}", url, json.dumps(cfg), f"sched_{schedule_id}"),
            )
            scan_id = cur.lastrowid
        task = asyncio.create_task(run_scan(scan_id, url, cfg))
        _running_tasks[scan_id] = task
        task.add_done_callback(lambda t: _running_tasks.pop(scan_id, None))
        scan_ids.append(scan_id)

    # Update last_run
    now = datetime.now(timezone.utc).isoformat()
    next_run = _compute_next_run(sched["cron_expression"]) or now
    with get_db() as db:
        db.execute(
            "UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?",
            (now, next_run, schedule_id),
        )


async def scheduler_loop():
    """Check for due schedules every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        try:
            with get_db() as db:
                rows = db.execute(
                    "SELECT id, cron_expression, next_run FROM schedules WHERE enabled = 1"
                ).fetchall()
            now = datetime.now(timezone.utc)
            for row in rows:
                sched = dict(row)
                if sched["next_run"]:
                    next_run = datetime.fromisoformat(sched["next_run"].replace("Z", "+00:00"))
                    if next_run <= now:
                        asyncio.create_task(_run_schedule(sched["id"]))
        except Exception as e:
            print(f"[scheduler] error: {e}")


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


class ResetPasswordReq(BaseModel):
    password: str


@app.put("/api/users/{user_id}/password")
def user_reset_password(user_id: int, req: ResetPasswordReq, request: Request):
    """Admin resets any user's password, or user resets own."""
    u = get_user(request)
    # Non-admin can only reset own password
    if u["role"] != "admin" and u["sub"] != user_id:
        raise HTTPException(403, "Not authorized")
    if not req.password or len(req.password) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")
    if not reset_password(user_id, req.password):
        raise HTTPException(404, "User not found")
    return {"ok": True}


# ──────────────── Storage Stats ────────────────


@app.get("/api/storage")
def get_storage(request: Request):
    """Admin-only: per-user storage usage (scan count + artifact bytes)."""
    u = get_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    with get_db() as db:
        users = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()
        rows = db.execute("""
            SELECT user_id, COUNT(*) as scan_count,
                   SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) as done_count
            FROM scans GROUP BY user_id
        """).fetchall()
        art_rows = db.execute("""
            SELECT scans.user_id, SUM(artifacts.size) as artifact_bytes
            FROM artifacts JOIN scans ON scans.id = artifacts.scan_id
            GROUP BY scans.user_id
        """).fetchall()

    scan_counts = {r["user_id"]: dict(r) for r in rows}
    art_bytes = {r["user_id"]: r["artifact_bytes"] or 0 for r in art_rows}

    result = []
    for user_row in users:
        uid = user_row["id"]
        scans_info = scan_counts.get(uid, {"scan_count": 0, "done_count": 0})
        result.append({
            "user_id": uid,
            "username": user_row["username"],
            "scan_count": scans_info.get("scan_count", 0),
            "done_count": scans_info.get("done_count", 0),
            "artifact_bytes": art_bytes.get(uid, 0),
        })
    return result


class ScanReq(BaseModel):
    url: str = ""  # optional when urls batch is provided
    urls: list[str] = []  # batch: multiple URLs
    config: dict = {}
    name: str = ""


DEFAULT_CONFIG = {
    # Module toggles
    "smoke_enabled": True,
    "security_enabled": True,
    "seo_enabled": True,
    "accessibility_enabled": True,
    "performance_enabled": True,
    "responsive_enabled": True,
    "links_enabled": True,
    "images_enabled": True,
    "content_enabled": True,
    "faces_enabled": True,
    "exposure_enabled": True,
    # Browser & viewport
    "browsers": ["chromium"],
    "viewports": [
        {"name": "Mobile S", "width": 320, "height": 568},
        {"name": "Mobile L", "width": 430, "height": 932},
        {"name": "Tablet", "width": 768, "height": 1024},
        {"name": "Desktop", "width": 1280, "height": 800},
        {"name": "Wide", "width": 1920, "height": 1080},
    ],
    # Recording options
    "trace_enabled": True,
    "har_enabled": True,
    # Network blocking
    "blockers": {
        "ads": False,
        "analytics": False,
        "social": False,
        "chat": False,
    },
    # Crawl options
    "max_pages": 15,
    # Face API
    "face_api_url": "https://faces.uat.argitic.com",
    "face_api_token": os.getenv("FACE_API_TOKEN", ""),
}


@app.post("/api/scans")
async def create_scan(req: ScanReq, request: Request):
    u = get_user(request)

    # Build URL list — batch or single
    if req.urls:
        all_urls = [u.strip() for u in req.urls if u.strip()]
    else:
        url = req.url.strip()
        if not url:
            raise HTTPException(400, "URL required")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        all_urls = [url]

    # Merge config
    config = {**DEFAULT_CONFIG, **req.config}

    batch_id = f"batch_{secrets.token_urlsafe(8)}"
    scan_ids = []

    for i, url in enumerate(all_urls):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        name = req.name or f"Scan of {url}"
        if len(all_urls) > 1:
            name = f"{req.name} [{i+1}/{len(all_urls)}] — {url}" if req.name else f"{url} [{i+1}/{len(all_urls)}]"

        with get_db() as db:
            cur = db.execute(
                "INSERT INTO scans (user_id, name, url, config, batch_id) VALUES (?, ?, ?, ?, ?)",
                (u["sub"], name, url, json.dumps(config), batch_id),
            )
            scan_id = cur.lastrowid

        task = asyncio.create_task(run_scan(scan_id, url, config))
        _running_tasks[scan_id] = task
        task.add_done_callback(lambda t: _running_tasks.pop(scan_id, None))
        scan_ids.append(scan_id)

    return {"id": scan_ids[0], "batch_id": batch_id, "urls": all_urls, "status": "queued"}


@app.get("/api/scans")
def list_scans(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, url, batch_id, status, progress, score, summary, video_path, created_at, finished_at "
            "FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
            (u["sub"],),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("video_path"):
            filename = Path(d["video_path"]).name
            d["video_url"] = f"/artifacts/{d['id']}/{filename}"
        else:
            d["video_url"] = ""
        result.append(d)
    return result


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
    scan_dict = dict(scan)
    # Include video — use actual filename from stored path
    if scan_dict.get("video_path"):
        filename = Path(scan_dict["video_path"]).name
        scan_dict["video_url"] = f"/artifacts/{scan_id}/{filename}"
    else:
        scan_dict["video_url"] = ""
    scan_dict["artifacts"] = get_artifacts(scan_id)
    scan_dict["results"] = [dict(r) for r in results]
    return scan_dict


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM artifacts WHERE scan_id = ? AND scan_id IN (SELECT id FROM scans WHERE user_id = ?)",
                   (scan_id, u["sub"]))
        db.execute("DELETE FROM results WHERE scan_id = ? AND scan_id IN (SELECT id FROM scans WHERE user_id = ?)",
                   (scan_id, u["sub"]))
        db.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, u["sub"]))
    # Cancel if running
    task = _running_tasks.pop(scan_id, None)
    if task:
        task.cancel()
    # Clean up artifact files
    artifact_dir = ARTIFACTS_DIR / str(scan_id)
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    return {"ok": True}


@app.delete("/api/scans/batch/{batch_id}")
def delete_batch(batch_id: str, request: Request):
    """Delete all scans in a batch, plus their artifacts."""
    u = get_user(request)
    with get_db() as db:
        scan_ids = [r["id"] for r in db.execute(
            "SELECT id FROM scans WHERE batch_id = ? AND user_id = ?", (batch_id, u["sub"])
        ).fetchall()]
        for sid in scan_ids:
            db.execute("DELETE FROM artifacts WHERE scan_id = ?", (sid,))
            db.execute("DELETE FROM results WHERE scan_id = ?", (sid,))
            # Cancel if running
            task = _running_tasks.pop(sid, None)
            if task:
                task.cancel()
            # Clean up artifact files
            artifact_dir = ARTIFACTS_DIR / str(sid)
            if artifact_dir.exists():
                shutil.rmtree(artifact_dir)
        db.execute("DELETE FROM scans WHERE batch_id = ? AND user_id = ?", (batch_id, u["sub"]))
    return {"ok": True, "deleted": len(scan_ids)}


# ──────────────── Saved Config Profiles ────────────────


class SaveConfigReq(BaseModel):
    name: str
    config: dict
    is_default: bool = False


@app.get("/api/configs")
def list_configs(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, config, is_default, created_at FROM configs WHERE user_id = ? ORDER BY created_at DESC",
            (u["sub"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/configs")
def save_config(req: SaveConfigReq, request: Request):
    u = get_user(request)
    with get_db() as db:
        if req.is_default:
            db.execute("UPDATE configs SET is_default = 0 WHERE user_id = ?", (u["sub"],))
        cur = db.execute(
            "INSERT INTO configs (user_id, name, config, is_default) VALUES (?, ?, ?, ?)",
            (u["sub"], req.name, json.dumps(req.config), 1 if req.is_default else 0),
        )
        return {"id": cur.lastrowid, "name": req.name}


@app.delete("/api/configs/{config_id}")
def delete_config(config_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM configs WHERE id = ? AND user_id = ?", (config_id, u["sub"]))
    return {"ok": True}


# ──────────────── Scheduled Scans ────────────────


class ScheduleReq(BaseModel):
    name: str
    urls: list[str]
    config: dict
    cron_expression: str


@app.get("/api/schedules")
def list_schedules(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM schedules WHERE user_id = ? ORDER BY created_at DESC",
            (u["sub"],),
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/schedules")
def create_schedule(req: ScheduleReq, request: Request):
    u = get_user(request)
    next_run = _compute_next_run(req.cron_expression) or datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO schedules (user_id, name, urls, config, cron_expression, next_run) VALUES (?, ?, ?, ?, ?, ?)",
            (u["sub"], req.name, json.dumps(req.urls), json.dumps(req.config), req.cron_expression, next_run),
        )
        return {"id": cur.lastrowid, "name": req.name}


@app.put("/api/schedules/{schedule_id}")
def update_schedule(schedule_id: int, request: Request, enabled: bool = None, cron_expression: str = None):
    u = get_user(request)
    with get_db() as db:
        sched = db.execute("SELECT * FROM schedules WHERE id = ? AND user_id = ?", (schedule_id, u["sub"])).fetchone()
        if not sched:
            raise HTTPException(404, "Schedule not found")
        updates = []
        vals = []
        if enabled is not None:
            updates.append("enabled = ?")
            vals.append(1 if enabled else 0)
        if cron_expression:
            updates.append("cron_expression = ?")
            vals.append(cron_expression)
        if updates:
            vals.append(schedule_id)
            db.execute(f"UPDATE schedules SET {', '.join(updates)} WHERE id = ?", vals)
    return {"ok": True}


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM schedules WHERE id = ? AND user_id = ?", (schedule_id, u["sub"]))
    return {"ok": True}


# ──────────────── API Keys ────────────────


class ApiKeyReq(BaseModel):
    name: str


def _hash_key(key: str) -> str:
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()


@app.get("/api/keys")
def list_keys(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, last_used, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
            (u["sub"],),
        ).fetchall()
    return [{"id": r["id"], "name": r["name"], "last_used": r["last_used"], "created_at": r["created_at"]} for r in rows]


@app.post("/api/keys")
def create_key(req: ApiKeyReq, request: Request):
    u = get_user(request)
    import secrets
    raw_key = f"qas_{secrets.token_urlsafe(32)}"
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO api_keys (user_id, name, key_hash) VALUES (?, ?, ?)",
            (u["sub"], req.name, _hash_key(raw_key)),
        )
    return {"id": cur.lastrowid, "name": req.name, "key": raw_key}


@app.delete("/api/keys/{key_id}")
def delete_key(key_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, u["sub"]))
    return {"ok": True}


# ──────────────── Webhooks ────────────────


class WebhookReq(BaseModel):
    name: str
    url: str
    events: list[str]
    secret: str = ""


@app.get("/api/webhooks")
def list_webhooks(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, url, events, active, created_at FROM webhooks WHERE user_id = ? ORDER BY created_at DESC",
            (u["sub"],),
        ).fetchall()
    return [{"id": r["id"], "name": r["name"], "url": r["url"],
             "events": r["events"], "active": r["active"], "created_at": r["created_at"]} for r in rows]


@app.post("/api/webhooks")
def create_webhook(req: WebhookReq, request: Request):
    u = get_user(request)
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO webhooks (user_id, name, url, events, secret) VALUES (?, ?, ?, ?, ?)",
            (u["sub"], req.name, req.url, json.dumps(req.events), req.secret),
        )
        return {"id": cur.lastrowid, "name": req.name}


@app.delete("/api/webhooks/{webhook_id}")
def delete_webhook(webhook_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        db.execute("DELETE FROM webhooks WHERE id = ? AND user_id = ?", (webhook_id, u["sub"]))
    return {"ok": True}


# ──────────────── Teams ────────────────


class TeamReq(BaseModel):
    name: str
    logo_url: str = ""
    primary_color: str = "#7c6cf0"
    secondary_color: str = "#b4a8ff"
    custom_domain: str = ""


class TeamMemberReq(BaseModel):
    user_id: int
    role: str = "member"


@app.get("/api/teams")
def list_teams(request: Request):
    u = get_user(request)
    with get_db() as db:
        rows = db.execute("""
            SELECT t.*, tm.role as member_role
            FROM teams t
            JOIN team_members tm ON tm.team_id = t.id
            WHERE tm.user_id = ?
            ORDER BY t.created_at DESC
        """, (u["sub"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/teams")
def create_team(req: TeamReq, request: Request):
    u = get_user(request)
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO teams (name, logo_url, primary_color, secondary_color, custom_domain) VALUES (?, ?, ?, ?, ?)",
            (req.name, req.logo_url, req.primary_color, req.secondary_color, req.custom_domain),
        )
        team_id = cur.lastrowid
        db.execute(
            "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
            (team_id, u["sub"], "owner"),
        )
    return {"id": team_id, "name": req.name}


@app.put("/api/teams/{team_id}")
def update_team(team_id: int, req: TeamReq, request: Request):
    u = get_user(request)
    with get_db() as db:
        # Verify membership
        member = db.execute(
            "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, u["sub"]),
        ).fetchone()
        if not member or member["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Not authorized")
        db.execute(
            "UPDATE teams SET name=?, logo_url=?, primary_color=?, secondary_color=?, custom_domain=? WHERE id=?",
            (req.name, req.logo_url, req.primary_color, req.secondary_color, req.custom_domain, team_id),
        )
    return {"ok": True}


@app.delete("/api/teams/{team_id}")
def delete_team(team_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        member = db.execute(
            "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, u["sub"]),
        ).fetchone()
        if not member or member["role"] != "owner":
            raise HTTPException(403, "Only owner can delete team")
        db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    return {"ok": True}


@app.get("/api/teams/{team_id}/members")
def list_team_members(team_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        # Verify membership
        if not db.execute("SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?", (team_id, u["sub"])).fetchone():
            raise HTTPException(403, "Not a team member")
        rows = db.execute("""
            SELECT tm.id, tm.user_id, tm.role, u.username
            FROM team_members tm JOIN users u ON u.id = tm.user_id
            WHERE tm.team_id = ?
        """, (team_id,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/teams/{team_id}/members")
def add_team_member(team_id: int, req: TeamMemberReq, request: Request):
    u = get_user(request)
    with get_db() as db:
        member = db.execute(
            "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, u["sub"]),
        ).fetchone()
        if not member or member["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Not authorized")
        cur = db.execute(
            "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)",
            (team_id, req.user_id, req.role),
        )
    return {"id": cur.lastrowid}


@app.delete("/api/teams/{team_id}/members/{user_id}")
def remove_team_member(team_id: int, user_id: int, request: Request):
    u = get_user(request)
    with get_db() as db:
        member = db.execute(
            "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, u["sub"]),
        ).fetchone()
        if not member or member["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Not authorized")
        db.execute(
            "DELETE FROM team_members WHERE team_id = ? AND user_id = ?",
            (team_id, user_id),
        )
    return {"ok": True}


# ──────────────── PDF Export ────────────────


@app.get("/api/scans/{scan_id}/report.pdf")
async def export_pdf(scan_id: int, request: Request):
    """Generate a PDF report for a scan using Playwright."""
    # Support both JWT auth and API key
    auth = request.headers.get("authorization", "")
    user = None
    if auth.startswith("Bearer "):
        user = verify_jwt(auth[7:])
        if not user:
            raise HTTPException(401, "Invalid or expired token")
    elif auth.startswith("ApiKey "):
        raw = verify_api_key(auth[7:])
        if not raw:
            raise HTTPException(401, "Invalid API key")
        # Normalize to same shape as JWT payload
        user = {"sub": raw["user_id"], "usr": raw.get("username", ""), "role": raw.get("role", "user")}
    else:
        raise HTTPException(401, "Not authenticated")

    with get_db() as db:
        scan = db.execute("SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user["sub"])).fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        results = db.execute(
            "SELECT category, test_name, status, severity, message FROM results WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        scan_dict = dict(scan)
    results_list = [dict(r) for r in results]

    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = styles["Title"]
    title_style.textColor = colors.HexColor(scan_dict.get("primary_color", "#7c6cf0"))
    elements.append(Paragraph(f"QA Scan Report: {scan_dict['url']}", title_style))
    elements.append(Spacer(1, 0.2*inch))

    # Score summary
    summary = json.loads(scan_dict.get("summary", "{}"))
    score = scan_dict.get("score", 0)
    score_color = colors.green if score >= 80 else colors.orange if score >= 60 else colors.red
    elements.append(Paragraph(f"<b>Overall Score: </b> {score} / 100", styles["Normal"]))
    elements.append(Paragraph(f"<b>Status: </b> {scan_dict['status']}", styles["Normal"]))
    elements.append(Paragraph(
        f"<b>Summary: </b> {summary.get('passed',0)} passed, "
        f"{summary.get('warned',0)} warnings, {summary.get('failed',0)} failed",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 0.3*inch))

    # Results table
    data = [["Category", "Test", "Status", "Severity", "Message"]]
    status_colors = {"pass": colors.green, "fail": colors.red, "warn": colors.orange}
    for r in results_list:
        msg = (r["message"] or "")[:60]
        data.append([
            r["category"],
            (r["test_name"] or "")[:40],
            r["status"].upper(),
            r["severity"],
            msg,
        ])

    t = Table(data, colWidths=[0.9*inch, 1.8*inch, 0.7*inch, 0.7*inch, 2.8*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c6cf0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    elements.append(t)

    doc.build(elements)
    buf.seek(0)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        iter([buf.read()]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'}
    )


# ──────────────── Config route ────────────────


@app.get("/api/config/default")
def default_config(request: Request):
    get_user(request)
    return DEFAULT_CONFIG


# ──────────────── Health ────────────────


@app.get("/health")
def health():
    return {"status": "ok"}


# ──────────────── SEO Static Files ────────────────


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return """User-agent: *
Allow: /

Sitemap: https://qa.uat.argitic.com/sitemap.xml
"""


@app.get("/sitemap.xml")
def sitemap():
    with get_db() as db:
        scans = db.execute(
            "SELECT id, url FROM scans ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    urls = [
        {"loc": "https://qa.uat.argitic.com/", "priority": "1.0", "changefreq": "daily"},
        {"loc": "https://qa.uat.argitic.com/#reports", "priority": "0.8", "changefreq": "weekly"},
        {"loc": "https://qa.uat.argitic.com/#config", "priority": "0.7", "changefreq": "weekly"},
        {"loc": "https://qa.uat.argitic.com/#settings", "priority": "0.6", "changefreq": "monthly"},
    ]
    for scan in scans:
        scan_id = scan["id"] if isinstance(scan, dict) else scan[0]
        urls.append({
            "loc": f"https://qa.uat.argitic.com/#report/{scan_id}",
            "priority": "0.5",
            "changefreq": "monthly"
        })
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for u in urls:
        xml += f'  <url>\n    <loc>{u["loc"]}</loc>\n    <changefreq>{u["changefreq"]}</changefreq>\n    <priority>{u["priority"]}</priority>\n  </url>\n'
    xml += '</urlset>'
    return Response(content=xml.encode(), media_type="application/xml")


# ──────────────── Web UI ────────────────


@app.get("/", response_class=HTMLResponse)
async def web_ui():
    with open("static/index.html") as f:
        return f.read()
