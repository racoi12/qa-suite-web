"""JWT auth + user management."""

import os
import hashlib
import hmac
import json
import time
import base64
from database import get_db

SECRET = os.getenv("JWT_SECRET", "change-me-in-production-please")
TOKEN_EXPIRY = 86400 * 7  # 7 days


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return (salt + h).hex()


def _verify_password(password: str, stored: str) -> bool:
    data = bytes.fromhex(stored)
    salt, h = data[:16], data[16:]
    return hmac.compare_digest(h, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_jwt(user_id: int, username: str, role: str) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "sub": user_id, "usr": username, "role": role,
        "exp": int(time.time()) + TOKEN_EXPIRY,
    }).encode())
    sig = hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def verify_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected = hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


def create_user(username: str, password: str, role: str = "user") -> int:
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, _hash_password(password), role),
        )
        return cur.lastrowid


def authenticate(username: str, password: str) -> dict | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and _verify_password(password, row["password_hash"]):
            return dict(row)
    return None


def list_users() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT id, username, role, created_at FROM users").fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: int) -> bool:
    with get_db() as db:
        # Delete in correct order to respect FK constraints
        db.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM api_keys WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM configs WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM schedules WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM webhooks WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM team_members WHERE user_id = ?", (user_id,))
        cur = db.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        return cur.rowcount > 0


def reset_password(user_id: int, new_password: str) -> bool:
    with get_db() as db:
        cur = db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_hash_password(new_password), user_id))
        return cur.rowcount > 0


def bootstrap_admin():
    """Create admin user if none exists."""
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    with get_db() as db:
        exists = db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        if not exists:
            create_user("admin", admin_pass, "admin")
            print(f"  Admin user created (username: admin)")


def verify_api_key(raw_key: str) -> dict | None:
    """Verify an API key and return the associated user dict. Updates last_used."""
    import hashlib, secrets
    if not raw_key.startswith("qas_"):
        return None
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with get_db() as db:
        row = db.execute(
            "SELECT api_keys.id, api_keys.user_id, api_keys.name, users.username, users.role "
            "FROM api_keys JOIN users ON users.id = api_keys.user_id "
            "WHERE api_keys.key_hash = ?",
            (key_hash,),
        ).fetchone()
        if not row:
            return None
        # Update last_used
        db.execute("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
    return dict(row)
