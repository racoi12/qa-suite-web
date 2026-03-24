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
        cur = db.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        return cur.rowcount > 0


def bootstrap_admin():
    """Create admin user if none exists."""
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    with get_db() as db:
        exists = db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
        if not exists:
            create_user("admin", admin_pass, "admin")
            print(f"  Admin user created (username: admin)")
