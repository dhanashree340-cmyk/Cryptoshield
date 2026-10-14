"""
auth/utils.py
Helpers for user accounts: SQLite storage, password hashing, login checks,
and a small brute-force throttle.

Two SQLite tables (file: cryptoshield.db):
  users   -> username + password HASH (never the password)
  bundles -> one encrypted bundle per user (salt, nonce, ciphertext, tags)
"""

import os
import re
import time
import sqlite3
import threading
from contextlib import closing
from functools import wraps

from flask import session, redirect, url_for, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("CRYPTOSHIELD_DB", os.path.join(BASE_DIR, "cryptoshield.db"))

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128

# Used so a login for an unknown username takes about as long as a real one.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------- database ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(get_db()) as conn, conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bundles (
                user_id        INTEGER PRIMARY KEY REFERENCES users(id),
                salt           BLOB NOT NULL,
                nonce          BLOB NOT NULL,
                ciphertext     BLOB NOT NULL,
                hmac_tag       TEXT NOT NULL,
                sha256_hash    TEXT NOT NULL,
                bundle_digest  TEXT NOT NULL,
                created_at     TEXT NOT NULL
            )""")


def _now():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- users ----------

def valid_username(username) -> bool:
    return isinstance(username, str) and bool(USERNAME_RE.match(username))


def valid_password(password) -> bool:
    return isinstance(password, str) and MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN


def create_user(username: str, password: str) -> bool:
    """Store username + password HASH. Returns False if the username is taken."""
    try:
        with closing(get_db()) as conn, conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), _now()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def username_taken(username: str) -> bool:
    with closing(get_db()) as conn:
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    return row is not None


def check_login(username: str, password: str):
    """Return the user row if the credentials are right, otherwise None."""
    with closing(get_db()) as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    if user is None:
        check_password_hash(_DUMMY_HASH, password)  # keep timing similar
        return None
    return user if check_password_hash(user["password_hash"], password) else None


# ---------- encrypted bundles (one per user) ----------

def save_bundle(user_id, salt, nonce, ciphertext, hmac_tag, sha256_hash, bundle_digest):
    with closing(get_db()) as conn, conn:
        conn.execute(
            """INSERT OR REPLACE INTO bundles
               (user_id, salt, nonce, ciphertext, hmac_tag, sha256_hash, bundle_digest, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, salt, nonce, ciphertext, hmac_tag, sha256_hash, bundle_digest, _now()),
        )


def get_bundle(user_id):
    """Always filtered by user_id, so one user can never read another's bundle."""
    with closing(get_db()) as conn:
        row = conn.execute("SELECT * FROM bundles WHERE user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def update_ciphertext(user_id, ciphertext):
    """Used only by the 'Test Tamper' demo."""
    with closing(get_db()) as conn, conn:
        conn.execute("UPDATE bundles SET ciphertext = ? WHERE user_id = ?", (ciphertext, user_id))


# ---------- sessions ----------

def current_user():
    if "user_id" in session and "username" in session:
        return {"id": session["user_id"], "username": session["username"]}
    return None


def login_required(view):
    """Pages redirect to /login; /api/* endpoints answer 401 JSON."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in first."}), 401
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


# ---------- brute-force throttle (in memory) ----------

MAX_FAILS = 5
WINDOW_SECONDS = 300
_fails = {}
_fails_lock = threading.Lock()


def _recent(key):
    cutoff = time.time() - WINDOW_SECONDS
    _fails[key] = [t for t in _fails.get(key, []) if t > cutoff]
    return _fails[key]


def is_blocked(key) -> bool:
    with _fails_lock:
        return len(_recent(key)) >= MAX_FAILS


def record_failure(key):
    with _fails_lock:
        _recent(key).append(time.time())


def clear_failures(key):
    with _fails_lock:
        _fails.pop(key, None)
