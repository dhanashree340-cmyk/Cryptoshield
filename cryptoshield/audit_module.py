"""
audit_module.py
Audit logging for CryptoShield (moved out of app.py so the login/registration
routes can use it too). Same file as before: logs/audit_log.txt

Line format:  [2026-10-08 08:30:10] USER dhanashree ENCRYPTION SUCCESS

NEVER pass passwords or keys to log().
"""

import os
import threading
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "audit_log.txt")
_lock = threading.Lock()


def log(message: str, username: str = None):
    """Append one event to the audit log, tagged with the username if given."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = " ".join(str(message).split())  # no newlines -> no fake log lines
    prefix = f"USER {username} " if username else ""
    with _lock:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {prefix}{message}\n")


def read_log(username: str, limit: int = 25):
    """Return the newest `limit` events for ONE user (newest first)."""
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f.readlines()]
    mine = []
    for line in lines:
        _, _, rest = line.partition("] ")
        if rest.startswith(f"USER {username} "):
            mine.append(line)
    return mine[-limit:][::-1]
