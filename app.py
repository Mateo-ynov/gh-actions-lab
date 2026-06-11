"""
VulnTasker — Deliberately Vulnerable Task Management API
=========================================================
⚠️  FOR TRAINING ONLY — NEVER deploy this in production.
    This app contains 6 labelled security vulnerabilities.
=========================================================
"""

import hashlib
import logging
import sqlite3
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 🚨 VULN #1 — Hardcoded Credentials (CWE-798)
#    API tokens and passwords must come from environment variables or a
#    secrets manager — never hardcoded in source code.
#    Fix: import os; ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]
# ─────────────────────────────────────────────────────────────────────────────
ADMIN_TOKEN  = "super-secret-admin-token-1234"
ADMIN_PASSWD = "admin123"

# ─────────────────────────────────────────────────────────────────────────────
# Database — SQLite in-memory (reused across requests)
# ─────────────────────────────────────────────────────────────────────────────
_db: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _db
    if _db is None:
        _db = sqlite3.connect(":memory:", check_same_thread=False)
        _db.row_factory = sqlite3.Row
        _db.executescript("""
            CREATE TABLE tasks (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                title  TEXT NOT NULL,
                owner  TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            );
            INSERT INTO tasks (title, owner) VALUES ('Fix prod server',  'alice');
            INSERT INTO tasks (title, owner) VALUES ('Write runbook',    'bob');
            INSERT INTO tasks (title, owner) VALUES ('Review PR #42',    'alice');
            INSERT INTO tasks (title, owner) VALUES ('Update firewall',  'carol');
        """)
    return _db


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/tasks")
def list_tasks():
    """List all tasks, optionally filtered by owner."""
    owner = request.args.get("owner", "")

    # ─────────────────────────────────────────────────────────────────────────
    # 🚨 VULN #2 — SQL Injection (CWE-89)
    #    An attacker can bypass the filter with:
    #    GET /tasks?owner=' OR '1'='1
    #    …and retrieve ALL tasks in the database.
    #
    #    Fix: use a parameterised query —
    #    get_db().execute("SELECT * FROM tasks WHERE owner = ?", (owner,))
    # ─────────────────────────────────────────────────────────────────────────
    rows = get_db().execute(
        f"SELECT * FROM tasks WHERE owner = '{owner}'"
    ).fetchall()
    return jsonify({"tasks": [dict(r) for r in rows]})


@app.route("/tasks", methods=["POST"])
def create_task():
    """Create a new task."""
    data  = request.get_json(silent=True) or {}
    title = data.get("title", "Untitled")
    owner = data.get("owner", "unknown")
    get_db().execute("INSERT INTO tasks (title, owner) VALUES (?, ?)", (title, owner))
    get_db().commit()
    return jsonify({"message": "Task created"}), 201


@app.route("/login", methods=["POST"])
def login():
    """Authenticate a user and return an admin token."""
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # ─────────────────────────────────────────────────────────────────────────
    # 🚨 VULN #3 — Sensitive Data in Logs (CWE-532)
    #    Passwords written to log files can be read by anyone with log access.
    #    Fix: log only the username, never the password.
    # ─────────────────────────────────────────────────────────────────────────
    logger.info("Login attempt: user=%s password=%s", username, password)

    # ─────────────────────────────────────────────────────────────────────────
    # 🚨 VULN #4 — Weak Password Hashing — MD5 (CWE-327)
    #    MD5 is cryptographically broken and trivially reversible with
    #    rainbow tables. Use bcrypt or argon2id instead.
    # ─────────────────────────────────────────────────────────────────────────
    hashed = hashlib.md5(password.encode()).hexdigest()
    if username == "admin" and hashed == hashlib.md5(ADMIN_PASSWD.encode()).hexdigest():
        return jsonify({"token": ADMIN_TOKEN})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/export")
def export_tasks():
    """Export tasks to CSV (admin only)."""
    if request.headers.get("X-Token") != ADMIN_TOKEN:
        return jsonify({"error": "Forbidden"}), 403

    filename = request.args.get("filename", "tasks.csv")

    # ─────────────────────────────────────────────────────────────────────────
    # 🚨 VULN #5 — Command Injection via shell=True (CWE-78)
    #    An attacker can append shell commands to the filename:
    #    GET /export?filename=x.csv;cat+/etc/passwd
    #
    #    Fix: never use shell=True; pass a list of arguments instead:
    #    subprocess.run(["sh", "-c", f"echo ... > /tmp/{safe_filename}"])
    #    and validate/sanitise the filename first.
    # ─────────────────────────────────────────────────────────────────────────
    cmd = f"echo 'id,title,owner,status' > /tmp/{filename}"
    subprocess.run(cmd, shell=True)  # noqa: S602

    return jsonify({"exported_to": f"/tmp/{filename}"})


@app.route("/health")
def health():
    """Liveness probe — used by Docker and GitHub Actions."""
    return jsonify({"status": "ok", "app": "VulnTasker"})


# ─────────────────────────────────────────────────────────────────────────────
# 🚨 VULN #6 — Debug Mode Enabled in Production (CWE-215)
#    Flask's debug mode exposes an interactive Python console in the browser
#    on every exception page — full remote code execution for an attacker.
#
#    Fix: never set debug=True; use the environment variable:
#    FLASK_DEBUG=0 flask run
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
