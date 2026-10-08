#!/usr/bin/env python3
"""Halves ledger: static page + SQLite API on 127.0.0.1:8091."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, make_response, redirect, request, send_from_directory
from werkzeug.security import check_password_hash

ROOT = Path(__file__).resolve().parent
DB = ROOT / "halves.db"
SECRET = ROOT / "halves.secret"
USERS = ROOT / "halves.users"
AUTHKEY = ROOT / "halves.authkey"
SEED = ROOT / "halves-backup.json"
HISTORY_KEEP = 200
COOKIE = "halves"
SESSION_DAYS = 180

app = Flask(__name__)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ledger_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            saved_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def pin_ok() -> bool:
    if current_user():
        return True
    if not SECRET.exists():
        return True
    expected = SECRET.read_text().strip()
    got = (request.headers.get("X-Halves-Pin") or "").strip()
    body = request.get_json(silent=True) or {}
    if not got:
        got = str(body.get("pin") or "").strip()
    return bool(expected) and got == expected


def auth_key() -> bytes:
    if AUTHKEY.exists():
        return AUTHKEY.read_bytes().strip()
    AUTHKEY.write_bytes(secrets.token_bytes(32))
    AUTHKEY.chmod(0o600)
    return AUTHKEY.read_bytes().strip()


def load_users() -> dict[str, str]:
    users = {}
    if not USERS.exists():
        return users
    for line in USERS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, hashed = line.split(":", 1)
        name = name.strip().lower()
        if name:
            users[name] = hashed.strip()
    return users


def password_ok(username: str, password: str) -> bool:
    users = load_users()
    hashed = users.get((username or "").strip().lower())
    if not hashed or not password:
        return False
    try:
        return check_password_hash(hashed, password.strip())
    except Exception:
        return False


def sign(user: str, exp: str) -> str:
    return hmac.new(auth_key(), f"{user}.{exp}".encode(), hashlib.sha256).hexdigest()


def make_session(user: str) -> str:
    exp = str(int(time.time()) + SESSION_DAYS * 24 * 3600)
    return f"{user}.{exp}.{sign(user, exp)}"


def session_user() -> str | None:
    raw = request.cookies.get(COOKIE) or ""
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    user, exp, sig = parts
    try:
        if int(exp) < int(time.time()):
            return None
    except ValueError:
        return None
    if not hmac.compare_digest(sign(user, exp), sig):
        return None
    if user not in load_users():
        return None
    return user


def basic_user() -> str | None:
    auth = request.authorization
    if not auth:
        return None
    if password_ok(auth.username, auth.password):
        return auth.username.strip().lower()
    return None


def current_user() -> str | None:
    return session_user() or basic_user()


def attach_session(resp, user: str):
    resp.set_cookie(
        COOKIE,
        make_session(user),
        max_age=SESSION_DAYS * 24 * 3600,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    return resp


def login_html(error: str = "") -> str:
    err = f'<p class="err">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Halves · Sign in</title>
  <style>
    :root {{ --bg:#153a58; --card:#f3f7fb; --ink:#1b2d40; --muted:#5c738a; --btn:#1e5a8a; }}
    html,body {{ margin:0; min-height:100%; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:#e8f0f7; }}
    .wrap {{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }}
    form {{ background:var(--card); color:var(--ink); width:min(400px,100%); border-radius:16px; padding:28px 24px; box-shadow:0 8px 24px rgba(10,30,48,.25); }}
    h1 {{ font-weight:500; margin:0 0 8px; font-size:1.8rem; }}
    p {{ color:var(--muted); margin:0 0 18px; }}
    .err {{ color:#8f3d32; font-weight:600; }}
    code {{ font-size:.95rem; color:var(--ink); }}
    label {{ display:block; font-size:.78rem; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); margin:12px 0 6px; }}
    input {{ width:100%; box-sizing:border-box; border:1px solid #c9d7e4; border-radius:10px; padding:10px 12px; font-size:1rem; }}
    button {{ margin-top:18px; border:0; border-radius:10px; padding:10px 14px; font-weight:600; background:var(--btn); color:#f4f8fc; font-size:.95rem; width:100%; }}
  </style>
</head>
<body>
  <div class="wrap">
    <form method="post" action="/login" autocomplete="on">
      <h1>Halves</h1>
      <p>Username is <code>ian</code> or <code>trudie</code> — not your email. Password is case-sensitive. Safari can save it after a successful sign-in.</p>
      {err}
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="ian" required />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" required />
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"""


def seed_if_empty() -> None:
    conn = connect()
    row = conn.execute("SELECT 1 FROM ledger WHERE id = 1").fetchone()
    if row:
        conn.close()
        return
    if not SEED.exists():
        conn.close()
        return
    payload = json.dumps(json.loads(SEED.read_text()), separators=(",", ":"))
    ts = utcnow()
    conn.execute(
        "INSERT INTO ledger (id, payload, updated_at) VALUES (1, ?, ?)",
        (payload, ts),
    )
    conn.execute(
        "INSERT INTO ledger_history (payload, saved_at) VALUES (?, ?)",
        (payload, ts),
    )
    conn.commit()
    conn.close()


@app.before_request
def require_login():
    if request.endpoint in {"login", "login_post", "logout", "health", "public_file"}:
        return None
    if current_user():
        return None
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "login"}), 401
    return redirect("/login")


@app.get("/login")
def login():
    if current_user():
        return redirect("/")
    return login_html()


@app.post("/login")
def login_post():
    user = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    if not password_ok(user, password):
        # 200 not 401: Safari on iPhone often hides 401 HTML and looks like "it doesn't work".
        return make_response(login_html("Wrong username or password. Use ian or trudie, and check the capital W."), 200)
    html = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8" />
<meta http-equiv="refresh" content="0;url=/" />
<title>Halves</title>
<script>location.replace("/");</script>
</head>
<body><p><a href="/">Continue to Halves</a></p></body></html>"""
    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-store"
    return attach_session(resp, user)


@app.get("/logout")
def logout():
    resp = redirect("/login")
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/")
def index():
    resp = send_from_directory(ROOT, "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.get("/<name>")
def public_file(name):
    # Google Search Console verification files only — never db/secret/backups.
    if not (name.startswith("google") and name.endswith(".html")):
        abort(404)
    if "/" in name or "\\" in name or ".." in name:
        abort(404)
    path = ROOT / name
    if not path.is_file():
        abort(404)
    return send_from_directory(ROOT, name)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "deposits": True, "pnl": True, "auth": True})


@app.get("/api/ledger")
def get_ledger():
    conn = connect()
    row = conn.execute(
        "SELECT payload, updated_at FROM ledger WHERE id = 1"
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": True, "updated_at": None, "ledger": None})
    return jsonify(
        {"ok": True, "updated_at": row[1], "ledger": json.loads(row[0])}
    )


@app.put("/api/ledger")
def put_ledger():
    if not pin_ok():
        return jsonify({"ok": False, "error": "pin"}), 403
    body = request.get_json(force=True, silent=True) or {}
    ledger = body.get("ledger", body)
    if not isinstance(ledger, dict) or "people" not in ledger or "expenses" not in ledger:
        return jsonify({"ok": False, "error": "invalid ledger"}), 400
    payload = json.dumps(ledger, separators=(",", ":"))
    ts = utcnow()
    conn = connect()
    conn.execute(
        """
        INSERT INTO ledger (id, payload, updated_at)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            payload = excluded.payload,
            updated_at = excluded.updated_at
        """,
        (payload, ts),
    )
    conn.execute(
        "INSERT INTO ledger_history (payload, saved_at) VALUES (?, ?)",
        (payload, ts),
    )
    conn.execute(
        """
        DELETE FROM ledger_history
        WHERE id NOT IN (
            SELECT id FROM ledger_history ORDER BY id DESC LIMIT ?
        )
        """,
        (HISTORY_KEEP,),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "updated_at": ts})


if __name__ == "__main__":
    seed_if_empty()
    app.run(host="127.0.0.1", port=8091, threaded=True)
