"""Meteora Capital website server.

Serves the static site and runs the investor portal:

  1. An investor submits the accredited investor attestation (investors.html).
  2. Approvers (MAIL_TO) get an email with a one-time review link
     (review.html), where they approve or deny the request.
  3. On approval the investor is emailed a one-time link to set a password
     (set-password.html).
  4. The investor logs in on investors.html and only then receives the
     DocSend links. Access is re-checked against the database on every request,
     so revoking (server/manage.py) takes effect immediately.

Security measures (see https://cheatsheetseries.owasp.org/):
  - XSS: user input is never rendered into HTML by the server; API responses
    are JSON; a strict Content-Security-Policy blocks inline and third-party
    scripts; page scripts write values with textContent only.
  - SQL injection: every query uses sqlite3 parameter binding (?).
  - Email header injection: subjects are fixed, senders/approvers come from
    config, the only user-supplied header (investor To/Reply-To) is a validated
    address built with Address(); inputs with control characters (CR/LF etc.)
    are rejected, and EmailMessage itself refuses headers with line breaks.
    Links in emails use PUBLIC_BASE_URL, never the request's Host header.
  - CSRF: synchronizer token in the signed session, required in an
    X-CSRF-Token header on every POST; Origin/Referer allowlist;
    SameSite=Strict, HttpOnly session cookie; JSON-only request bodies.
  - Authentication: passwords hashed with Argon2id; 15-128 character
    passwords; generic login errors and a dummy hash check so responses don't
    reveal which emails have accounts; per-IP rate limits and per-account
    lockout; session rotated on login; one-time tokens are random, stored only
    as SHA-256 hashes, expire, and are carried in the URL fragment so they
    never reach server logs or Referer headers.
Also: request size cap, security headers, and an allowlist of files that may
be served (server code, .env and the database are never exposed).
"""

import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

SITE_DIR = Path(__file__).resolve().parent.parent
SERVER_DIR = Path(__file__).resolve().parent

# Only these files (plus assets/) are ever served.
PUBLIC_FILES = {
    "index.html",
    "team.html",
    "login.html",
    "investors.html",
    "review.html",
    "set-password.html",
    "styles.css",
    "script.js",
    "portal.js",
    "investors.js",
    "review.js",
    "set-password.js",
}

# Bump whenever the attestation wording on investors.html changes, so each
# stored record shows which version the investor agreed to.
ATTESTATION_VERSION = "2026-10-18-draft"

# Rule 501(a) bases an investor may select, by investor type, with the short
# labels shown to approvers.
BASES = {
    "individual": {
        "income": "Income over $200K ($300K joint) in each of the last two years",
        "net_worth": "Net worth over $1M excluding primary residence",
        "license": "Holds Series 7, 65 or 82 license",
    },
    "entity": {
        "entity_assets": "Entity with total assets over $5M",
        "entity_investments": "Entity with investments over $5M",
        "entity_owners": "All equity owners are accredited",
        "institution": "Bank, broker-dealer, RIA, insurer or investment company",
        "family_office": "Family office over $5M AUM, or its family client",
        "trust": "Trust with assets over $5M, sophisticated trustee",
    },
}

TOKEN_TTL = {
    "review": timedelta(days=7),
    "set_password": timedelta(hours=72),
    "reset_password": timedelta(hours=1),
}

PASSWORD_MIN, PASSWORD_MAX = 15, 128
MAX_FAILED_LOGINS, LOCKOUT = 5, timedelta(minutes=15)

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
# C0/C1 control characters and Unicode line/paragraph separators.
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,100}$")

GENERIC_REQUEST_REPLY = (
    "Thank you. We will review your request and email you once access is approved."
)
GENERIC_FORGOT_REPLY = (
    "If that email has approved access, a reset link is on its way. It expires in 1 hour."
)

log = logging.getLogger("meteora")

# Argon2id with the library's defaults (above OWASP's minimum parameters).
hasher = PasswordHasher()


def verify_password(password_hash, password):
    try:
        return hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable {name}")
    if value and CONTROL_RE.search(value):
        raise RuntimeError(f"Environment variable {name} contains control characters")
    return value


def env_bool(name, default):
    return env(name, str(default)).strip().lower() in {"1", "true", "yes"}


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


class RateLimiter:
    """Fixed-window limiter kept in memory (fine for a single process)."""

    def __init__(self, limit, window_seconds):
        self.limit = limit
        self.window = window_seconds
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self.lock:
            hits = self.hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class ValidationError(Exception):
    pass


def clean_text(data, key, max_len, required=True, label=None):
    label = label or key
    value = data.get(key, "")
    if not isinstance(value, str):
        raise ValidationError(f"{label} is invalid.")
    value = value.strip()
    if CONTROL_RE.search(value):
        raise ValidationError(f"{label} contains invalid characters.")
    if required and not value:
        raise ValidationError(f"{label} is required.")
    if len(value) > max_len:
        raise ValidationError(f"{label} is too long.")
    return value


def clean_email(data, key="email"):
    email = clean_text(data, key, 254, label="Email")
    if not EMAIL_RE.match(email):
        raise ValidationError("Enter a valid email address.")
    return email


def clean_token(data):
    token = data.get("token")
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        raise ValidationError("This link is invalid or has expired.")
    return token


def clean_password(data):
    password = data.get("password")
    if not isinstance(password, str):
        raise ValidationError("Password is invalid.")
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise ValidationError(f"Password must be {PASSWORD_MIN} to {PASSWORD_MAX} characters.")
    if "\x00" in password:
        raise ValidationError("Password contains invalid characters.")
    return password


def validate_attestation(data):
    full_name = clean_text(data, "fullName", 120, label="Full name")
    email = clean_email(data)

    investor_type = clean_text(data, "investorType", 20, label="Investor type")
    if investor_type not in BASES:
        raise ValidationError("Select an investor type.")

    entity_name = clean_text(
        data, "entityName", 160, required=investor_type == "entity", label="Entity name"
    )

    basis = data.get("basis")
    allowed = BASES[investor_type]
    if not isinstance(basis, list) or not basis or len(basis) > len(allowed):
        raise ValidationError("Select at least one qualification.")
    if not all(isinstance(b, str) and b in allowed for b in basis):
        raise ValidationError("Invalid qualification selected.")

    if data.get("attest") is not True:
        raise ValidationError("You must confirm the attestation.")

    signature = clean_text(data, "signature", 120, label="Signature")
    if " ".join(signature.split()).casefold() != " ".join(full_name.split()).casefold():
        raise ValidationError("Your signature must match your full name.")

    return {
        "full_name": full_name,
        "email": email,
        "investor_type": investor_type,
        "entity_name": entity_name if investor_type == "entity" else "",
        "basis": sorted(set(basis)),
        "signature": signature,
    }


SCHEMA = """
CREATE TABLE IF NOT EXISTS investors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'revoked')),
    password_hash TEXT,
    session_epoch INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS attestations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investor_id INTEGER NOT NULL REFERENCES investors(id),
    created_at TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    investor_type TEXT NOT NULL,
    entity_name TEXT NOT NULL,
    basis TEXT NOT NULL,
    signature TEXT NOT NULL,
    attestation_version TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    investor_id INTEGER NOT NULL REFERENCES investors(id),
    attestation_id INTEGER REFERENCES attestations(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
"""


def database_path():
    return Path(env("DATABASE_PATH") or SERVER_DIR / "instance" / "portal.db")


@contextmanager
def connect(path=None):
    """Connection that commits on success and always closes."""
    conn = sqlite3.connect(path or database_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(path=None):
    path = path or database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def issue_token(conn, purpose, investor_id, attestation_id=None):
    """Create a one-time token, invalidating older ones for the same purpose."""
    issued = now_utc()
    conn.execute(
        "UPDATE tokens SET used_at = ? WHERE investor_id = ? AND purpose = ? AND used_at IS NULL",
        (iso(issued), investor_id, purpose),
    )
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO tokens (token_hash, purpose, investor_id, attestation_id, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (hash_token(token), purpose, investor_id, attestation_id, iso(issued), iso(issued + TOKEN_TTL[purpose])),
    )
    return token


def find_token(conn, token, purposes):
    row = conn.execute(
        "SELECT * FROM tokens WHERE token_hash = ? AND used_at IS NULL",
        (hash_token(token),),
    ).fetchone()
    if row is None or row["purpose"] not in purposes or row["expires_at"] <= iso(now_utc()):
        return None
    return row


def use_token(conn, token_row):
    conn.execute("UPDATE tokens SET used_at = ? WHERE id = ?", (iso(now_utc()), token_row["id"]))


class Mailer:
    def __init__(self, base_url):
        self.base_url = base_url

    def link(self, page, token):
        # Token in the fragment: never sent to the server or in Referer.
        return f"{self.base_url}/{page}#token={token}"

    def send(self, to, subject, body, reply_to=None):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = env("MAIL_FROM", "website@meteoracapital.com")
        msg["To"] = to
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(body)

        host = env("SMTP_HOST")
        if not host:
            # Development only: print instead of sending.
            log.warning(
                "SMTP_HOST not set; email not sent.\nTo: %s\nSubject: %s\n\n%s",
                msg["To"], msg["Subject"], msg.get_content(),
            )
            return
        port = int(env("SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            user = env("SMTP_USER")
            if user:
                smtp.login(user, env("SMTP_PASSWORD", required=True))
            smtp.send_message(msg)

    def investor_address(self, email):
        # Validated by EMAIL_RE; Address() also rejects malformed values.
        return Address(display_name="", addr_spec=email)

    def review_request(self, record, token):
        bases = BASES[record["investor_type"]]
        self.send(
            env("MAIL_TO", required=True),
            "Investor access request",
            "\n".join(
                [
                    "A new investor access request needs review.",
                    "",
                    f"Name:           {record['full_name']}",
                    f"Email:          {record['email']}",
                    f"Investor type:  {record['investor_type']}",
                    f"Entity:         {record['entity_name'] or '-'}",
                    "Qualifications: " + "; ".join(bases[b] for b in record["basis"]),
                    f"Signature:      {record['signature']}",
                    f"Submitted:      {record['created_at']}",
                    "",
                    "Review and approve or deny (single use, expires in 7 days):",
                    self.link("review.html", token),
                    "",
                    "Anyone with this link can decide the request, so do not forward it.",
                ]
            ),
            reply_to=self.investor_address(record["email"]),
        )

    def set_password(self, email, full_name, token):
        self.send(
            self.investor_address(email),
            "Your Meteora Capital investor access is approved",
            "\n".join(
                [
                    f"Hello {full_name},",
                    "",
                    "Your request for access to Meteora Capital investor materials has been approved.",
                    "Set your password using the link below (single use, expires in 72 hours):",
                    "",
                    self.link("set-password.html", token),
                    "",
                    f"Then sign in at {self.base_url}/investors.html",
                ]
            ),
        )

    def reset_password(self, email, token):
        self.send(
            self.investor_address(email),
            "Reset your Meteora Capital investor password",
            "\n".join(
                [
                    "We received a request to reset your password.",
                    "Use the link below to choose a new one (single use, expires in 1 hour):",
                    "",
                    self.link("set-password.html", token),
                    "",
                    "If you did not request this, you can ignore this email.",
                ]
            ),
        )


def create_app():
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=env("SECRET_KEY", required=True),
        SESSION_COOKIE_NAME="mc_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=env_bool("COOKIE_SECURE", True),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(env("SESSION_HOURS", "12"))),
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    proxies = int(env("TRUSTED_PROXIES", "0"))
    if proxies:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies)

    base_url = env("PUBLIC_BASE_URL", required=True).rstrip("/")
    if urlsplit(base_url).scheme not in {"https", "http"}:
        raise RuntimeError("PUBLIC_BASE_URL must be an http(s) URL")
    allowed_origins = {base_url} | {
        o.strip().rstrip("/") for o in env("ALLOWED_ORIGINS", "").split(",") if o.strip()
    }
    materials = {
        "deck": env("DOCSEND_DECK_URL", "https://docsend.com/view/REPLACE-DECK"),
        "tearSheet": env("DOCSEND_TEARSHEET_URL", "https://docsend.com/view/REPLACE-TEARSHEET"),
    }
    for url in materials.values():
        if urlsplit(url).scheme != "https":
            raise RuntimeError("DocSend URLs must use https")

    init_db()
    mailer = Mailer(base_url)
    dummy_hash = hasher.hash(secrets.token_urlsafe(16))
    limits = {
        "request": RateLimiter(int(env("REQUEST_LIMIT", "5")), 600),
        "login": RateLimiter(int(env("LOGIN_LIMIT", "10")), 900),
        "forgot": RateLimiter(5, 600),
        "token": RateLimiter(20, 600),
    }

    def client_ip():
        return request.remote_addr or "unknown"

    def error(message, status):
        return jsonify({"ok": False, "error": message}), status

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def origin_allowed():
        origin = request.headers.get("Origin")
        if origin is None:
            parts = urlsplit(request.headers.get("Referer", ""))
            origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None
        return origin in allowed_origins

    def current_investor(conn):
        """The logged-in investor, only while still approved and not revoked."""
        investor_id = session.get("investor_id")
        if investor_id is None:
            return None
        row = conn.execute("SELECT * FROM investors WHERE id = ?", (investor_id,)).fetchone()
        if row is None or row["status"] != "approved" or row["session_epoch"] != session.get("epoch"):
            return None
        return row

    def start_session(investor):
        session.clear()
        session.permanent = True
        session["investor_id"] = investor["id"]
        session["epoch"] = investor["session_epoch"]
        session["csrf"] = secrets.token_urlsafe(32)

    @app.before_request
    def protect_posts():
        if request.method != "POST":
            return None
        if not origin_allowed():
            return error("Request origin not allowed.", 403)
        sent = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            return error("Your session expired. Reload the page and try again.", 403)
        if not request.is_json or not isinstance(request.get_json(silent=True), dict):
            return error("Unsupported request.", 415)
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data: https://meteoracapital.com https://images.pexels.com https://upload.wikimedia.org; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/session")
    def api_session():
        with connect() as conn:
            investor = current_investor(conn)
        return jsonify(
            {
                "csrfToken": csrf_token(),
                "loggedIn": investor is not None,
                "name": investor["full_name"] if investor else None,
            }
        )

    @app.post("/api/request-access")
    def api_request_access():
        if not limits["request"].allow(client_ip()):
            return error("Too many requests. Try again later.", 429)
        try:
            data = validate_attestation(request.get_json())
        except ValidationError as exc:
            return error(str(exc), 400)

        record = dict(data, created_at=iso(now_utc()))
        review_token = None
        with connect() as conn:
            investor = conn.execute(
                "SELECT * FROM investors WHERE email = ?", (data["email"],)
            ).fetchone()
            if investor is None:
                investor_id = conn.execute(
                    "INSERT INTO investors (email, full_name, status, created_at) VALUES (?, ?, 'pending', ?)",
                    (data["email"], data["full_name"], record["created_at"]),
                ).lastrowid
                status = "pending"
            else:
                investor_id, status = investor["id"], investor["status"]

            attestation_id = conn.execute(
                "INSERT INTO attestations (investor_id, created_at, full_name, email, investor_type,"
                " entity_name, basis, signature, attestation_version, ip, user_agent)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    investor_id,
                    record["created_at"],
                    data["full_name"],
                    data["email"],
                    data["investor_type"],
                    data["entity_name"],
                    ",".join(data["basis"]),
                    data["signature"],
                    ATTESTATION_VERSION,
                    client_ip(),
                    CONTROL_RE.sub("", request.headers.get("User-Agent", ""))[:300],
                ),
            ).lastrowid

            # Already-approved investors just get the new attestation on file;
            # anyone else goes (back) to the approvers.
            if status != "approved":
                conn.execute(
                    "UPDATE investors SET status = 'pending', full_name = ?, decided_at = NULL WHERE id = ?",
                    (data["full_name"], investor_id),
                )
                review_token = issue_token(conn, "review", investor_id, attestation_id)

        if review_token:
            try:
                mailer.review_request(record, review_token)
            except Exception:
                log.exception("Failed to send review email for investor %s", investor_id)
        # Same reply whatever the account state, so it can't be used to probe emails.
        return jsonify({"ok": True, "message": GENERIC_REQUEST_REPLY})

    @app.post("/api/review/details")
    def api_review_details():
        if not limits["token"].allow(client_ip()):
            return error("Too many requests. Try again later.", 429)
        try:
            token = clean_token(request.get_json())
        except ValidationError as exc:
            return error(str(exc), 400)
        with connect() as conn:
            row = find_token(conn, token, {"review"})
            if row is None:
                return error("This review link is invalid, already used or expired.", 404)
            att = conn.execute(
                "SELECT * FROM attestations WHERE id = ?", (row["attestation_id"],)
            ).fetchone()
        bases = BASES[att["investor_type"]]
        return jsonify(
            {
                "ok": True,
                "request": {
                    "fullName": att["full_name"],
                    "email": att["email"],
                    "investorType": att["investor_type"],
                    "entityName": att["entity_name"],
                    "qualifications": [bases[b] for b in att["basis"].split(",")],
                    "signature": att["signature"],
                    "submitted": att["created_at"],
                    "attestationVersion": att["attestation_version"],
                },
            }
        )

    @app.post("/api/review/decide")
    def api_review_decide():
        if not limits["token"].allow(client_ip()):
            return error("Too many requests. Try again later.", 429)
        data = request.get_json()
        try:
            token = clean_token(data)
        except ValidationError as exc:
            return error(str(exc), 400)
        decision = data.get("decision")
        if decision not in {"approve", "deny"}:
            return error("Invalid decision.", 400)

        password_token = None
        with connect() as conn:
            row = find_token(conn, token, {"review"})
            if row is None:
                return error("This review link is invalid, already used or expired.", 404)
            use_token(conn, row)
            investor = conn.execute(
                "SELECT * FROM investors WHERE id = ?", (row["investor_id"],)
            ).fetchone()
            status = "approved" if decision == "approve" else "denied"
            conn.execute(
                "UPDATE investors SET status = ?, decided_at = ?, session_epoch = session_epoch + 1 WHERE id = ?",
                (status, iso(now_utc()), investor["id"]),
            )
            if status == "approved":
                password_token = issue_token(conn, "set_password", investor["id"])
            log.info("Investor %s %s", investor["id"], status)

        if password_token:
            try:
                mailer.set_password(investor["email"], investor["full_name"], password_token)
            except Exception:
                log.exception("Failed to send set-password email for investor %s", investor["id"])
                return jsonify(
                    {"ok": True, "status": status, "warning": "Approved, but the email to the investor failed to send."}
                )
        return jsonify({"ok": True, "status": status})

    @app.post("/api/password/set")
    def api_password_set():
        if not limits["token"].allow(client_ip()):
            return error("Too many requests. Try again later.", 429)
        data = request.get_json()
        try:
            token = clean_token(data)
            password = clean_password(data)
        except ValidationError as exc:
            return error(str(exc), 400)
        with connect() as conn:
            row = find_token(conn, token, {"set_password", "reset_password"})
            if row is None:
                return error("This link is invalid, already used or expired.", 404)
            investor = conn.execute(
                "SELECT * FROM investors WHERE id = ?", (row["investor_id"],)
            ).fetchone()
            if investor["status"] != "approved":
                return error("This link is invalid, already used or expired.", 404)
            if password.casefold() == investor["email"].casefold():
                return error("Choose a password that isn't your email address.", 400)
            use_token(conn, row)
            # Bumping the epoch signs out any other sessions.
            conn.execute(
                "UPDATE investors SET password_hash = ?, session_epoch = session_epoch + 1,"
                " failed_logins = 0, locked_until = NULL WHERE id = ?",
                (hasher.hash(password), investor["id"]),
            )
        return jsonify({"ok": True})

    @app.post("/api/password/forgot")
    def api_password_forgot():
        if not limits["forgot"].allow(client_ip()):
            return error("Too many requests. Try again later.", 429)
        try:
            email = clean_email(request.get_json())
        except ValidationError as exc:
            return error(str(exc), 400)
        token = None
        with connect() as conn:
            investor = conn.execute(
                "SELECT * FROM investors WHERE email = ? AND status = 'approved'", (email,)
            ).fetchone()
            if investor is not None:
                token = issue_token(conn, "reset_password", investor["id"])
        if token:
            try:
                mailer.reset_password(investor["email"], token)
            except Exception:
                log.exception("Failed to send reset email for investor %s", investor["id"])
        return jsonify({"ok": True, "message": GENERIC_FORGOT_REPLY})

    @app.post("/api/login")
    def api_login():
        if not limits["login"].allow(client_ip()):
            return error("Too many sign-in attempts. Try again later.", 429)
        data = request.get_json()
        failure = error("Incorrect email or password.", 401)
        try:
            email = clean_email(data)
        except ValidationError:
            return failure
        password = data.get("password")
        if not isinstance(password, str) or not password or len(password) > PASSWORD_MAX:
            return failure

        with connect() as conn:
            investor = conn.execute("SELECT * FROM investors WHERE email = ?", (email,)).fetchone()
            usable = (
                investor is not None
                and investor["status"] == "approved"
                and investor["password_hash"] is not None
            )
            # Always run a hash check so timing doesn't reveal which emails exist.
            valid = verify_password(investor["password_hash"] if usable else dummy_hash, password)
            if not usable:
                return failure
            if investor["locked_until"] and investor["locked_until"] > iso(now_utc()):
                return error("Too many failed attempts. Try again in 15 minutes or reset your password.", 429)
            if not valid:
                failed = investor["failed_logins"] + 1
                locked = iso(now_utc() + LOCKOUT) if failed >= MAX_FAILED_LOGINS else None
                conn.execute(
                    "UPDATE investors SET failed_logins = ?, locked_until = ? WHERE id = ?",
                    (0 if locked else failed, locked, investor["id"]),
                )
                return failure
            conn.execute(
                "UPDATE investors SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                (investor["id"],),
            )
        start_session(investor)
        return jsonify({"ok": True, "name": investor["full_name"], "csrfToken": session["csrf"]})

    @app.post("/api/logout")
    def api_logout():
        session.clear()
        return jsonify({"ok": True, "csrfToken": csrf_token()})

    @app.get("/api/materials")
    def api_materials():
        with connect() as conn:
            investor = current_investor(conn)
        if investor is None:
            return error("Sign in to view materials.", 401)
        return jsonify({"ok": True, "materials": materials})

    @app.get("/")
    def home():
        return send_from_directory(SITE_DIR, "index.html")

    @app.get("/assets/<path:name>")
    def assets(name):
        return send_from_directory(SITE_DIR / "assets", name)

    @app.get("/<name>")
    def page(name):
        if name not in PUBLIC_FILES:
            abort(404)
        return send_from_directory(SITE_DIR, name)

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
