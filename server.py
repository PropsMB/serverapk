#!/usr/bin/env python3
"""Zmiana schedule API. SQLite locally; Render PostgreSQL when DATABASE_URL is set."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


HERE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("ZM_DATA_DIR", HERE / "data"))
DB_PATH = DATA_DIR / "zmiana.sqlite3"
SECRET_PATH = DATA_DIR / "server.key"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))
PASSWORD_ITERATIONS = 310_000
TOKEN_LIFETIME = 60 * 60 * 24
LOGIN_WINDOW = 10 * 60
LOGIN_LIMIT = 10
login_attempts: dict[str, list[float]] = {}
login_lock = threading.Lock()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def get_secret() -> bytes:
    configured = os.environ.get("ZM_SECRET")
    if configured:
        return configured.encode("utf-8")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        return SECRET_PATH.read_bytes()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            with SECRET_PATH.open("xb") as f:
                f.write(key)
        except FileExistsError:
            return SECRET_PATH.read_bytes()
        return key


SECRET = get_secret()


class Database:
    def __init__(self) -> None:
        if USE_POSTGRES:
            import psycopg
            from psycopg.rows import dict_row
            self.raw = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            self.raw = sqlite3.connect(DB_PATH, timeout=15)
            self.raw.row_factory = sqlite3.Row
            self.raw.execute("PRAGMA foreign_keys = ON")

    def __enter__(self) -> "Database":
        self.raw.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        try:
            return self.raw.__exit__(*args)
        finally:
            self.raw.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        if USE_POSTGRES:
            sql = sql.replace("?", "%s")
        return self.raw.execute(sql, params)

    def executescript(self, sql: str) -> None:
        if USE_POSTGRES:
            for statement in sql.split(";"):
                if statement.strip():
                    self.raw.execute(statement)
        else:
            self.raw.executescript(sql)


def connect() -> Database:
    return Database()


def initialize_db() -> None:
    if not USE_POSTGRES:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    id_type = "BIGSERIAL PRIMARY KEY" if USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    ref_type = "BIGINT" if USE_POSTGRES else "INTEGER"
    with connect() as db:
        db.executescript(
            f"""
            {'-- PostgreSQL schema' if USE_POSTGRES else 'PRAGMA journal_mode = WAL;'}
            CREATE TABLE IF NOT EXISTS users (
                id {id_type},
                email TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee',
                created_at TEXT NOT NULL,
                employer_id {ref_type} REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_id_hash TEXT PRIMARY KEY,
                user_id {ref_type} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profiles (
                user_id {ref_type} PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                hourly_rate REAL NOT NULL DEFAULT 32.0,
                net_percent REAL NOT NULL DEFAULT 75.0
            );
            CREATE TABLE IF NOT EXISTS shifts (
                id {id_type},
                user_id {ref_type} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                start_at TEXT NOT NULL,
                end_at TEXT NOT NULL,
                role TEXT NOT NULL,
                place TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS shifts_by_user_date ON shifts(user_id, start_at);
            CREATE TABLE IF NOT EXISTS time_off (
                id {id_type},
                user_id {ref_type} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                kind TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS time_off_by_user_date ON time_off(user_id, start_date);
            CREATE TABLE IF NOT EXISTS pay_records (
                user_id {ref_type} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                month TEXT NOT NULL,
                actual_net REAL NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, month)
            );
            """
        )
        if USE_POSTGRES:
            db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS employer_id BIGINT REFERENCES users(id) ON DELETE CASCADE")
            db.execute("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS net_percent REAL NOT NULL DEFAULT 75.0")
        else:
            user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
            profile_columns = {row[1] for row in db.execute("PRAGMA table_info(profiles)").fetchall()}
            if "employer_id" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN employer_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
            if "net_percent" not in profile_columns:
                db.execute("ALTER TABLE profiles ADD COLUMN net_percent REAL NOT NULL DEFAULT 75.0")
        db.execute("UPDATE users SET role = 'employer' WHERE employer_id IS NULL AND role = 'worker'")


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${b64url(salt)}${b64url(digest)}"


def check_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = password_hash(password, unb64url(salt_text)).split("$", 3)[3]
        return hmac.compare_digest(actual, digest_text)
    except (ValueError, TypeError):
        return False


def user_json(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "role": row["role"],
        "employer_id": row["employer_id"],
    }


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "ZmianaAPI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Do not log request bodies, passwords, or authorization headers.
        print(f"{self.log_date_time_string()} {self.client_address[0]} {fmt % args}")

    def send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "Nieprawidłowa długość żądania.")
        if size < 0 or size > 1_000_000:
            raise ApiError(413, "Żądanie jest za duże.")
        try:
            value = json.loads(self.rfile.read(size) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "Nieprawidłowy JSON.")
        if not isinstance(value, dict):
            raise ApiError(400, "Dane muszą być obiektem JSON.")
        return value

    def dispatch(self) -> None:
        try:
            path = urlparse(self.path).path.rstrip("/") or "/"
            if self.command == "GET" and path == "/health":
                self.send_json(200, {"ok": True, "service": "zmiana"})
                return
            if self.command == "POST" and path == "/auth/register":
                self.register()
                return
            if self.command == "POST" and path == "/auth/login":
                self.login()
                return
            if self.command == "GET" and path == "/auth/me":
                user = self.require_user()
                self.send_json(200, {"user": user})
                return
            if self.command == "POST" and path == "/auth/logout":
                self.logout()
                return

            user = self.require_user()
            if self.command == "GET" and path == "/api/profile":
                self.get_profile(user, self.query_user_id())
            elif self.command == "PATCH" and path == "/api/profile":
                self.update_profile(user, self.query_user_id())
            elif self.command == "GET" and path == "/api/team":
                self.list_team(user)
            elif self.command == "POST" and path == "/api/team":
                self.create_employee(user)
            elif self.command == "GET" and path == "/api/payroll":
                self.list_payroll(user)
            elif self.command == "POST" and path == "/api/payroll":
                self.save_payroll(user)
            elif self.command == "GET" and path == "/api/shifts":
                self.list_shifts(user)
            elif self.command == "POST" and path == "/api/shifts":
                self.create_shift(user)
            elif self.command == "GET" and path == "/api/time-off":
                self.list_time_off(user)
            elif self.command == "POST" and path == "/api/time-off":
                self.create_time_off(user["id"])
            elif path.startswith("/api/shifts/") and self.command == "DELETE":
                self.delete_shift(user, path)
            elif path.startswith("/api/time-off/") and path.endswith("/cancel") and self.command == "POST":
                self.cancel_time_off(user["id"], path)
            elif path.startswith("/api/time-off/") and path.endswith("/review") and self.command == "POST":
                self.review_time_off(user, path)
            else:
                raise ApiError(404, "Nie znaleziono endpointu.")
        except ApiError as err:
            self.send_json(err.status, {"error": err.message})
        except Exception as err:
            if isinstance(err, sqlite3.IntegrityError) or getattr(err, "sqlstate", None) == "23505":
                self.send_json(409, {"error": "Konto z tym adresem e-mail już istnieje."})
            elif isinstance(err, (BrokenPipeError, ConnectionResetError)):
                return
            else:
                self.send_json(500, {"error": "Wewnętrzny błąd serwera."})

    def do_GET(self) -> None:
        self.dispatch()

    def do_POST(self) -> None:
        self.dispatch()

    def do_PATCH(self) -> None:
        self.dispatch()

    def do_DELETE(self) -> None:
        self.dispatch()

    def require_user(self) -> dict[str, Any]:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ApiError(401, "Zaloguj się, aby kontynuować.")
        pieces = auth[7:].split(".")
        if len(pieces) != 3:
            raise ApiError(401, "Sesja jest nieprawidłowa.")
        unsigned = ".".join(pieces[:2]).encode("ascii", errors="ignore")
        signature = hmac.new(SECRET, unsigned, hashlib.sha256).digest()
        try:
            if not hmac.compare_digest(signature, unb64url(pieces[2])):
                raise ApiError(401, "Sesja jest nieprawidłowa.")
            payload = json.loads(unb64url(pieces[1]))
            user_id = int(payload["sub"])
            token_id = str(payload["jti"])
            expires = int(payload["exp"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            raise ApiError(401, "Sesja jest nieprawidłowa.")
        if expires < int(time.time()):
            raise ApiError(401, "Sesja wygasła. Zaloguj się ponownie.")
        with connect() as db:
            session = db.execute(
                "SELECT 1 FROM sessions WHERE token_id_hash = ? AND user_id = ? AND expires_at >= ?",
                (hashlib.sha256(token_id.encode()).hexdigest(), user_id, int(time.time())),
            ).fetchone()
            row = db.execute(
                "SELECT id, email, display_name, role, employer_id FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if session is None or row is None:
            raise ApiError(401, "Sesja wygasła. Zaloguj się ponownie.")
        return user_json(row)

    def make_session(self, user_id: int) -> str:
        now = int(time.time())
        token_id = secrets.token_urlsafe(24)
        payload = {"sub": user_id, "iat": now, "exp": now + TOKEN_LIFETIME, "jti": token_id}
        header = b64url(b'{"alg":"HS256","typ":"JWT"}')
        body = b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header}.{body}".encode("ascii")
        signature = b64url(hmac.new(SECRET, signing_input, hashlib.sha256).digest())
        with connect() as db:
            db.execute(
                "INSERT INTO sessions(token_id_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hashlib.sha256(token_id.encode()).hexdigest(), user_id, now + TOKEN_LIFETIME),
            )
        return f"{header}.{body}.{signature}"

    def auth_response(self, user: dict[str, Any]) -> None:
        self.send_json(200, {"access_token": self.make_session(user["id"]), "user": user})

    def register(self) -> None:
        data = self.read_json()
        expected_code = os.environ.get("ZM_EMPLOYER_CODE", "")
        supplied_code = str(data.get("employer_code", ""))
        if not expected_code or not hmac.compare_digest(expected_code, supplied_code):
            raise ApiError(403, "Kod zatrudniającego jest nieprawidłowy.")
        email = str(data.get("email", "")).strip().lower()
        name = str(data.get("display_name", "")).strip()
        password = str(data.get("password", ""))
        if "@" not in email or len(email) > 254:
            raise ApiError(400, "Podaj prawidłowy adres e-mail.")
        if not name or len(name) > 100:
            raise ApiError(400, "Podaj imię lub nazwę użytkownika.")
        if len(password) < 8 or len(password) > 256:
            raise ApiError(400, "Hasło musi mieć od 8 do 256 znaków.")
        with connect() as db:
            cur = db.execute(
                "INSERT INTO users(email, display_name, password_hash, role, created_at) VALUES (?, ?, ?, 'employer', ?) RETURNING id",
                (email, name, password_hash(password), iso(utc_now())),
            )
            user_id = int(cur.fetchone()["id"])
            db.execute("INSERT INTO profiles(user_id, hourly_rate) VALUES (?, 32.0)", (user_id,))
            row = db.execute(
                "SELECT id, email, display_name, role, employer_id FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        self.auth_response(user_json(row))

    def login(self) -> None:
        data = self.read_json()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        ip = self.client_address[0]
        now = time.time()
        with login_lock:
            attempts = [t for t in login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
            if len(attempts) >= LOGIN_LIMIT:
                raise ApiError(429, "Za dużo prób logowania. Spróbuj ponownie za kilka minut.")
            attempts.append(now)
            login_attempts[ip] = attempts
        with connect() as db:
            row = db.execute(
                "SELECT id, email, display_name, role, employer_id, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if row is None or not check_password(password, row["password_hash"]):
            raise ApiError(401, "Nieprawidłowy e-mail lub hasło.")
        with login_lock:
            login_attempts.pop(ip, None)
        self.auth_response(user_json(row))

    def logout(self) -> None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            parts = auth[7:].split(".")
            if len(parts) == 3:
                try:
                    token_id = json.loads(unb64url(parts[1])).get("jti")
                    with connect() as db:
                        db.execute(
                            "DELETE FROM sessions WHERE token_id_hash = ?",
                            (hashlib.sha256(str(token_id).encode()).hexdigest(),),
                        )
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass
        self.send_json(200, {"ok": True})

    def query_user_id(self) -> int | None:
        value = parse_qs(urlparse(self.path).query).get("user_id", [None])[0]
        return int(value) if value and value.isdigit() else None

    def employee_ids(self, user: dict[str, Any]) -> list[int]:
        if user["role"] == "employer":
            with connect() as db:
                return [int(row["id"]) for row in db.execute(
                    "SELECT id FROM users WHERE employer_id = ? AND role = 'employee' ORDER BY display_name", (user["id"],)
                ).fetchall()]
        employer_id = user.get("employer_id")
        if employer_id is None:
            return [int(user["id"])]
        with connect() as db:
            return [int(row["id"]) for row in db.execute(
                "SELECT id FROM users WHERE employer_id = ? AND role = 'employee' ORDER BY display_name", (employer_id,)
            ).fetchall()]

    def assert_employee_scope(self, user: dict[str, Any], employee_id: int) -> None:
        if employee_id == user["id"]:
            return
        allowed = self.employee_ids(user) if user["role"] == "employer" else []
        if employee_id not in allowed:
            raise ApiError(403, "Brak dostępu do danych tego pracownika.")

    def get_profile(self, user: dict[str, Any], employee_id: int | None) -> None:
        employee_id = employee_id or int(user["id"])
        self.assert_employee_scope(user, employee_id)
        with connect() as db:
            row = db.execute("SELECT hourly_rate, net_percent FROM profiles WHERE user_id = ?", (employee_id,)).fetchone()
        if row is None:
            raise ApiError(404, "Nie znaleziono profilu.")
        self.send_json(200, {"hourly_rate": row["hourly_rate"], "gross_hourly": row["hourly_rate"], "net_percent": row["net_percent"], "currency": "PLN"})

    def update_profile(self, user: dict[str, Any], employee_id: int | None) -> None:
        employee_id = employee_id or int(user["id"])
        self.assert_employee_scope(user, employee_id)
        data = self.read_json()
        with connect() as db:
            row = db.execute("SELECT hourly_rate, net_percent FROM profiles WHERE user_id = ?", (employee_id,)).fetchone()
            if row is None:
                raise ApiError(404, "Nie znaleziono profilu.")
            try:
                rate = float(data.get("hourly_rate", row["hourly_rate"]))
                percent = float(data.get("net_percent", row["net_percent"]))
            except (TypeError, ValueError):
                raise ApiError(400, "Podaj poprawną stawkę i procent netto.")
            if user["role"] != "employer" and rate != float(row["hourly_rate"]):
                raise ApiError(403, "Stawkę brutto ustala osoba zatrudniająca.")
            if not math.isfinite(rate) or not 0 <= rate <= 10000:
                raise ApiError(400, "Stawka brutto musi mieścić się w zakresie 0–10 000 zł.")
            if not math.isfinite(percent) or not 0 <= percent <= 100:
                raise ApiError(400, "Procent szacowanego netto musi wynosić od 0 do 100.")
            db.execute("UPDATE profiles SET hourly_rate = ?, net_percent = ? WHERE user_id = ?", (rate, percent, employee_id))
        self.send_json(200, {"hourly_rate": rate, "gross_hourly": rate, "net_percent": percent, "currency": "PLN"})

    def list_team(self, user: dict[str, Any]) -> None:
        if user["role"] == "employer":
            employer_id = user["id"]
        else:
            employer_id = user.get("employer_id")
        with connect() as db:
            if employer_id is None:
                rows = db.execute("SELECT id, email, display_name, role FROM users WHERE id = ?", (user["id"],)).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, email, display_name, role FROM users WHERE employer_id = ? AND role = 'employee' ORDER BY display_name",
                    (employer_id,),
                ).fetchall()
        self.send_json(200, {"employees": [dict(row) for row in rows]})

    def create_employee(self, user: dict[str, Any]) -> None:
        if user["role"] != "employer":
            raise ApiError(403, "Tylko osoba zatrudniająca może dodawać pracowników.")
        data = self.read_json()
        email = str(data.get("email", "")).strip().lower()
        name = str(data.get("display_name", "")).strip()
        password = str(data.get("password", ""))
        if "@" not in email or len(email) > 254:
            raise ApiError(400, "Podaj prawidłowy adres e-mail pracownika.")
        if not name or len(name) > 100:
            raise ApiError(400, "Podaj imię i nazwisko pracownika.")
        if len(password) < 8 or len(password) > 256:
            raise ApiError(400, "Hasło tymczasowe musi mieć co najmniej 8 znaków.")
        with connect() as db:
            cur = db.execute(
                "INSERT INTO users(email, display_name, password_hash, role, created_at, employer_id) VALUES (?, ?, ?, 'employee', ?, ?) RETURNING id",
                (email, name, password_hash(password), iso(utc_now()), user["id"]),
            )
            employee_id = int(cur.fetchone()["id"])
            db.execute("INSERT INTO profiles(user_id, hourly_rate, net_percent) VALUES (?, 32.0, 75.0)", (employee_id,))
        self.send_json(201, {"employee": {"id": employee_id, "email": email, "display_name": name, "role": "employee"}})

    def list_payroll(self, user: dict[str, Any]) -> None:
        month = parse_month(parse_qs(urlparse(self.path).query).get("month", [""])[0])
        ids = self.employee_ids(user) if user["role"] == "employer" else [int(user["id"])]
        if not ids:
            self.send_json(200, {"records": []})
            return
        marks = ",".join("?" for _ in ids)
        with connect() as db:
            rows = db.execute(
                f"SELECT p.user_id, u.display_name, p.month, p.actual_net FROM pay_records p JOIN users u ON u.id = p.user_id WHERE p.month = ? AND p.user_id IN ({marks}) ORDER BY u.display_name",
                (month, *ids),
            ).fetchall()
        self.send_json(200, {"records": [dict(row) for row in rows]})

    def save_payroll(self, user: dict[str, Any]) -> None:
        data = self.read_json()
        employee_id = int(data.get("user_id", user["id"]))
        self.assert_employee_scope(user, employee_id)
        month = parse_month(str(data.get("month", "")))
        try:
            amount = float(data.get("actual_net"))
        except (TypeError, ValueError):
            raise ApiError(400, "Podaj kwotę otrzymaną na rękę.")
        if not math.isfinite(amount) or not 0 <= amount <= 1_000_000:
            raise ApiError(400, "Kwota musi wynosić od 0 do 1 000 000 zł.")
        with connect() as db:
            db.execute(
                "INSERT INTO pay_records(user_id, month, actual_net, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, month) DO UPDATE SET actual_net = excluded.actual_net, updated_at = excluded.updated_at",
                (employee_id, month, amount, iso(utc_now())),
            )
        self.send_json(200, {"user_id": employee_id, "month": month, "actual_net": amount})

    def list_shifts(self, user: dict[str, Any]) -> None:
        ids = self.employee_ids(user) if user["role"] == "employer" or user.get("employer_id") is not None else [int(user["id"])]
        if not ids:
            self.send_json(200, {"shifts": []})
            return
        marks = ",".join("?" for _ in ids)
        with connect() as db:
            rows = db.execute(
                f"SELECT s.id, s.user_id AS employee_id, u.display_name AS employee_name, s.start_at, s.end_at, s.role, s.place, s.notes FROM shifts s JOIN users u ON u.id = s.user_id WHERE s.user_id IN ({marks}) ORDER BY s.start_at",
                tuple(ids),
            ).fetchall()
        self.send_json(200, {"shifts": [dict(row) for row in rows]})

    def create_shift(self, user: dict[str, Any]) -> None:
        data = self.read_json()
        start = parse_datetime(data.get("start_at"), "Początek zmiany")
        end = parse_datetime(data.get("end_at"), "Koniec zmiany")
        if end <= start or (end - start).total_seconds() > 24 * 60 * 60:
            raise ApiError(400, "Koniec zmiany musi być później niż początek i nie dalej niż 24 godziny.")
        role = str(data.get("role", "")).strip()
        if not role or len(role) > 120:
            raise ApiError(400, "Podaj nazwę zmiany (maksymalnie 120 znaków).")
        place = str(data.get("place", "")).strip()[:160]
        notes = str(data.get("notes", "")).strip()[:1000]
        employee_id = int(data.get("employee_id", user["id"]))
        self.assert_employee_scope(user, employee_id)
        if user["role"] != "employer" and employee_id != user["id"]:
            raise ApiError(403, "Nie możesz przypisać zmiany innej osobie.")
        with connect() as db:
            cur = db.execute(
                "INSERT INTO shifts(user_id, start_at, end_at, role, place, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
                (employee_id, iso(start), iso(end), role, place, notes, iso(utc_now())),
            )
            shift_id = int(cur.fetchone()["id"])
            row = db.execute(
                "SELECT s.id, s.user_id AS employee_id, u.display_name AS employee_name, s.start_at, s.end_at, s.role, s.place, s.notes FROM shifts s JOIN users u ON u.id = s.user_id WHERE s.id = ?", (shift_id,)
            ).fetchone()
        self.send_json(201, {"shift": dict(row)})

    def delete_shift(self, user: dict[str, Any], path: str) -> None:
        shift_id = path.removeprefix("/api/shifts/")
        if not shift_id.isdigit():
            raise ApiError(404, "Nie znaleziono zmiany.")
        with connect() as db:
            shift = db.execute("SELECT user_id FROM shifts WHERE id = ?", (int(shift_id),)).fetchone()
            if shift is None:
                raise ApiError(404, "Nie znaleziono zmiany.")
            self.assert_employee_scope(user, int(shift["user_id"]))
            cur = db.execute("DELETE FROM shifts WHERE id = ?", (int(shift_id),))
        if cur.rowcount == 0:
            raise ApiError(404, "Nie znaleziono zmiany.")
        self.send_json(200, {"ok": True})

    def list_time_off(self, user: dict[str, Any]) -> None:
        ids = self.employee_ids(user) if user["role"] == "employer" else [int(user["id"])]
        if not ids:
            self.send_json(200, {"requests": []})
            return
        marks = ",".join("?" for _ in ids)
        with connect() as db:
            rows = db.execute(
                f"SELECT t.id, t.user_id, u.display_name, t.start_date, t.end_date, t.kind, t.note, t.status, t.created_at FROM time_off t JOIN users u ON u.id = t.user_id WHERE t.user_id IN ({marks}) ORDER BY t.start_date DESC",
                tuple(ids),
            ).fetchall()
        self.send_json(200, {"requests": [dict(row) for row in rows]})

    def review_time_off(self, user: dict[str, Any], path: str) -> None:
        if user["role"] != "employer":
            raise ApiError(403, "Tylko osoba zatrudniająca może rozpatrywać wnioski.")
        request_id = path.removeprefix("/api/time-off/").removesuffix("/review")
        status = str(self.read_json().get("status", ""))
        if not request_id.isdigit() or status not in ("approved", "rejected"):
            raise ApiError(400, "Nieprawidłowa decyzja.")
        with connect() as db:
            row = db.execute("SELECT user_id FROM time_off WHERE id = ?", (int(request_id),)).fetchone()
            if row is None:
                raise ApiError(404, "Nie znaleziono prośby.")
            self.assert_employee_scope(user, int(row["user_id"]))
            cur = db.execute("UPDATE time_off SET status = ? WHERE id = ? AND status = 'pending'", (status, int(request_id)))
        if cur.rowcount == 0:
            raise ApiError(409, "Ta prośba została już rozpatrzona.")
        self.send_json(200, {"ok": True, "status": status})

    def create_time_off(self, user_id: int) -> None:
        data = self.read_json()
        start = parse_date(data.get("start_date"), "Data początkowa")
        end = parse_date(data.get("end_date"), "Data końcowa")
        if end < start or (end - start).days > 366:
            raise ApiError(400, "Zakres dat jest nieprawidłowy.")
        kind = str(data.get("kind", "")).strip()
        if not kind or len(kind) > 100:
            raise ApiError(400, "Wybierz rodzaj wolnego.")
        note = str(data.get("note", "")).strip()[:1000]
        with connect() as db:
            cur = db.execute(
                "INSERT INTO time_off(user_id, start_date, end_date, kind, note, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?) RETURNING id",
                (user_id, start.isoformat(), end.isoformat(), kind, note, iso(utc_now())),
            )
            row = db.execute(
                "SELECT id, start_date, end_date, kind, note, status, created_at FROM time_off WHERE id = ?",
                (cur.fetchone()["id"],),
            ).fetchone()
        self.send_json(201, {"request": dict(row)})

    def cancel_time_off(self, user_id: int, path: str) -> None:
        request_id = path.removeprefix("/api/time-off/").removesuffix("/cancel")
        if not request_id.isdigit():
            raise ApiError(404, "Nie znaleziono prośby.")
        with connect() as db:
            cur = db.execute(
                "DELETE FROM time_off WHERE id = ? AND user_id = ? AND status = 'pending'",
                (int(request_id), user_id),
            )
        if cur.rowcount == 0:
            raise ApiError(404, "Nie znaleziono oczekującej prośby.")
        self.send_json(200, {"ok": True})


def parse_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ApiError(400, f"{label}: podaj datę i godzinę.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(400, f"{label}: nieprawidłowy format daty.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_month(value: str) -> str:
    if not value:
        return utc_now().strftime("%Y-%m")
    try:
        parsed = datetime.strptime(value, "%Y-%m")
        return parsed.strftime("%Y-%m")
    except (TypeError, ValueError):
        raise ApiError(400, "Miesiąc musi mieć format RRRR-MM.")


def parse_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise ApiError(400, f"{label}: podaj datę.")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ApiError(400, f"{label}: nieprawidłowy format daty.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lokalny serwer danych aplikacji Zmiana")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"), help="Domyślnie tylko ten komputer")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("UWAGA: serwer HTTP bez TLS nie jest przeznaczony do publicznego Internetu.")
    initialize_db()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"Zmiana API działa pod http://{args.host}:{args.port}")
    print(f"Baza danych: {'PostgreSQL' if USE_POSTGRES else DB_PATH}")
    print("Zatrzymaj serwer klawiszami Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nZamykanie serwera…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
