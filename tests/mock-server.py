#!/usr/bin/env python3
"""
Intentionally vulnerable LAB server for testing bola-scanner.sh.

DO NOT deploy this anywhere. It exists so you can prove the scanner
works, safely, on your own machine, before pointing it at your own app.

Run:
    python3 tests/mock-server.py          # listens on 127.0.0.1:8000

Test accounts (Bearer tokens):
    alice-token   owns ID 1001, email alice@lab.local, role: user
    bob-token     owns ID 1002, email bob@lab.local,   role: user
    admin-token   role: admin

Routes:
    VULNERABLE (default) — no ownership / role check, only "is logged in":
        GET /api/v1/users/{id}/profile
        GET /api/v1/admin/users

    FIXED — same routes under /secure, with ownership + role checks:
        GET /secure/api/v1/users/{id}/profile
        GET /secure/api/v1/admin/users

Expected scanner result:
    Against the vulnerable routes -> BOLA + vertical BAC findings
    Against the /secure routes    -> SECURE
"""
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    "alice-token": {"id": 1001, "name": "Alice Lab", "email": "alice@lab.local", "role": "user"},
    "bob-token":   {"id": 1002, "name": "Bob Lab",   "email": "bob@lab.local",   "role": "user"},
    "admin-token": {"id": 1,    "name": "Admin Lab", "email": "admin@lab.local", "role": "admin"},
}
PROFILES = {u["id"]: u for u in USERS.values()}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the lab output clean
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _caller(self):
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        return USERS.get(token)

    def do_GET(self):
        secure = self.path.startswith("/secure")
        path = self.path.removeprefix("/secure")

        m = re.fullmatch(r"/api/v1/users/(\d+)/profile", path)
        if m:
            caller = self._caller()
            if caller is None:
                return self._send(401, {"error": "unauthenticated"})
            profile = PROFILES.get(int(m.group(1)))
            if profile is None:
                return self._send(404, {"error": "not found"})
            # THE BUG (vulnerable route): any logged-in user can read any profile.
            # THE FIX (secure route): the object owner must be the caller.
            if secure and caller["id"] != profile["id"] and caller["role"] != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, profile)

        if path == "/api/v1/admin/users":
            caller = self._caller()
            if caller is None:
                return self._send(401, {"error": "unauthenticated"})
            # THE BUG: role is never checked.  THE FIX: require admin.
            if secure and caller["role"] != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"users": list(PROFILES.values())})

        return self._send(404, {"error": "not found"})

    do_HEAD = do_GET


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
