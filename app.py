"""Pocket Vuln Lab: intentionally vulnerable, synthetic-data classroom app.

Run with Python 3.10+; no third-party dependencies. See README.md.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from http.cookies import SimpleCookie, CookieError
import json
import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
import argparse
import ipaddress
import webbrowser
from pathlib import Path


DEMO_KEY = 'pvlab_DEMO_ONLY_not_a_real_secret'


class Lab:
    def __init__(self):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, salt TEXT, digest TEXT)')
        self.sessions = {}
        self.failures = {}
        for uid, name, role in [(1, 'alice', 'student'), (2, 'bob', 'student'), (3, 'admin', 'admin')]:
            password = name + '123!'
            salt = secrets.token_hex(16)
            digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 150_000).hex()
            self.db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)', (uid, name, password, role, salt, digest))
        self.db.commit()

    def close(self):
        self.db.close()

    def reset(self):
        with self.lock:
            self.sessions.clear()
            self.failures.clear()
        return 200, {'reset': True}, {'Set-Cookie': 'pvlab_fixed=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/'}

    def login(self, data, client='local'):
        mode = data.get('mode', 'vulnerable')
        username, password = data.get('username', ''), data.get('password', '')
        if mode not in ('vulnerable', 'fixed') or not isinstance(username, str) or not isinstance(password, str):
            return 400, {'error': 'Invalid login fields.'}, {}
        if max(len(username), len(password)) > 512:
            return 400, {'error': 'Use at most 512 characters per field.'}, {}
        try:
            username.encode('utf-8')
            password.encode('utf-8')
        except UnicodeEncodeError:
            return 400, {'error': 'Login fields must contain valid Unicode text.'}, {}
        with self.lock:
            recent = [t for t in self.failures.get(client, []) if time.monotonic() - t < 60]
            self.failures[client] = recent
            if mode == 'fixed' and len(recent) >= 5:
                return 429, {'error': 'Too many attempts. Wait 60 seconds or reset the lab.'}, {'Retry-After': '60'}
            if mode == 'vulnerable':
                # INTENTIONAL CWE-89: a real SQL injection, not a canned payload check.
                query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
                try:
                    user = self.db.execute(query).fetchone()
                except sqlite3.Error as exc:
                    return 400, {'error': str(exc), 'query': query}, {}
            else:
                user = self.db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                salt = user['salt'] if user else 'constant-dummy-salt-for-unknown-user'
                digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 150_000).hex()
                if not hmac.compare_digest(digest, user['digest'] if user else '0' * 64):
                    user = None
            if not user:
                if mode == 'vulnerable':
                    exists = self.db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
                    return (401 if exists else 404), {'error': 'Wrong password for this account.' if exists else 'That username does not exist.', 'query': query}, {}
                recent.append(time.monotonic())
                return 401, {'error': 'Invalid username or password.'}, {}
            if mode == 'fixed':
                self.failures.pop(client, None)
            identity = {key: user[key] for key in ('id', 'username', 'role')}
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {'user': identity, 'mode': mode}
            if mode == 'vulnerable':
                return 200, {'user': identity, 'token': token, 'query': query}, {}
            return 200, {'user': identity, 'session_storage': 'HttpOnly cookie'}, {
                'Set-Cookie': f'pvlab_fixed={token}; HttpOnly; SameSite=Strict; Path=/'}


class Handler(BaseHTTPRequestHandler):
    server_version = 'PocketVulnLab/1.0'

    def log_message(self, fmt, *args):
        # Do not log request bodies or demo credentials.
        pass

    def send_json(self, status, body, headers=None):
        payload = json.dumps(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def allowed_request(self, write=False):
        try:
            host = urlsplit('http://' + self.headers.get('Host', '')).hostname
            allowed = host == 'localhost' or (host is not None and ipaddress.ip_address(host).is_private)
        except ValueError:
            allowed = False
        if not allowed:
            self.send_json(403, {'error': 'Use localhost or a private LAN address.'})
            return False
        if write:
            origin = self.headers.get('Origin')
            expected = 'http://' + self.headers.get('Host', '')
            if self.headers.get('X-Lab-Request') != 'pocket-vuln' or (origin and origin != expected):
                self.send_json(403, {'error': 'Lab requests must be same-origin with X-Lab-Request: pocket-vuln.'})
                return False
        return True

    def do_POST(self):
        if not self.allowed_request(write=True):
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if size < 1 or size > 16_384:
                return self.send_json(413, {'error': 'Request must be 1-16384 bytes.'})
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError('Expected object')
        except (ValueError, UnicodeError):
            return self.send_json(400, {'error': 'Expected a JSON object.'})
        if urlsplit(self.path).path == '/api/login':
            return self.send_json(*self.server.lab.login(data, self.client_address[0]))
        if urlsplit(self.path).path == '/api/reset':
            return self.send_json(*self.server.lab.reset())
        return self.send_json(404, {'error': 'not_found'})

    def session_user(self, mode):
        token = ''
        if mode == 'vulnerable':
            auth = self.headers.get('Authorization', '')
            token = auth[7:] if auth.startswith('Bearer ') else ''
        elif mode == 'fixed':
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get('Cookie', ''))
                token = cookie['pvlab_fixed'].value if 'pvlab_fixed' in cookie else ''
            except CookieError:
                return None
        with self.server.lab.lock:
            session = self.server.lab.sessions.get(token)
            return session['user'] if session and session['mode'] == mode else None

    def do_GET(self):
        if not self.allowed_request():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        mode = parse_qs(parsed.query).get('mode', ['vulnerable'])[0]
        if mode not in ('vulnerable', 'fixed'):
            return self.send_json(400, {'error': 'Unknown mode.'})
        if path == '/api/config':
            config = {'app': 'Pocket Vuln Lab', 'demo_only': True, 'api_base': '/api', 'transport': 'HTTP - NOT encrypted; fixed mode does not add TLS.'}
            if mode == 'vulnerable':
                config.update({'debug': True, 'backup_api_key': DEMO_KEY,
                    'database_url': 'postgresql://demo_reader:classroom_only@database.invalid:5432/pocket_demo'})
            return self.send_json(200, config)
        if path == '/api/backup':
            user = self.session_user(mode)
            key = self.headers.get('X-Demo-Key', '')
            allowed = (mode == 'vulnerable' and key.isascii() and hmac.compare_digest(key, DEMO_KEY)) or (mode == 'fixed' and user and user['role'] == 'admin')
            if not allowed:
                return self.send_json(403, {'error': 'Backup access denied.'})
            with self.server.lab.lock:
                records = [dict(row) for row in self.server.lab.db.execute('SELECT id, username, role FROM users')]
            return self.send_json(200, {'demo_only': True, 'records': records})
        if path == '/api/session' or path.startswith('/api/profiles/'):
            user = self.session_user(mode)
            if not user:
                return self.send_json(401, {'error': 'Sign in first.'})
            if path == '/api/session':
                return self.send_json(200, {'user': user})
            try:
                uid = int(path.rsplit('/', 1)[1])
            except ValueError:
                return self.send_json(400, {'error': 'Profile ID must be a number.'})
            if not -(2 ** 63) <= uid < 2 ** 63:
                return self.send_json(400, {'error': 'Profile ID is outside the supported integer range.'})
            if mode == 'fixed' and uid != user['id']:
                return self.send_json(403, {'error': 'You can only read your own profile.'})
            with self.server.lab.lock:
                row = self.server.lab.db.execute('SELECT id, username, role FROM users WHERE id = ?', (uid,)).fetchone()
            if not row:
                return self.send_json(404, {'error': 'Profile not found.'})
            profile = dict(row)
            profile['email'] = profile['username'] + '@classroom.invalid'
            profile['private_note'] = '[DEMO] ' + {1: 'Alice is planning a surprise astronomy meetup.', 2: 'Bob keeps the pretend club budget in locker 42.', 3: 'Admin test note; no real systems are connected.'}[uid]
            return self.send_json(200, {'profile': profile, 'requested_by': user['username']})
        if path == '/api/health':
            return self.send_json(200, {'name': 'Pocket Vuln Lab', 'demo_only': True})
        static_routes = {'/': ('index.html', 'text/html'), '/style.css': ('style.css', 'text/css'),
            '/app.js': ('app.js', 'text/javascript'), '/manifest.webmanifest': ('manifest.webmanifest', 'application/json'),
            '/icon.svg': ('icon.svg', 'image/svg+xml'), '/favicon.ico': ('icon.svg', 'image/svg+xml')}
        if path in static_routes:
            filename, mime = static_routes[path]
            target = Path(__file__).resolve().parent / 'static' / filename
            if not target.is_file():
                return self.send_json(404, {'error': 'Asset not found.'})
            payload = target.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', mime + '; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            return self.wfile.write(payload)
        self.send_json(404, {'error': 'not_found'})


def make_server(host='127.0.0.1', port=8765):
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.lab = Lab()
    return server


def main():
    parser = argparse.ArgumentParser(description='Pocket Vuln Lab. Default: http://127.0.0.1:8765 (local only).')
    parser.add_argument('--port', type=int, default=8765, help='HTTP port (default: 8765)')
    parser.add_argument('--lan', action='store_true', help='Opt in to listening on your classroom LAN (0.0.0.0)')
    parser.add_argument('--open', action='store_true', help='Open the app in your browser')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    host = '0.0.0.0' if args.lan else '127.0.0.1'
    try:
        server = make_server(host, args.port)
    except OSError as exc:
        parser.exit(1, f'Cannot start server: {exc}. Try --port 8766.\n')
    url = f'http://127.0.0.1:{args.port}'
    print(f'Pocket Vuln Lab -> {url}', flush=True)
    print('Synthetic accounts only. Ctrl+C stops the lab.', flush=True)
    if args.lan:
        print(f'LAN enabled. On your phone, open http://YOUR-PC-PRIVATE-IP:{args.port}', flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.lab.close()


if __name__ == '__main__':
    main()
