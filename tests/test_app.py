"""Black-box HTTP checks for the classroom lab (standard library only)."""
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import threading
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class LabHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = None
        if importlib.util.find_spec('app') is not None:
            import app
            cls.server = app.make_server('127.0.0.1', 0)
            cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
            cls.worker.start()
            cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
            cls.server.lab.close()
            cls.worker.join(timeout=3)

    def request(self, path, body=None, headers=None):
        self.assertIsNotNone(self.server, 'The local lab server has not been implemented')
        h = {'Content-Type': 'application/json', 'X-Lab-Request': 'pocket-vuln'}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read().decode()
            content = json.loads(raw) if 'application/json' in response.headers.get('Content-Type', '') else raw
            return response.status, content, dict(response.headers)

    def test_sql_injection_authenticates_without_admin_password(self):
        status, body, _ = self.request('/api/login', {
            'mode': 'vulnerable', 'username': "admin' -- ", 'password': 'wrong'})
        self.assertEqual(status, 200)
        self.assertEqual(body['user']['role'], 'admin')
        self.assertIn("admin' -- ", body['query'])
        self.assertTrue(body['token'])

    def test_fixed_login_rejects_the_same_injection(self):
        status, body, _ = self.request('/api/login', {
            'mode': 'fixed', 'username': "admin' -- ", 'password': 'wrong'})
        self.assertEqual(status, 401)
        self.assertEqual(body['error'], 'Invalid username or password.')
        self.assertNotIn('query', body)

    def test_fixed_login_uses_httponly_session_instead_of_json_token(self):
        status, body, headers = self.request('/api/login', {
            'mode': 'fixed', 'username': 'alice', 'password': 'alice123!'})
        self.assertEqual(status, 200)
        self.assertEqual(body['user']['username'], 'alice')
        self.assertNotIn('token', body)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])

    def test_vulnerable_login_reveals_which_accounts_exist(self):
        first = self.request('/api/login', {'mode': 'vulnerable', 'username': 'alice', 'password': 'bad'})
        second = self.request('/api/login', {'mode': 'vulnerable', 'username': 'nobody', 'password': 'bad'})
        self.assertEqual(first[0], 401)
        self.assertEqual(second[0], 404)
        self.assertNotEqual(first[1]['error'], second[1]['error'])

    def test_fixed_login_hides_accounts_and_limits_retries(self):
        status, _, _ = self.request('/api/reset', {})
        self.assertEqual(status, 200)
        a = self.request('/api/login', {'mode': 'fixed', 'username': 'alice', 'password': 'bad'})
        b = self.request('/api/login', {'mode': 'fixed', 'username': 'nobody', 'password': 'bad'})
        self.assertEqual(a[:2], b[:2])
        for _ in range(3):
            self.assertEqual(self.request('/api/login', {'mode': 'fixed', 'username': 'alice', 'password': 'bad'})[0], 401)
        status, _, headers = self.request('/api/login', {'mode': 'fixed', 'username': 'alice', 'password': 'bad'})
        self.assertEqual(status, 429)
        self.assertIn('Retry-After', headers)
        self.request('/api/reset', {})

    def test_reset_invalidates_existing_sessions(self):
        status, body, _ = self.request('/api/login', {'mode': 'vulnerable', 'username': 'alice', 'password': 'alice123!'})
        self.assertEqual(status, 200)
        token = body['token']
        self.assertIn(token, self.server.lab.sessions)
        self.assertEqual(self.request('/api/reset', {})[0], 200)
        self.assertNotIn(token, self.server.lab.sessions)

    def login_headers(self, mode):
        self.request('/api/reset', {})
        status, body, headers = self.request('/api/login', {'mode': mode, 'username': 'alice', 'password': 'alice123!'})
        self.assertEqual(status, 200)
        return {'Authorization': 'Bearer ' + body['token']} if mode == 'vulnerable' else {'Cookie': headers['Set-Cookie'].split(';')[0]}

    def test_idor_reads_bobs_private_note_as_alice(self):
        headers = self.login_headers('vulnerable')
        status, body, _ = self.request('/api/profiles/2?mode=vulnerable', headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body['profile']['username'], 'bob')
        self.assertIn('DEMO', body['profile']['private_note'])

    def test_fixed_profile_checks_ownership(self):
        headers = self.login_headers('fixed')
        self.assertEqual(self.request('/api/profiles/2?mode=fixed', headers=headers)[0], 403)
        status, body, _ = self.request('/api/profiles/1?mode=fixed', headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body['profile']['username'], 'alice')
        self.assertEqual(self.request('/api/profiles/1?mode=fixed')[0], 401)

    def test_stolen_browser_token_replays_only_in_vulnerable_mode(self):
        headers = self.login_headers('vulnerable')
        status, body, _ = self.request('/api/session?mode=vulnerable', headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(body['user']['username'], 'alice')
        self.assertEqual(self.request('/api/session?mode=fixed', headers=headers)[0], 401)
        self.request('/api/reset', {})
        self.assertEqual(self.request('/api/session?mode=vulnerable', headers=headers)[0], 401)

    def test_leaked_connection_key_unlocks_demo_backup(self):
        status, config, _ = self.request('/api/config?mode=vulnerable')
        self.assertEqual(status, 200)
        self.assertIn('database.invalid', config['database_url'])
        self.assertTrue(config['demo_only'])
        status, body, _ = self.request('/api/backup?mode=vulnerable', headers={'X-Demo-Key': config['backup_api_key']})
        self.assertEqual(status, 200)
        self.assertEqual(len(body['records']), 3)
        self.assertTrue(body['demo_only'])
        self.assertEqual(self.request('/api/backup?mode=vulnerable')[0], 403)

    def test_fixed_configuration_does_not_publish_secrets(self):
        status, config, _ = self.request('/api/config?mode=fixed')
        self.assertEqual(status, 200)
        self.assertNotIn('backup_api_key', config)
        self.assertNotIn('database_url', config)
        leaked_key = self.request('/api/config?mode=vulnerable')[1]['backup_api_key']
        self.assertEqual(self.request('/api/backup?mode=fixed', headers={'X-Demo-Key': leaked_key})[0], 403)
        self.assertEqual(self.request('/api/config?mode=typo')[0], 400)

    def test_fixed_admin_cookie_authorizes_backup_without_demo_key(self):
        self.request('/api/reset', {})
        status, body, headers = self.request('/api/login', {
            'mode': 'fixed', 'username': 'admin', 'password': 'admin123!'})
        self.assertEqual(status, 200)
        self.assertEqual(body['user']['role'], 'admin')
        cookie = headers['Set-Cookie'].split(';')[0]
        status, body, _ = self.request('/api/backup?mode=fixed', headers={'Cookie': cookie})
        self.assertEqual(status, 200)
        self.assertEqual(len(body['records']), 3)
        self.assertTrue(body['demo_only'])

    def test_other_origins_cannot_reset_the_lab(self):
        self.assertEqual(self.request('/api/reset', {}, {'Origin': 'https://outside.invalid'})[0], 403)
        self.assertEqual(self.request('/api/reset', {}, {'X-Lab-Request': ''})[0], 403)

    def test_untrusted_host_header_is_blocked(self):
        self.assertEqual(self.request('/api/health', headers={'Host': 'outside.invalid'})[0], 403)

    def assert_client_error_and_healthy(self, path, body=None, headers=None):
        try:
            status, response, response_headers = self.request(path, body, headers)
        except http.client.RemoteDisconnected:
            self.fail('Invalid input disconnected instead of returning a JSON 4xx response.')
        finally:
            self.assertEqual(self.request('/api/health')[0], 200)
        self.assertGreaterEqual(status, 400)
        self.assertLess(status, 500)
        self.assertIn('application/json', response_headers['Content-Type'])
        self.assertIsInstance(response, dict)
        self.assertIsInstance(response.get('error'), str)
        self.assertTrue(response['error'])
        return status

    def test_login_rejects_unpaired_surrogates_as_invalid_input(self):
        self.request('/api/reset', {})
        for mode in ('vulnerable', 'fixed'):
            for field in ('username', 'password'):
                for surrogate in ('\ud800', '\udfff'):
                    with self.subTest(mode=mode, field=field, surrogate=repr(surrogate)):
                        body = {'mode': mode, 'username': 'alice', 'password': 'alice123!'}
                        body[field] = surrogate
                        self.assertEqual(self.assert_client_error_and_healthy('/api/login', body), 400)

    def test_non_ascii_demo_key_is_denied_without_disconnecting(self):
        for mode in ('vulnerable', 'fixed'):
            with self.subTest(mode=mode):
                status = self.assert_client_error_and_healthy(
                    f'/api/backup?mode={mode}', headers={'X-Demo-Key': '\u00e9'})
                self.assertEqual(status, 403)

    def test_profile_ids_outside_sqlite_integer_range_are_invalid(self):
        for mode in ('vulnerable', 'fixed'):
            headers = self.login_headers(mode)
            for uid in ('9223372036854775808', '-9223372036854775809'):
                with self.subTest(mode=mode, uid=uid):
                    status = self.assert_client_error_and_healthy(
                        f'/api/profiles/{uid}?mode={mode}', headers=headers)
                    self.assertEqual(status, 400)
            for uid in ('9223372036854775807', '-9223372036854775808'):
                with self.subTest(mode=mode, boundary=uid):
                    status = self.assert_client_error_and_healthy(
                        f'/api/profiles/{uid}?mode={mode}', headers=headers)
                    self.assertEqual(status, 404 if mode == 'vulnerable' else 403)

    def test_invalid_payloads_are_bounded(self):
        self.assertEqual(self.request('/api/login', [1, 2])[0], 400)
        self.assertEqual(self.request('/api/login', {'username': 'x' * 17000})[0], 413)
        self.assertEqual(self.request('/api/login', {'mode': 'oops'})[0], 400)
        self.assertEqual(self.request('/api/profiles/not-a-number', headers=self.login_headers('vulnerable'))[0], 400)

    def test_cli_defaults_to_loopback_and_lan_is_opt_in(self):
        result = subprocess.run([sys.executable, str(ROOT / 'app.py'), '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--lan', result.stdout)
        self.assertIn('127.0.0.1', result.stdout)

    def test_mobile_app_assets_are_served_without_file_traversal(self):
        status, html, headers = self.request('/')
        self.assertEqual(status, 200)
        self.assertIn('Pocket Vuln Lab', html)
        self.assertIn('name="viewport"', html)
        for path, kind in [('/app.js', 'javascript'), ('/style.css', 'text/css'), ('/manifest.webmanifest', 'json'), ('/icon.svg', 'image/svg')]:
            status, _, headers = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertIn(kind, headers['Content-Type'])
        self.assertEqual(self.request('/../app.py')[0], 404)
        self.assertEqual(self.request('/%2e%2e/app.py')[0], 404)

    def test_health_reports_demo_only_local_service(self):
        status, body, headers = self.request('/api/health')
        self.assertEqual(status, 200)
        self.assertEqual(body['name'], 'Pocket Vuln Lab')
        self.assertTrue(body['demo_only'])
        self.assertEqual(headers['Cache-Control'], 'no-store')


if __name__ == '__main__':
    unittest.main(verbosity=2)
