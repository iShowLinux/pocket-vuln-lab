"""Real Chromium checks. QA dependency: uv run --with playwright tests/browser_checks.py"""
import json
import os
from pathlib import Path
import sys
import threading
import unittest

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app


class BrowserChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.make_server('127.0.0.1', 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.pw = sync_playwright().start()
        options = {'headless': True}
        chrome = Path('C:/Program Files/Google/Chrome/Application/chrome.exe')
        if chrome.exists():
            options['executable_path'] = str(chrome)
        cls.browser = cls.pw.chromium.launch(**options)
        cls.artifacts = ROOT / 'artifacts'
        cls.artifacts.mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.lab.close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.lab.reset()
        self.context = self.browser.new_context(viewport={'width': 1365, 'height': 1000})
        self.page = self.context.new_page()
        self.errors = []
        self.page.on('pageerror', lambda exc: self.errors.append(str(exc)))
        self.page.goto(self.base)

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.errors, [], 'Unexpected JavaScript errors')

    def mode(self, name):
        self.page.get_by_role('button', name=name, exact=True).click()

    def lesson(self, value):
        self.page.locator(f'button[data-lesson="{value}"]').click()

    def test_01_login_and_fixed_comparison(self):
        expect(self.page.get_by_role('heading', name='Walk past the login.')).to_be_visible()
        self.page.get_by_role('button', name='Use injection').click()
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#result')).to_contain_text('admin')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Use injection').click()
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#result')).to_contain_text('401')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')
        expect(self.page.locator('#progress-text')).to_have_text('1 / 6 complete')
        self.page.reload()
        expect(self.page.locator('#progress-text')).to_have_text('1 / 6 complete')
        self.page.screenshot(path=str(self.artifacts / 'desktop.png'), full_page=True)

    def test_02_enumeration_then_rate_limiting(self):
        self.lesson('enumeration')
        self.page.get_by_role('button', name='Run six-attempt probe').click(timeout=2000)
        expect(self.page.locator('#result')).to_contain_text('Accounts are distinguishable')
        expect(self.page.locator('#probe-results tbody tr')).to_have_count(6)
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Run six-attempt probe').click()
        expect(self.page.locator('#result')).to_contain_text('429')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')

    def test_03_idor_denied_only_in_fixed_mode(self):
        self.lesson('idor')
        expect(self.page.get_by_role('button', name='Sign in as Alice')).to_be_visible()
        self.page.get_by_role('button', name='Sign in as Alice').click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
        self.page.locator('#profile-id').fill('2')
        self.page.get_by_role('button', name='Load profile').click()
        expect(self.page.locator('#result')).to_contain_text('locker 42')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Sign in as Alice').click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
        self.page.locator('#profile-id').fill('2')
        self.page.get_by_role('button', name='Load profile').click()
        expect(self.page.locator('#result')).to_contain_text('403')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')

    def test_04_connection_secret_is_really_used(self):
        self.lesson('connections')
        expect(self.page.get_by_role('button', name='Load client config')).to_be_visible()
        self.page.get_by_role('button', name='Load client config').click()
        expect(self.page.locator('#config-output')).to_contain_text('database.invalid')
        self.page.get_by_role('button', name='Request demo backup').click()
        expect(self.page.locator('#result')).to_contain_text('records')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Load client config').click()
        expect(self.page.locator('#config-output')).not_to_contain_text('backup_api_key')
        self.page.get_by_role('button', name='Request demo backup').click()
        expect(self.page.locator('#result')).to_contain_text('403')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')

    def test_05_readable_token_replays_without_cookies(self):
        self.lesson('storage')
        expect(self.page.get_by_role('button', name='Sign in as Alice')).to_be_visible()
        self.page.get_by_role('button', name='Sign in as Alice').click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
        token = self.page.evaluate("localStorage.getItem('pvlab.session')")
        self.assertTrue(token)
        self.page.get_by_role('button', name='Inspect browser storage').click()
        expect(self.page.locator('#storage-output')).to_contain_text(token)
        self.page.get_by_role('button', name='Replay readable token').click()
        expect(self.page.locator('#result')).to_contain_text('200')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Sign in as Alice').click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
        self.assertIsNone(self.page.evaluate("localStorage.getItem('pvlab.session')"))
        self.assertNotIn('pvlab_fixed=', self.page.evaluate('document.cookie'))
        self.assertTrue(next(c for c in self.context.cookies() if c['name'] == 'pvlab_fixed')['httpOnly'])
        self.page.get_by_role('button', name='Inspect browser storage').click()
        self.page.get_by_role('button', name='Replay readable token').click()
        expect(self.page.locator('#result')).to_contain_text('401')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')

    def test_06_xss_executes_only_inside_vulnerable_sandbox(self):
        self.lesson('xss')
        expect(self.page.get_by_role('button', name='Use sample payload')).to_be_visible()
        self.page.get_by_role('button', name='Use sample payload').click()
        payload = self.page.locator('#message').input_value()
        self.page.get_by_role('button', name='Render preview').click()
        expect(self.page.locator('#result')).to_contain_text('Script executed')
        expect(self.page.frame_locator('#xss-frame').locator('body')).to_have_attribute('data-executed', 'yes')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        self.assertEqual(self.page.locator('#xss-frame').get_attribute('sandbox'), 'allow-scripts')
        frame = self.page.locator('#xss-frame').element_handle().content_frame()
        self.assertEqual(frame.evaluate("() => {try {return parent.document.title} catch(e) {return e.name}}"), 'SecurityError')
        self.mode('Fixed')
        self.page.get_by_role('button', name='Use sample payload').click()
        self.page.get_by_role('button', name='Render preview').click()
        expect(self.page.locator('#result')).to_contain_text('Rendered as text')
        expect(self.page.frame_locator('#xss-frame').locator('#preview')).to_have_text(payload)
        expect(self.page.frame_locator('#xss-frame').locator('#preview img')).to_have_count(0)
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')
        self.page.screenshot(path=str(self.artifacts / 'xss-fixed.png'), full_page=True)

    def test_07_mobile_layout_all_lessons_and_touch_targets(self):
        lesson_ids = ['login', 'enumeration', 'idor', 'connections', 'storage', 'xss']
        for width in (320, 390, 768):
            self.page.set_viewport_size({'width': width, 'height': 844})
            for lesson_id in lesson_ids:
                self.page.locator('#lesson-select').select_option(lesson_id)
                self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'Horizontal overflow: {width}px {lesson_id}')
                undersized = self.page.locator('button').evaluate_all("els => els.filter(e => e.getClientRects().length && e.getBoundingClientRect().height < 44).map(e => e.textContent)")
                self.assertEqual(undersized, [], f'Undersized mobile touch targets: {width}px')
        self.page.set_viewport_size({'width': 390, 'height': 844})
        self.page.locator('#lesson-select').select_option('login')
        self.page.get_by_role('button', name='Use injection').click()
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#result')).to_contain_text('admin')
        self.page.screenshot(path=str(self.artifacts / 'mobile.png'), full_page=True)

    def test_08_reset_clears_server_session_and_progress(self):
        self.page.get_by_role('button', name='Use injection').click()
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        token = self.page.evaluate("localStorage.getItem('pvlab.session')")
        self.page.once('dialog', lambda dialog: dialog.accept())
        self.page.get_by_role('button', name='Reset lab & progress').click()
        expect(self.page.locator('#result')).to_contain_text('Lab reset')
        expect(self.page.locator('#progress-text')).to_have_text('0 / 6 complete')
        self.assertIsNone(self.page.evaluate("localStorage.getItem('pvlab.session')"))
        response = self.page.request.get(self.base + '/api/session?mode=vulnerable', headers={'Authorization': 'Bearer ' + token})
        self.assertEqual(response.status, 401)

    def test_09_xss_input_cannot_escape_the_script_serializer(self):
        self.lesson('xss')
        self.mode('Fixed')
        payload = '</script><img src=x onerror="parent.hacked=true">'
        self.page.locator('#message').fill(payload)
        self.page.get_by_role('button', name='Render preview').click()
        expect(self.page.frame_locator('#xss-frame').locator('#preview')).to_have_text(payload)
        self.assertIsNone(self.page.evaluate('window.hacked'))

    def test_10_backup_key_experiment_ignores_retained_admin_cookie(self):
        self.mode('Fixed')
        self.page.locator('#username').fill('admin')
        self.page.locator('#password').fill('admin123!')
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as admin')
        admin_cookie = next(c for c in self.context.cookies() if c['name'] == 'pvlab_fixed')
        self.assertTrue(admin_cookie['httpOnly'])

        self.mode('Vulnerable')
        self.lesson('connections')
        self.page.get_by_role('button', name='Load client config').click()
        expect(self.page.locator('#config-output')).to_contain_text('backup_api_key')
        key = self.page.locator('#backup-key').input_value()
        self.assertTrue(key)
        with self.page.expect_response(lambda r: '/api/backup?mode=vulnerable' in r.url) as vulnerable:
            self.page.get_by_role('button', name='Request demo backup').click()
        self.assertEqual(vulnerable.value.status, 200)
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')

        self.mode('Fixed')
        expect(self.page.locator('#backup-key')).to_have_value(key)
        self.page.get_by_role('button', name='Load client config').click()
        expect(self.page.locator('#config-output')).not_to_contain_text('backup_api_key')
        with self.page.expect_response(lambda r: '/api/backup?mode=fixed' in r.url) as fixed:
            self.page.get_by_role('button', name='Request demo backup').click()
        self.assertEqual(fixed.value.status, 403)
        expect(self.page.locator('#result')).to_contain_text('Backup denied')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')
        for response in (vulnerable.value, fixed.value):
            self.assertNotIn('cookie', response.request.all_headers())
        expect(self.page.locator('#exercise')).to_contain_text('key-only, cookie-free')

        retained_cookie = next(c for c in self.context.cookies() if c['name'] == 'pvlab_fixed')
        self.assertEqual(retained_cookie['value'], admin_cookie['value'])
        session = self.page.request.get(self.base + '/api/session?mode=fixed')
        self.assertEqual(session.status, 200)
        self.assertEqual(session.json()['user']['username'], 'admin')

    def test_11_manual_hint_payload_completes_both_login_evidence_markers(self):
        payload = "admin' --"
        for mode, status in (('Vulnerable', 200), ('Fixed', 401)):
            self.mode(mode)
            self.page.locator('#username').fill(payload)
            self.page.locator('#password').fill('not-the-password')
            with self.page.expect_response(lambda r: '/api/login?' in r.url) as login:
                self.page.get_by_role('button', name='Sign in', exact=True).click()
            self.assertEqual(login.value.status, status)
            self.assertEqual(login.value.request.post_data_json['username'], payload)
            expect(self.page.locator('#result')).to_contain_text(f'HTTP {status}')
        expect(self.page.locator('#evidence-vulnerable')).to_contain_text('Observed')
        expect(self.page.locator('#evidence-fixed')).to_contain_text('Verified')
        expect(self.page.locator('#progress-text')).to_have_text('1 / 6 complete')

    def test_12_all_six_lessons_complete_in_one_continuous_session(self):
        for mode, status in (('Vulnerable', 200), ('Fixed', 401)):
            self.mode(mode)
            self.page.locator('#username').fill("admin' --")
            self.page.locator('#password').fill('not-the-password')
            self.page.get_by_role('button', name='Sign in', exact=True).click()
            expect(self.page.locator('#result')).to_contain_text(f'HTTP {status}')

        self.lesson('enumeration')
        for mode, result in (('Vulnerable', 'Accounts are distinguishable'), ('Fixed', 'HTTP 429')):
            self.mode(mode)
            self.page.get_by_role('button', name='Run six-attempt probe').click()
            expect(self.page.locator('#result')).to_contain_text(result)
        # Use the documented control after throttling, not a hidden test reset.
        self.page.get_by_role('button', name='Clear retry counters').click()
        expect(self.page.locator('#result')).to_contain_text('Retry counters cleared')

        self.lesson('idor')
        for mode, status in (('Vulnerable', 200), ('Fixed', 403)):
            self.mode(mode)
            self.page.get_by_role('button', name='Sign in as Alice').click()
            expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
            self.page.locator('#profile-id').fill('2')
            self.page.get_by_role('button', name='Load profile').click()
            expect(self.page.locator('#result')).to_contain_text(f'HTTP {status}')

        # Carry a real fixed admin cookie into the key-only experiment.
        self.lesson('login')
        self.page.locator('#username').fill('admin')
        self.page.locator('#password').fill('admin123!')
        self.page.get_by_role('button', name='Sign in', exact=True).click()
        expect(self.page.locator('#result')).to_contain_text('Signed in as admin')
        self.lesson('connections')
        for mode, status in (('Vulnerable', 200), ('Fixed', 403)):
            self.mode(mode)
            self.page.get_by_role('button', name='Load client config').click()
            expect(self.page.locator('#result')).to_contain_text('HTTP 200')
            self.page.get_by_role('button', name='Request demo backup').click()
            expect(self.page.locator('#result')).to_contain_text(f'HTTP {status}')

        self.lesson('storage')
        for mode, status in (('Vulnerable', 200), ('Fixed', 401)):
            self.mode(mode)
            self.page.get_by_role('button', name='Sign in as Alice').click()
            expect(self.page.locator('#result')).to_contain_text('Signed in as alice')
            self.page.get_by_role('button', name='Inspect browser storage').click()
            self.page.get_by_role('button', name='Replay readable token').click()
            expect(self.page.locator('#result')).to_contain_text(f'HTTP {status}')

        self.lesson('xss')
        for mode, result in (('Vulnerable', 'Script executed'), ('Fixed', 'Rendered as text')):
            self.mode(mode)
            self.page.get_by_role('button', name='Use sample payload').click()
            self.page.get_by_role('button', name='Render preview').click()
            expect(self.page.locator('#result')).to_contain_text(result)

        expect(self.page.locator('#progress-text')).to_have_text('6 / 6 complete')
        progress = self.page.evaluate("JSON.parse(localStorage.getItem('pvlab.progress.v1'))")
        self.assertEqual(progress, {
            lesson: {'vulnerable': True, 'fixed': True}
            for lesson in ('login', 'enumeration', 'idor', 'connections', 'storage', 'xss')
        })
        self.page.reload()
        expect(self.page.locator('#progress-text')).to_have_text('6 / 6 complete')


if __name__ == '__main__':
    unittest.main(verbosity=2)
