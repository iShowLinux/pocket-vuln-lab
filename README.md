# Pocket Vuln Lab

A small, intentionally vulnerable **mobile-first web application** for teaching application security. Open it in an Android/iPhone browser or on a laptop. No Android SDK, account, database installation, Docker, build step, or runtime packages are needed.

**This is a browser app, not a native APK/IPA.** Its storage exercise covers browser localStorage/cookies, not Android Keystore or iOS Keychain. A web manifest supplies home-screen metadata, but this is not an offline PWA: the Python server must stay running. Home-screen/install options depend on browser and secure-context support, especially over LAN HTTP.

## Start in under a minute

Requires **Python 3.10 or newer**.

### Windows

Double-click **StartLab.cmd**. It starts the server and opens your browser. Leave its terminal window open. Press Ctrl+C in that window to stop.

Or, in a terminal in this folder:

```sh
python app.py --open
```

### macOS / Linux

```sh
python3 app.py --open
```

Open **http://127.0.0.1:8765**. The default listener is loopback only. If that port is busy, run `python app.py --port 8766 --open`.

### Use a phone

1. Put your computer and phone on the same private classroom Wi-Fi.
2. Run `python app.py --lan` on the computer.
3. Find the computer's private IPv4 address (`ipconfig` on Windows; look at the active Wi-Fi adapter).
4. On the phone, visit `http://YOUR-PC-PRIVATE-IP:8765`. `127.0.0.1` on the phone means the phone, not your computer.
5. If Windows asks, permit access only for the private classroom network. Guest Wi-Fi/client isolation may prevent devices reaching one another.

Nothing changes firewall settings automatically. `--lan` is explicit opt-in. No public deployment or tunneling is needed.

## Start learning

Each lesson includes a mission, three steps, a hint, the actual result, a request/response inspector, an explanation, and a repair snippet.

1. Choose **Vulnerable** and reproduce the behavior.
2. Open the inspector to understand the request and server response.
3. Choose **Fixed** and repeat the same experiment.
4. A lesson completes after the app observes both the vulnerable result and its fixed comparison. Progress persists only in the current browser.

| Lesson | Experiment | Fixed comparison |
|---|---|---|
| Login bypass | Enter `admin' -- ` as username and any password | Parameterized lookup and salted PBKDF2 hash verification reject the injected login |
| Leaky login errors | Run six attempts alternating `alice` and `nobody` | Uniform 401 errors; a rolling per-IP retry limit returns 429 |
| Someone else's profile | Sign in as Alice; change profile 1 to 2 | Server ownership check returns 403 |
| Exposed connection details | Read the fake database URI and backup key; use that key | Public config omits secrets; the old key cannot authorize a fixed-mode backup |
| Browser token theft | Read localStorage and replay the token without cookies | HttpOnly session cookie is not script-readable; cookie-free replay returns 401 |
| Text that becomes code | Render a message with an `onerror` handler | `textContent` renders the exact input as text instead of executable markup |

### Seeded accounts

| Username | Password | Profile | Role |
|---|---|---|---|
| alice | alice123! | 1 | student |
| bob | bob123! | 2 | student |
| admin | admin123! | 3 | admin |

All accounts, profile notes, keys, and connection details are synthetic fixtures. The `.invalid` database address is a nonworking example. The app never connects to a database service or third-party API. SQLite runs in memory inside Python.

## Classroom operation

- Prefer one server per student or pair. It makes sessions, retry counters, resets and experiments independent.
- A shared instructor server works, but rate limiting is per client IP; students sharing an address may share a limit. **Reset lab** and **Clear retry counters** invalidate all sessions on that server.
- The retry window is 60 seconds. Clear counters before demonstrating the full six-attempt fixed sequence if earlier exercises already used failed attempts.
- Progress is a learning aid, not a tamper-resistant exam score. Students control their own browser storage.
- On mobile, use the lesson selector. On desktop, use the sidebar. The built-in inspector avoids needing mobile DevTools for the basic exercises.
- See **INSTRUCTOR.md** for the teaching sequence, expected results, and discussion prompts.

## Important architectural distinctions

The vulnerable behavior is real: SQLite evaluates the injected query; the server returns another seeded user's profile; the copied bearer token really authenticates another cookie-free request; the browser executes the XSS handler.

The XSS preview uses `sandbox="allow-scripts"` **without** `allow-same-origin`. That frame has an opaque origin and cannot read the main page's cookies or storage. A restrictive frame CSP blocks fetches/external images in the provided exercise; the sample only sends a lesson signal to its parent. This is not total network isolation for arbitrary student-authored scripts: a sandboxed frame may still navigate itself. The sandbox protects the parent origin, not every possible network action. This exercise deliberately does not chain XSS into the storage lesson. Students may examine each flaw separately.

**Fixed is a per-lesson comparison, not a secure deployment mode.** Both modes are still available in the same service, share the same synthetic database, and use HTTP. The SQL lesson deliberately keeps plaintext demo passwords alongside fixed-mode hashes. The fixed cookie lacks `Secure` because this local server does not supply TLS. Hiding a client config secret does not clean up this deliberately vulnerable shared service. A production design would remove vulnerable routes/data, deploy HTTPS, use Secure cookies, add session expiry/revocation and robust abuse controls, and undergo independent review.

The request inspector is a log of real browser requests, **not packet interception**. To demonstrate cleartext transport, inspect your own lab's HTTP traffic with DevTools or an instructor-controlled proxy. Toggling Fixed never claims to encrypt the connection.

## Source map

```text
app.py                    Python HTTP API, SQLite fixtures, modes, sessions
static/index.html         Responsive application shell
static/app.js             Six lessons, requests, progress and XSS sandbox
static/style.css          Responsive styling
static/manifest.webmanifest Home-screen metadata
static/icon.svg           App icon
StartLab.cmd              Windows launcher
INSTRUCTOR.md             Classroom guide and expected answers
VERIFY.md                 Test commands and verification scope
LICENSE                   MIT license
THIRD_PARTY.md            Dependencies / attribution
checks/package.py         Source-archive builder
tests/test_app.py         Standard-library HTTP integration checks
tests/browser_checks.py   Playwright real-browser checks
```

Runtime state is in memory; restarting clears sessions and retry counters. Browser progress and deliberately vulnerable stored tokens remain until reset/cleared. Tokens from a previous server process no longer authenticate.

## Tests

Backend checks require no packages:

```sh
python -m unittest discover -s tests -v
```

Optional browser QA (not needed to use the app):

```sh
uv run --with playwright==1.64.0 tests/browser_checks.py
```

The browser script uses installed Windows Chrome when available. Otherwise first install Playwright Chromium using `uv run --with playwright==1.64.0 playwright install chromium`. It starts its own ephemeral local server, exercises both modes, and saves screenshots to `artifacts/`.

Package source for students:

```sh
python checks/package.py
```

The resulting `dist/PocketVulnLab.zip` excludes environments, caches, runtime state and verification screenshots.
