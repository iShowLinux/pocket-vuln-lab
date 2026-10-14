# Verification scope

## Commands

From the project folder:

```sh
python -m unittest discover -s tests -v
uv run --with playwright==1.64.0 tests/browser_checks.py
python checks/package.py
```

If Playwright Chromium is not installed and Windows Chrome is not present:

```sh
uv run --with playwright==1.64.0 playwright install chromium
```

No QA dependency is needed to **run** the classroom app. The browser suite uses its own ephemeral local server and disposable browser contexts, not the instructor's running server or logged-in browser profile.

## Verified result

The final local run passed **23 HTTP/distribution tests and 12 Chromium browser scenarios**. This includes a continuous six-lesson flow reaching **6 / 6 complete**, retained-admin-cookie isolation for the key-only experiment, hand-typed SQL injection without a trailing space, and malformed-input regressions. The Python source also passed compilation, and the source archive passed integrity/content checks.

## What the checks actually exercise

- Real HTTP responses from a running Python server, including SQL injection and legitimate fixed login.
- HttpOnly/SameSite cookie flags, fixed-mode generic errors and rate limiting.
- Missing profile ownership checks versus the fixed 403; correct owner and unauthenticated cases.
- A real recovered-key backup request and refusal of that key by the fixed route.
- Bearer-token replay, mode separation and invalidation after reset.
- Same-origin control-plane restrictions, untrusted Host rejection, request bounds, invalid modes and static path traversal.
- All six browser lessons in vulnerable and fixed modes, including actual script execution inside the XSS sandbox.
- Browser inability to read the fixed HttpOnly cookie, and cookie-free replay failure.
- The XSS sandbox's opaque-origin restriction and fixed rendering of a `</script>` boundary input.
- All six lessons at 320, 390 and 768 CSS pixels: no horizontal page overflow and visible button heights of at least 44 pixels.
- Browser progress persistence and reset behavior; no uncaught page errors in passing scenarios.
- Windows launcher reaching the actual CLI and ZIP integrity/content checks.

## What this does not establish

- Physical Android/iPhone or Safari/WebKit compatibility has not been tested. Chromium responsive/browser checks are not physical-device validation.
- LAN connectivity, firewall prompts and home-screen installation must be checked on the classroom's actual devices/network.
- No APK/IPA is built. There is no native runtime, certificate pinning, rooted-device detection or native secure storage exercise.
- Fixed mode is not a secure production configuration. Deliberately vulnerable routes remain accessible, database fixtures are shared, TLS is absent and tokens are in-memory.
- This is not a penetration test or formal audit. Tests document the behavior of an intentionally vulnerable learning fixture.

Browser screenshots are written to `artifacts/` in a development checkout and deliberately omitted from the student source ZIP.
