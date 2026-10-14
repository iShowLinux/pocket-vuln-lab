# Instructor field guide

## Learning goals

Students should be able to distinguish authentication from authorization, explain why client-visible secrets are recoverable, trace a bearer-token replay, recognize an unsafe HTML sink, and verify a specific mitigation with the same input that exposed a flaw.

The basic lab needs only a browser. Optional extension work uses browser DevTools, a request proxy configured for the student's own instance, or edited source files. No scanning, real credentials, external targets, or internet connection are needed to run the lessons.

## Suggested class format

- Demonstrate an ordinary Alice login before introducing malicious input.
- Work through one lesson at a time: predict, execute, inspect, explain, compare.
- Ask students to describe the server-side trust decision before they press Fixed.
- Use the final discussion to separate a repaired code path from a production-secure application.

A 45–60 minute session is a suggested teaching plan, not a measured completion time. Leave more time for students new to HTTP, JavaScript or SQL.

## 1. Login bypass

**Baseline:** `alice` / `alice123!` signs in as Alice.

**Attack:** username `admin' --` and any nonempty password. The Use injection button includes a final space, but hand-typing the same username without that space also works. Expected result: HTTP 200, username `admin`, role `admin`, and an actual SQLite query in the inspector.

```sql
SELECT id, username, role FROM users
WHERE username = 'admin' -- ' AND password = 'not-the-password'
```

The apostrophe terminates the username string. `--` comments out the remainder, including the password condition. The response is from SQLite, not a special-case check for that example. As an extension, a tautology such as `' OR 1=1 -- ` can return the first matching seeded account.

**Fixed:** the same injection receives HTTP 401 with a generic error. The username is a bound parameter; a separate PBKDF2 comparison checks the password. Ordinary Alice login still works.

**Ask:** Would hiding the login button fix this? What happens if the request is sent without the UI? Why should passwords normally be hashed rather than stored in plaintext?

## 2. Account enumeration and retries

**Vulnerable:** Run six-attempt probe. Alice receives 401 with Wrong password; nobody receives 404 with Username does not exist. All six are processed without throttling.

**Fixed:** Clear retry counters, then run again. The first five attempts receive identical 401 messages; the sixth receives 429. The limit uses a rolling 60-second window per client IP. The fixed path does hash work even for unknown users, but this is not a formal proof of timing indistinguishability.

**Ask:** Can a generic message still leak through a different status, response size, timing or reset workflow? What are the downsides of account-only and IP-only limits?

**Operational note:** Previous fixed-mode login failures count too. The Clear retry counters control also invalidates all sessions on this lab server. Progress is unaffected.

## 3. Insecure direct object reference (IDOR)

**Vulnerable:** Sign in as Alice. Load profile 1. Change the ID to 2 and load again. Bob's synthetic private note is returned, with `requested_by: alice`.

**Fixed:** Sign in as Alice again and request 2. Expect 403. Requesting 1 still succeeds. A request without an authenticated session receives 401 in either mode.

**Ask:** Is knowing an object ID permission to access it? Would a UUID alone repair this? Where should an ownership check run?

## 4. Client-exposed connection details

**Vulnerable:** Load client config. It returns a pretend PostgreSQL connection URI and `backup_api_key`. The browser displays the recovered key in an editable field. Request demo backup: the server accepts that key and returns three seeded records.

**Fixed:** Reload config; neither the URI nor key is published. Retry the old key; expect 403. The key is deliberately kept in the exercise field to show that merely deleting a string from the interface is not the authorization repair.

The fixed backup route uses server-side role authorization. A legitimate fixed-mode admin session can access it when its cookie is sent; that is intended. The key-only comparison in this exercise omits cookies so a retained admin session cannot be mistaken for a successful replay of the leaked key.

**Transport:** Read the HTTP connection label and request inspector. Neither mode encrypts the connection. The config URI ends in `.invalid`, and the server never tries it. Do not describe the built-in inspector as a packet sniffer or this exercise as an actual database compromise.

**Ask:** Why is a secret embedded in a mobile bundle recoverable? Why is HTTPS necessary but insufficient to hide a secret from the client that receives it? What must happen after a real service key is exposed?

## 5. Insecure browser storage / replay

**Vulnerable:** Sign in as Alice, inspect storage, then replay. `pvlab.session` contains the session token. The replay uses that exact token as a Bearer header and explicitly omits cookies; HTTP 200 proves the copied token works.

**Fixed:** Sign in again. localStorage contains no session token, and `document.cookie` cannot read the HttpOnly cookie. Replay sends neither a readable token nor cookies; expect 401. A separate authenticated fixed request with the real browser cookie would still succeed.

**Ask:** Does HttpOnly stop an XSS script from performing actions through the victim's browser? (No.) Does it encrypt cookies in transit? (No.) How do browser storage and native Keychain/Keystore differ?

## 6. DOM XSS

**Vulnerable:** Use sample payload, then Render preview. A broken data-URL image triggers an inline error handler. The preview changes and the parent receives a local Script executed message. The handler really ran in Chromium; it is not a simulated success banner.

**Fixed:** Repeat the same sample. The entire message, including `<img ...>`, is visible as literal text. No image node or event handler is created.

The sandbox frame has no same-origin permission and cannot read the app's storage or cookies. The main page only accepts exercise messages from that particular frame. The supplied sample makes no external request; arbitrary custom scripts can still navigate the frame itself, so do not describe the sandbox as complete network isolation. A fixed-mode regression test also uses a `</script>` input to check the serializer boundary. Explain the difference between safe rendering (the repair) and sandboxing (the exercise containment).

**Ask:** Why can event-handler attributes execute when scripts inserted by innerHTML often do not? When would a sanitizer be needed instead of textContent?

## Debrief / worksheet

For each lesson, record:

1. The input or changed request field.
2. What permission or trust boundary was bypassed.
3. The observed status and returned identity/data.
4. The vulnerable code decision.
5. The repaired decision and result for the same input.
6. One limitation of the mitigation.

Completion ticks are client-side learning feedback, not secure assessment records. A learner can modify localStorage or use DevTools; do not use these ticks as exam integrity evidence.

## Reset and troubleshooting

- **429 before the sixth attempt:** previous failures or a shared client IP; clear counters or wait for the rolling window.
- **401 after a restart:** the server's in-memory sessions were reset; sign in again.
- **Phone cannot connect:** check private LAN address, same network, server started with --lan, private-network firewall permission, and guest Wi-Fi isolation.
- **Different students affect one another:** use one lab process per pair, or accept that reset/rate limits are server-wide/per-IP.
- **A manually sent fixed backup request succeeds:** check whether a valid admin cookie was sent. The built-in key-only exercise omits cookies; session-authorized access is a different experiment.
- **No XSS completion tick for custom input:** only the sample sends the explicit execution signal. Arbitrary working payloads do not necessarily send that signal.
- **Browser privacy mode disables storage:** use a normal disposable browser profile that permits site storage. No real credentials are required.

## Source exercises

Have students remove the vulnerable SQL interpolation, add an ownership check to every object read, delete the client key authorization path, and replace the unsafe preview sink. Then run the regression tests. Discuss why some tests are intentionally written to expect vulnerabilities: these tests document a teaching fixture, not a production release gate.
