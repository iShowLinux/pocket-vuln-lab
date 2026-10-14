'use strict';
// Everything in this app is a seeded classroom fixture, never a real credential.
const $ = (selector) => document.querySelector(selector);
const DEMO = {username: 'alice', password: 'alice123!'};
const TOKEN_KEY = 'pvlab.session';
const PROGRESS_KEY = 'pvlab.progress.v1';
const lessons = [
  {id:'login', name:'Login bypass', cwe:'CWE-89 · SQL INJECTION', title:'Walk past the login.', description:'A login form should check your credentials. This one lets your username change the question the database asks.', mission:'Get in without the password.',
    steps:['Sign in as alice with alice123! to see a normal login.', 'Choose “Use injection” and sign in again. Watch which account comes back.', 'Switch to Fixed. Repeat the exact same payload and compare the response.'],
    hint:"Use admin' -- as the username and anything as the password. The apostrophe closes the string; -- comments out the password check.",
    why:'The vulnerable backend inserts text directly into a real SQLite query. Your username becomes SQL syntax, so the password condition is no longer evaluated.',
    repair:'Use parameterized queries, then verify a salted password hash. Never construct authentication queries by joining user-supplied strings.',
    code:"user = db.execute(\n  'SELECT * FROM users WHERE username = ?',\n  (username,)\n).fetchone()\n# Then verify the PBKDF2 password hash."},
  {id:'enumeration', name:'Leaky login errors', cwe:'CWE-204 / CWE-307 · AUTHENTICATION', title:'Ask who has an account.', description:'Different error messages give away valid usernames. Unlimited retries make that information even more useful.', mission:'Learn from a failed login.',
    steps:['Run the six-attempt probe against two invented usernames.', 'Compare the messages for alice and nobody. Notice whether the server ever slows you down.', 'Switch to Fixed and run it again. Look for uniform errors followed by HTTP 429.'],
    hint:'A 401 for alice and a 404 for nobody reveal which account exists. Fixed mode allows five failed attempts per client IP in a rolling 60-second window; the sixth is blocked.',
    why:'Authentication fails in both cases, but the status and wording disclose account existence. Without throttling, repeated guesses are inexpensive.',
    repair:'Return the same authentication error for unknown users and wrong passwords, perform comparable hash work, and rate-limit retries. The class limit is per IP and in memory, not a production distributed limiter.',
    code:"if recent_failures >= 5:\n    return 429, 'Try again later'\n# Same status + message for both cases:\nreturn 401, 'Invalid username or password.'"},
  {id:'idor', name:'Someone else’s profile', cwe:'CWE-639 · OBJECT AUTHORIZATION', title:'Change one little number.', description:'Being signed in does not mean you can read every record. Try changing a profile ID while keeping the same account.', mission:'Read Bob’s note as Alice.',
    steps:['Use the Alice sign-in button. Her profile ID is 1.', 'Load profile 1, then change the ID to 2 and load it again.', 'Switch to Fixed, sign in as Alice again, and repeat.'],
    hint:'You do not need a different password or a special payload. Changing /api/profiles/1 to /api/profiles/2 is enough in vulnerable mode.',
    why:'The server checks that a session exists, but not whether that session owns the requested object. Hiding the profile ID in the interface would not repair this.',
    repair:'Check authorization on the server for every requested object. Use the authenticated session identity, not a user ID supplied by the client.',
    code:"user = authenticated_session()\nif requested_id != user['id']:\n    return 403, 'Access denied'\nreturn load_profile(requested_id)"},
  {id:'connections', name:'Exposed connection details', cwe:'CWE-200 / CWE-798 · CLIENT SECRETS', title:'Read what the app gives away.', description:'A secret shipped to the client is not a secret. Inspect a configuration response, then try its embedded key on a demo backup.', mission:'Find the key. Test its reach.',
    steps:['Load the client configuration and find the demo connection string and backup key.', 'Use the discovered key to request the synthetic backup.', 'Switch to Fixed. Reload the config and retry the old key. Notice that HTTP itself is still unencrypted.'],
    hint:'The backup_api_key in the vulnerable config is accepted as X-Demo-Key. The database.invalid URI is deliberately fake; this app never connects to it.',
    why:'Anything in a mobile bundle or a network response can be inspected. The vulnerable API treats a shared client-side key as authorization. The visible HTTP traffic also shows why TLS is a separate requirement.',
    repair:'Keep service credentials on the server. Authorize sensitive operations using a validated user session and role. Use HTTPS and Secure cookies in a real deployment; this mode toggle does not supply TLS.',
    code:"# Public config: non-secret values only\nconfig = {'api_base': '/api'}\nif session.user.role != 'admin':\n    return 403, 'Access denied'"},
  {id:'storage', name:'Browser token theft', cwe:'CWE-922 · SENSITIVE STORAGE', title:'Look inside the pocket.', description:'JavaScript can read a token in localStorage. If the token is a bearer credential, copying it can be enough to reuse the session.', mission:'Read a token, then replay it.',
    steps:['Sign in as Alice. Inspect what the browser can read from localStorage and document.cookie.', 'Replay the readable token in a request that deliberately sends no cookies.', 'Switch to Fixed, sign in again, and repeat. The HttpOnly cookie is not readable by JavaScript.'],
    hint:'The replay is a real fetch to /api/session with credentials: omit and Authorization: Bearer <copied token>. In fixed mode there is no readable token to send.',
    why:'Bearer tokens grant the rights of their session to anyone who possesses them. localStorage is readable by scripts running in the same origin. The fixed session is still a cookie: HttpOnly prevents script reads, not all XSS actions.',
    repair:'For this web app, keep the session identifier in an HttpOnly, SameSite cookie. Also prevent XSS and use HTTPS/Secure in production. Native mobile apps have different storage APIs, such as Keychain and Android Keystore.',
    code:"Set-Cookie: pvlab_fixed=<random>;\n  HttpOnly; SameSite=Strict; Path=/\n# Add Secure when served over HTTPS.\n# Never put the fixed token in JSON."},
  {id:'xss', name:'Text that becomes code', cwe:'CWE-79 · DOM XSS', title:'Make a message execute.', description:'A preview should show what you typed. An unsafe HTML sink can turn that text into running JavaScript instead.', mission:'Turn a preview into a signal.',
    steps:['Load the sample payload, then render it in the preview.', 'Watch for the “Script executed” signal from the sandboxed frame.', 'Switch to Fixed and render the same payload. It should appear as literal text.'],
    hint:'A broken image triggers its onerror handler. The handler changes the preview and sends a message to the lesson. No data leaves this app.',
    why:'innerHTML parses user input as markup, including event handlers. This is real browser execution, confined to a frame with a unique origin. The exercise frame cannot read the app’s cookies or storage.',
    repair:'Use textContent when displaying plain text. If rich HTML is a requirement, use a maintained allowlist sanitizer as well as a suitable content security policy. The sandbox is additional containment, not a replacement for safe rendering.',
    code:"// Vulnerable\npreview.innerHTML = message;\n\n// Fixed: treat input as text\npreview.textContent = message;"}
];
function loadProgress() {
  try {
    const value = JSON.parse(localStorage.getItem(PROGRESS_KEY) || '{}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  } catch { return {}; }
}
const state = {lesson: 'login', mode: 'vulnerable', progress: loadProgress(), traffic: [], user: null, busy: false, leakedKey: '', readableToken: ''};
function saveProgress() { try { localStorage.setItem(PROGRESS_KEY, JSON.stringify(state.progress)); } catch {} }
function evidence(mode) {
  const item = state.progress[state.lesson] || {};
  item[mode] = true;
  state.progress[state.lesson] = item;
  saveProgress(); updateProgress();
}
function updateProgress() {
  let count = 0;
  for (const lesson of lessons) {
    const done = state.progress[lesson.id]?.vulnerable && state.progress[lesson.id]?.fixed;
    if (done) count++;
    const check = document.querySelector(`[data-lesson="${lesson.id}"] .nav-check`);
    if (check) check.textContent = done ? '✓' : '';
  }
  $('#progress-text').textContent = `${count} / ${lessons.length} complete`;
  $('#progress').value = count;
  const progress = state.progress[state.lesson] || {};
  $('#evidence-vulnerable').textContent = progress.vulnerable ? '✓ Observed vulnerable behavior' : 'Vulnerable: not observed';
  $('#evidence-fixed').textContent = progress.fixed ? '✓ Verified fixed behavior' : 'Fix: not verified';
  $('#evidence-vulnerable').classList.toggle('done', !!progress.vulnerable);
  $('#evidence-fixed').classList.toggle('done', !!progress.fixed);
}
function result(title, detail, kind = '') {
  const target = $('#result'); target.replaceChildren(); target.dataset.state = kind;
  const strong = document.createElement('strong'); strong.textContent = title; target.append(strong);
  if (detail) {
    const block = document.createElement(typeof detail === 'string' ? 'p' : 'pre');
    block.textContent = typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2); target.append(block);
  }
}
async function api(path, {method = 'GET', body, headers = {}, omitCookies = false} = {}) {
  const url = path + (path.includes('?') ? '&' : '?') + 'mode=' + state.mode;
  const allHeaders = {'X-Lab-Request': 'pocket-vuln', ...headers};
  const token = localStorage.getItem(TOKEN_KEY);
  if (state.mode === 'vulnerable' && token && !('Authorization' in allHeaders)) allHeaders.Authorization = 'Bearer ' + token;
  if (body !== undefined) allHeaders['Content-Type'] = 'application/json';
  const payload = body === undefined ? undefined : {...body, mode: state.mode};
  const response = await fetch(url, {method, headers: allHeaders, credentials: omitCookies ? 'omit' : 'same-origin', body: payload === undefined ? undefined : JSON.stringify(payload)});
  const data = await response.json();
  state.traffic.unshift({request: {method, url, headers: allHeaders, body: payload, cookies: omitCookies ? 'omitted' : 'browser managed (HttpOnly is not readable here)'}, response: {status: response.status, body: data}});
  state.traffic = state.traffic.slice(0, 12);
  $('#traffic').textContent = state.traffic.map(item => JSON.stringify(item, null, 2)).join('\n\n');
  $('#request-count').textContent = `${state.traffic.length} request${state.traffic.length === 1 ? '' : 's'}`;
  return {status: response.status, data};
}
async function task(work) {
  if (state.busy) return;
  state.busy = true;
  document.querySelectorAll('button,select').forEach(el => { el.disabled = true; });
  try { await work(); }
  catch (err) { result('Request could not finish.', `${err.message}. Check that the local Python server is running.`, 'error'); }
  finally { state.busy = false; document.querySelectorAll('button,select').forEach(el => { el.disabled = false; }); }
}
async function signIn(username = DEMO.username, password = DEMO.password) {
  const response = await api('/api/login', {method:'POST', body:{username, password}});
  if (response.status === 200) {
    state.user = response.data.user;
    if (state.mode === 'vulnerable') localStorage.setItem(TOKEN_KEY, response.data.token);
    else localStorage.removeItem(TOKEN_KEY);
  } else { state.user = null; localStorage.removeItem(TOKEN_KEY); }
  return response;
}
function loginExercise() {
  $('#exercise').innerHTML = `<form id="login-form" autocomplete="off"><label>Username<input id="username" value="alice" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="512"></label><label>Demo password<input id="password" type="text" value="alice123!" autocomplete="off" spellcheck="false" maxlength="512"></label><p class="small">Seeded login: <code>alice</code> / <code>alice123!</code><br>Only use these made-up classroom credentials.</p><div class="actions"><button class="primary" type="submit">Sign in</button><button type="button" id="use-injection">Use injection</button></div></form>`;
  $('#use-injection').onclick = () => { $('#username').value = "admin' -- "; $('#password').value = 'not-the-password'; $('#username').focus(); };
  $('#login-form').onsubmit = event => { event.preventDefault(); task(async () => {
    const username = $('#username').value;
    const response = await signIn(username, $('#password').value);
    if (response.status === 200) {
      result(`HTTP 200 · Signed in as ${response.data.user.username}`, response.data, state.mode === 'vulnerable' ? 'observed' : 'fixed');
      if (state.mode === 'vulnerable' && username.includes("'") && response.data.user.username === 'admin') evidence('vulnerable');
    } else {
      result(`HTTP ${response.status} · Sign-in rejected`, response.data, state.mode === 'fixed' ? 'fixed' : 'error');
      if (state.mode === 'fixed' && username.trimEnd() === "admin' --" && response.status === 401) evidence('fixed');
    }
  }); };
}
function enumerationExercise() {
  $('#exercise').innerHTML = `<p class="small">Send six failed logins, alternating <code>alice</code> and <code>nobody</code>. Password: <code>wrong-demo-password</code>.</p><div class="actions"><button class="primary" id="run-probe">Run six-attempt probe</button><button id="clear-attempts">Clear retry counters</button></div><table id="probe-results" class="probe-table"><thead><tr><th>Attempt</th><th>User</th><th>Status</th><th>Message</th></tr></thead><tbody></tbody></table><p class="small">Fixed mode: five failures per IP per 60 seconds. Clearing counters also ends every session on this demo server.</p>`;
  $('#clear-attempts').onclick = () => task(async () => {
    const response = await api('/api/reset', {method:'POST', body:{}});
    state.user = null; localStorage.removeItem(TOKEN_KEY);
    result(`HTTP ${response.status} · Retry counters cleared`, 'All demo sessions were also reset. Lesson progress is unchanged.');
  });
  $('#run-probe').onclick = () => task(async () => {
    $('#probe-results tbody').replaceChildren();
    const responses = [];
    for (let i = 0; i < 6; i++) {
      const username = i % 2 === 0 ? 'alice' : 'nobody';
      const response = await api('/api/login', {method:'POST', body:{username, password:'wrong-demo-password'}});
      responses.push(response);
      const row = document.createElement('tr');
      for (const value of [i + 1, username, response.status, response.data.error]) {
        const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
      }
      $('#probe-results tbody').append(row);
    }
    if (state.mode === 'vulnerable' && responses[0].status === 401 && responses[1].status === 404 && !responses.some(r => r.status === 429)) {
      evidence('vulnerable'); result('Accounts are distinguishable · no retry limit', 'alice exists; nobody does not. Six failed attempts were processed without throttling.', 'observed');
    } else if (state.mode === 'fixed' && responses[0].status === 401 && responses[1].status === 401 && responses[0].data.error === responses[1].data.error && responses.some(r => r.status === 429)) {
      evidence('fixed'); result('Uniform errors, then HTTP 429', 'The error no longer reveals whether an account exists. The retry limit blocks further attempts.', 'fixed');
    } else result('Retry counters were already in use.', 'Clear retry counters, then run the probe again to observe the full sequence.');
  });
}
function idorExercise() {
  $('#exercise').innerHTML = `<p class="small">Alice owns profile <code>1</code>. Bob owns profile <code>2</code>. Start a demo session, then change the requested object.</p><button id="alice-login">Sign in as Alice</button><form id="profile-form" style="margin-top:20px"><label>Profile ID<input id="profile-id" type="number" min="1" max="9999" value="1" inputmode="numeric" required></label><button type="submit" class="primary">Load profile</button></form>`;
  $('#alice-login').onclick = () => task(async () => {
    const response = await signIn();
    result(`HTTP ${response.status} · ${response.status === 200 ? 'Signed in as alice' : 'Sign-in failed'}`, response.data);
  });
  $('#profile-form').onsubmit = event => { event.preventDefault(); task(async () => {
    const uid = $('#profile-id').value;
    const response = await api('/api/profiles/' + encodeURIComponent(uid));
    result(`HTTP ${response.status} · ${response.status === 200 ? 'Profile returned' : 'Profile request denied'}`, response.data, response.status === 200 && uid === '2' ? 'observed' : state.mode === 'fixed' && response.status === 403 ? 'fixed' : '');
    if (state.user?.username === 'alice' && uid === '2') {
      if (state.mode === 'vulnerable' && response.status === 200) evidence('vulnerable');
      if (state.mode === 'fixed' && response.status === 403) evidence('fixed');
    }
  }); };
}
function connectionsExercise() {
  let fixedConfigChecked = false;
  $('#exercise').innerHTML = `<p class="small">Connection: <code id="connection-origin"></code><br>Transport is HTTP in both modes. Fixed does not turn on encryption.</p><button class="primary" id="load-config">Load client config</button><pre id="config-output" class="data-panel">The client configuration will appear here.</pre><label style="margin-top:18px">Recovered demo backup key<input id="backup-key" autocomplete="off" placeholder="Load the vulnerable config to discover a key" spellcheck="false"></label><button id="load-backup">Request demo backup</button><p class="small">The old key is kept in this field when you switch modes. This is a key-only, cookie-free experiment in both modes, so an existing admin session cannot grant access here. Separate requests with an authorized admin cookie still work in Fixed.</p>`;
  $('#connection-origin').textContent = location.origin;
  $('#backup-key').value = state.leakedKey;
  $('#load-config').onclick = () => task(async () => {
    const response = await api('/api/config');
    $('#config-output').textContent = JSON.stringify(response.data, null, 2);
    if (response.data.backup_api_key) { state.leakedKey = response.data.backup_api_key; $('#backup-key').value = state.leakedKey; }
    fixedConfigChecked = state.mode === 'fixed' && response.status === 200 && !('backup_api_key' in response.data) && !('database_url' in response.data);
    result(`HTTP ${response.status} · ${fixedConfigChecked ? 'No service secrets in client config' : 'Configuration received'}`, fixedConfigChecked ? 'Now retry the old key. Removing a leaked secret from the UI alone would not revoke access.' : 'Inspect the demo database URI and backup key, then try the backup request.');
  });
  $('#load-backup').onclick = () => task(async () => {
    const key = $('#backup-key').value;
    const response = await api('/api/backup', {headers:{'X-Demo-Key':key}, omitCookies:true});
    result(`HTTP ${response.status} · ${response.status === 200 ? 'Demo backup returned' : 'Backup denied'}`, response.data, response.status === 200 ? 'observed' : 'fixed');
    if (state.mode === 'vulnerable' && response.status === 200) evidence('vulnerable');
    if (state.mode === 'fixed' && fixedConfigChecked && state.leakedKey && key === state.leakedKey && response.status === 403) evidence('fixed');
  });
}
function storageExercise() {
  let inspected = false;
  $('#exercise').innerHTML = `<button class="primary" id="storage-login">Sign in as Alice</button><div class="actions"><button id="inspect-storage">Inspect browser storage</button><button id="replay-token">Replay readable token</button></div><pre id="storage-output" class="data-panel">Sign in, then inspect browser storage.</pre><p class="small">The replay omits cookies on purpose. All requests stay on this local server. HttpOnly blocks JavaScript reads; it does not make XSS harmless.</p>`;
  $('#storage-login').onclick = () => task(async () => {
    inspected = false; state.readableToken = '';
    const response = await signIn();
    result(`HTTP ${response.status} · ${response.status === 200 ? 'Signed in as alice' : 'Sign-in failed'}`, response.data);
  });
  $('#inspect-storage').onclick = () => {
    state.readableToken = localStorage.getItem(TOKEN_KEY) || '';
    inspected = true;
    $('#storage-output').textContent = JSON.stringify({'localStorage[pvlab.session]':state.readableToken || null, 'document.cookie':document.cookie || '(no JavaScript-readable cookies)'}, null, 2);
    result(state.readableToken ? 'A script can read the bearer token.' : 'No session token readable by JavaScript.', 'Now replay the readable token. The replay request will not send browser cookies.');
  };
  $('#replay-token').onclick = () => task(async () => {
    if (!inspected || !state.user) return result('Sign in and inspect first.', 'This comparison needs a real demo session and a browser-storage read.');
    const response = await api('/api/session', {headers:{Authorization:state.readableToken ? 'Bearer ' + state.readableToken : ''}, omitCookies:true});
    result(`HTTP ${response.status} · ${response.status === 200 ? 'Copied token replayed successfully' : 'Cookie-free replay rejected'}`, response.data, response.status === 200 ? 'observed' : 'fixed');
    if (state.mode === 'vulnerable' && state.readableToken && response.status === 200) evidence('vulnerable');
    if (state.mode === 'fixed' && !state.readableToken && !document.cookie.includes('pvlab_fixed=') && response.status === 401) evidence('fixed');
  });
}
const SAMPLE_XSS = `<img src="data:,broken" onerror="document.body.dataset.executed='yes';this.outerHTML='<strong>Script executed in the sandbox.</strong>';parent.postMessage({lab:'pvlab-xss',event:'executed'},'*')">`;
function xssExercise() {
  let submitted = '';
  let executed = false;
  $('#exercise').innerHTML = `<form id="preview-form"><label>Preview message<textarea id="message" maxlength="4000" spellcheck="false">Hello, security class.</textarea></label><div class="actions"><button class="primary" type="submit">Render preview</button><button type="button" id="sample-xss">Use sample payload</button></div></form><iframe id="xss-frame" class="xss-preview" title="Sandboxed message preview" sandbox="allow-scripts" referrerpolicy="no-referrer"></iframe><p class="small">This is real DOM XSS inside an opaque-origin sandbox. The frame cannot access the main app’s storage or cookies. The sample sends only a local lesson-completion signal.</p>`;
  $('#sample-xss').onclick = () => { $('#message').value = SAMPLE_XSS; };
  window.onmessage = event => {
    const frame = $('#xss-frame');
    if (!frame || event.source !== frame.contentWindow || !event.data || event.data.lab !== 'pvlab-xss') return;
    if (state.mode === 'vulnerable' && event.data.event === 'executed') {
      executed = true; evidence('vulnerable'); result('Script executed · sandbox signal received', 'The preview treated text as executable markup. The signal came from this exercise’s isolated frame.', 'observed');
    } else if (event.data.event === 'rendered' && state.mode === 'fixed' && event.data.mode === 'fixed' && event.data.children === 0 && event.data.text === submitted) {
      result('Rendered as text · no HTML elements created', 'The exact input is displayed literally. Event handlers were not created or run.', 'fixed');
      if (submitted === SAMPLE_XSS) evidence('fixed');
    } else if (event.data.event === 'rendered' && !executed) {
      result('HTML rendered in the sandbox.', 'The vulnerable sink parsed your input. Use the sample payload to get a visible execution signal.');
    }
  };
  $('#preview-form').onsubmit = event => {
    event.preventDefault(); submitted = $('#message').value; executed = false;
    // Escape '<' in the JS string so user text cannot terminate this script element.
    const literal = JSON.stringify(submitted).replace(/</g, () => String.fromCharCode(92) + 'u003c');
    const sink = state.mode === 'vulnerable' ? 'innerHTML' : 'textContent';
    $('#xss-frame').srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'"><style>body{font:14px/1.6 sans-serif;color:#163c32;padding:12px;overflow-wrap:anywhere}</style></head><body><div id="preview"></div><script>const preview=document.getElementById('preview');preview.${sink}=${literal};parent.postMessage({lab:'pvlab-xss',event:'rendered',mode:'${state.mode}',text:preview.textContent,children:preview.children.length},'*');</script></body></html>`;
  };
}
function renderExercise() {
  window.onmessage = null;
  if (state.lesson === 'login') return loginExercise();
  if (state.lesson === 'enumeration') return enumerationExercise();
  if (state.lesson === 'idor') return idorExercise();
  if (state.lesson === 'connections') return connectionsExercise();
  if (state.lesson === 'storage') return storageExercise();
  if (state.lesson === 'xss') return xssExercise();
}
function render() {
  const index = lessons.findIndex(item => item.id === state.lesson);
  const lesson = lessons[index];
  $('#lesson-kicker').textContent = `LESSON ${String(index + 1).padStart(2, '0')} / 06 · ${lesson.cwe}`;
  $('#lesson-title').textContent = lesson.title;
  $('#lesson-description').textContent = lesson.description;
  $('#guide-title').textContent = lesson.mission;
  $('#steps').replaceChildren(...lesson.steps.map(step => { const li = document.createElement('li'); li.textContent = step; return li; }));
  $('#hint-body').textContent = lesson.hint;
  $('#why-text').textContent = lesson.why;
  $('#repair-text').textContent = lesson.repair;
  $('#repair-code').textContent = lesson.code;
  $('#lesson-select').value = lesson.id;
  document.querySelectorAll('[data-lesson]').forEach(button => button.setAttribute('aria-current', button.dataset.lesson === lesson.id ? 'step' : 'false'));
  $('#mode-vulnerable').setAttribute('aria-pressed', state.mode === 'vulnerable');
  $('#mode-fixed').setAttribute('aria-pressed', state.mode === 'fixed');
  $('#mode-badge').textContent = state.mode.toUpperCase();
  $('#mode-badge').classList.toggle('fixed', state.mode === 'fixed');
  $('#mode-note').textContent = state.mode === 'vulnerable' ? 'Intentional flaws are enabled. All accounts and connection details are made up.' : 'This lesson’s mitigation is enabled. The shared lab still uses HTTP and intentionally exposes its vulnerable routes.';
  document.querySelector('.hint').open = false;
  state.traffic = []; $('#traffic').textContent = 'No requests yet.'; $('#request-count').textContent = '0 requests';
  result('Ready when you are.', 'Try the exercise. The server response will appear here.');
  renderExercise(); updateProgress();
}
for (const [index, lesson] of lessons.entries()) {
  const button = document.createElement('button'); button.dataset.lesson = lesson.id;
  const number = document.createElement('span'); number.className = 'nav-number'; number.textContent = String(index + 1).padStart(2, '0');
  const name = document.createElement('span'); name.textContent = lesson.name;
  const check = document.createElement('span'); check.className = 'nav-check';
  button.append(number, name, check); button.onclick = () => { state.lesson = lesson.id; render(); };
  $('#lesson-nav').append(button);
  const option = document.createElement('option'); option.value = lesson.id; option.textContent = `${number.textContent} — ${lesson.name}`; $('#lesson-select').append(option);
}
$('#lesson-select').onchange = event => { state.lesson = event.target.value; render(); };
for (const mode of ['vulnerable', 'fixed']) {
  $(`#mode-${mode}`).onclick = () => {
    if (state.mode === mode) return;
    state.mode = mode; state.user = null; state.readableToken = ''; localStorage.removeItem(TOKEN_KEY); render();
  };
}
$('#reset-lab').onclick = () => {
  if (!confirm('Reset all server sessions, retry counters, and this browser’s lesson progress? On a shared server, this signs everyone out.')) return;
  task(async () => {
    const response = await api('/api/reset', {method:'POST', body:{}});
    if (response.status !== 200) return result('Reset failed.', response.data, 'error');
    state.progress = {}; state.user = null; state.leakedKey = ''; state.readableToken = ''; localStorage.removeItem(TOKEN_KEY); saveProgress(); render();
    result('Lab reset.', 'Sessions, retry counters and progress are clear.');
  });
};
render();
