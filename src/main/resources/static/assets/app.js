/*
 * SecureAuth console: a vanilla-JS client for the JWT Authentication System API.
 *
 * Token handling, the way a real client should do it:
 *  - the access token is kept in a JavaScript variable only (never localStorage), so a page reload loses it;
 *  - the refresh token is an HttpOnly cookie this code can't see; on load, POST /api/auth/refresh restores
 *    the session from it ("silent refresh");
 *  - the access token is refreshed a minute before it expires, and once more on a 401 token_expired/token_stale;
 *  - concurrent refreshes share one request, because the server treats a replayed refresh token as theft.
 */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const fmtTime = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const when = (iso) => (iso ? fmtTime.format(new Date(iso)) : '—');

  function ago(iso) {
    const s = Math.round((Date.now() - new Date(iso)) / 1000);
    if (s < 45) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return when(iso);
  }

  function toast(msg, bad = false) {
    const el = Object.assign(document.createElement('div'), { className: `toast ${bad ? 'bad' : ''}`, textContent: msg });
    $('#toasts').append(el);
    setTimeout(() => el.remove(), 4200);
  }

  // ---------------------------------------------------------------- token state
  const auth = { token: null, expiresAt: 0, user: null, refreshTimer: null, refreshing: null, issuedAt: 0 };

  class ApiError extends Error {
    constructor(status, body) {
      super(body?.message || `Request failed (${status})`);
      this.status = status;
      this.code = body?.code;
      this.fieldErrors = body?.fieldErrors;
    }
  }

  async function raw(path, { method = 'GET', body, token = auth.token } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = null; }
    return { res, data };
  }

  /** Authenticated call with one automatic refresh-and-retry on an expired or stale token. */
  async function api(path, opts = {}) {
    let { res, data } = await raw(path, opts);
    if (res.status === 401 && ['token_expired', 'token_stale'].includes(data?.code) && !opts.noRetry) {
      if (await refresh()) ({ res, data } = await raw(path, opts));
    }
    if (res.status === 401 && ['session_ended', 'account_disabled', 'account_locked'].includes(data?.code)) {
      signedOut(data.message);
    }
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
  }

  /** POST /api/auth/refresh, at most one at a time. Resolves true when a new access token was obtained. */
  function refresh() {
    if (!auth.refreshing) {
      auth.refreshing = (async () => {
        const { res, data } = await raw('/api/auth/refresh', { method: 'POST', token: null });
        if (!res.ok) {
          if (auth.token) signedOut(data?.message || 'Your session has ended');
          return false;
        }
        setToken(data);
        return true;
      })().finally(() => { auth.refreshing = null; });
    }
    return auth.refreshing;
  }

  function setToken(data) {
    auth.token = data.accessToken;
    auth.expiresAt = new Date(data.expiresAt).getTime();
    auth.issuedAt = Date.now();
    const roleChanged = auth.user && auth.user.role !== data.user.role;
    auth.user = data.user;
    clearTimeout(auth.refreshTimer);
    const inMs = Math.max(5_000, auth.expiresAt - Date.now() - 60_000);
    auth.refreshTimer = setTimeout(() => refresh().then((ok) => ok && toast('Access token refreshed automatically')), inMs);
    if (!$('#appScreen').hidden) {
      renderToken(true);
      renderMe();
      if (roleChanged) { toast(`Your role is now ${data.user.role}`); loadAll(); }
    }
  }

  // ---------------------------------------------------------------- screens
  async function boot() {
    // Silent refresh: if the HttpOnly cookie holds a live session, we are signed in without a password.
    const ok = await refresh();
    if (ok) showApp(); else showAuth();
  }

  async function showAuth(message) {
    $('#appScreen').hidden = true;
    $('#authScreen').hidden = false;
    const alert = $('#loginForm .alert');
    alert.hidden = !message;
    alert.textContent = message || '';
    alert.className = 'alert';
    try {
      const demo = await (await fetch('/api/auth/demo-accounts')).json();
      $('#demoBox').hidden = !demo.enabled;
      $('#demoAccounts').innerHTML = demo.accounts.map((a) => `
        <button type="button" class="demo-btn" data-user="${esc(a.username)}" data-pass="${esc(a.password)}" aria-label="Sign in as demo ${esc(a.role.toLowerCase())}">
          <strong>${esc(a.username)}</strong><span>${esc(a.role)}</span>
        </button>`).join('');
      $$('[data-user]').forEach((b) => b.onclick = () => login(b.dataset.user, b.dataset.pass));
    } catch { $('#demoBox').hidden = true; }
  }

  function showApp() {
    $('#authScreen').hidden = true;
    $('#appScreen').hidden = false;
    renderMe();
    renderToken();
    renderChecks();
    $('#tamperResult').hidden = true;
    $('#rotationNote').textContent = "The refresh token lives in an HttpOnly cookie, so this page can't read it. Each refresh swaps it for a new one.";
    loadAll();
  }

  function signedOut(message) {
    clearTimeout(auth.refreshTimer);
    Object.assign(auth, { token: null, expiresAt: 0, user: null });
    showAuth(message);
  }

  function loadAll() {
    loadSessions();
    loadEvents();
    loadFacts();
    const perms = auth.user.permissions;
    $('#adminCard').hidden = !perms.includes('users:read');
    $('#auditCard').hidden = !perms.includes('audit:read');
    if (perms.includes('users:read')) loadUsers();
    if (perms.includes('audit:read')) loadAudit();
  }

  // ---------------------------------------------------------------- sign in / register
  $$('.tab').forEach((t) => t.addEventListener('click', () => {
    $$('.tab').forEach((x) => { x.classList.toggle('active', x === t); x.setAttribute('aria-selected', x === t); });
    $('#loginForm').hidden = t.dataset.tab !== 'login';
    $('#registerForm').hidden = t.dataset.tab !== 'register';
  }));

  async function login(loginName, password) {
    const form = $('#loginForm');
    const alert = $('.alert', form);
    alert.hidden = true;
    $$('button', form).forEach((b) => (b.disabled = true));
    try {
      const { res, data } = await raw('/api/auth/login', { method: 'POST', body: { login: loginName, password }, token: null });
      if (!res.ok) throw new ApiError(res.status, data);
      form.reset();
      setToken(data);
      showApp();
      toast(`Signed in as ${data.user.username}`);
    } catch (err) {
      alert.textContent = err.fieldErrors ? Object.values(err.fieldErrors).join('. ') : err.message;
      alert.className = 'alert';
      alert.hidden = false;
    } finally {
      $$('button', form).forEach((b) => (b.disabled = false));
    }
  }

  $('#loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    login(e.target.login.value.trim(), e.target.password.value);
  });

  const RULES = { len: (p) => p.length >= 8, upper: (p) => /[A-Z]/.test(p), lower: (p) => /[a-z]/.test(p), digit: (p) => /\d/.test(p) };
  $('#registerForm').password.addEventListener('input', (e) => {
    $$('#pwRules li').forEach((li) => li.classList.toggle('met', RULES[li.dataset.rule](e.target.value)));
  });

  $('#registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const alert = $('.alert', f);
    alert.hidden = true;
    $$('.err', f).forEach((x) => (x.textContent = ''));
    const body = { fullName: f.fullName.value.trim(), username: f.username.value.trim(), email: f.email.value.trim(), password: f.password.value };
    const { res, data } = await raw('/api/auth/register', { method: 'POST', body, token: null });
    if (!res.ok) {
      if (data?.fieldErrors) {
        Object.entries(data.fieldErrors).forEach(([k, v]) => { const slot = $(`.err[data-for="${k}"]`, f); if (slot) slot.textContent = v; });
      } else {
        alert.textContent = data?.message || 'Could not create the account';
        alert.hidden = false;
      }
      return;
    }
    toast('Account created');
    login(body.username, body.password);
    f.reset();
    $$('#pwRules li').forEach((li) => li.classList.remove('met'));
  });

  // ---------------------------------------------------------------- header + token
  function renderMe() {
    const u = auth.user;
    $('#meName').textContent = u.fullName;
    $('#meRole').textContent = u.role;
    $('#meRole').className = `role-badge ${u.role}`;
    $('#meAvatar').textContent = u.fullName.split(/\s+/).map((w) => w[0]).slice(0, 2).join('').toUpperCase();
  }

  const b64 = (s) => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='))));

  function prettyJson(obj) {
    const notes = { iat: 'issued at', exp: 'expires', sub: 'user id', sid: 'session id', ver: 'token version', jti: 'token id' };
    const entries = Object.entries(obj);
    return '{\n' + entries.map(([k, v], i) => {
      let val;
      if (typeof v === 'string') val = `<span class="s">"${esc(v)}"</span>`;
      else if (typeof v === 'number') val = `<span class="n">${v}</span>`;
      else val = `<span class="s">${esc(JSON.stringify(v))}</span>`;
      let note = notes[k] ? `  <span class="c">// ${notes[k]}</span>` : '';
      if ((k === 'iat' || k === 'exp') && typeof v === 'number') note = `  <span class="c">// ${when(new Date(v * 1000).toISOString())}</span>`;
      const comma = i < entries.length - 1 ? ',' : '';
      return `  <span class="k">"${esc(k)}"</span>: ${val}${comma}${note}`;
    }).join('\n') + '\n}';
  }

  function renderToken(flash = false) {
    if (!auth.token) return;
    const [h, p, s] = auth.token.split('.');
    $('#jwtRaw').innerHTML = `<span class="h">${h}</span>.<span class="p">${p}</span>.<span class="s">${s}</span>`;
    $('#jwtHeader').innerHTML = prettyJson(JSON.parse(b64(h)));
    $('#jwtPayload').innerHTML = prettyJson(JSON.parse(b64(p)));
    if (flash) {
      const card = $('#tokenCard');
      card.classList.remove('flash');
      void card.offsetWidth;
      card.classList.add('flash');
      $('#rotationNote').textContent = `New token issued ${new Date().toLocaleTimeString()}. The refresh cookie was rotated too: the previous one is now dead, and replaying it would end this session.`;
    }
    tick();
  }

  function tick() {
    if (!auth.token) return;
    const total = Math.max(1, auth.expiresAt - auth.issuedAt);
    const left = Math.max(0, auth.expiresAt - Date.now());
    const pct = (left / total) * 100;
    $('#expiryFill').style.width = `${pct}%`;
    $('#expiryFill').classList.toggle('low', pct < 20);
    const m = Math.floor(left / 60000), sec = Math.floor((left % 60000) / 1000);
    $('#expiryText').textContent = left ? `expires in ${m}:${String(sec).padStart(2, '0')}` : 'expired';
  }
  setInterval(tick, 1000);

  $('#refreshBtn').addEventListener('click', async () => {
    if (await refresh()) toast('Token refreshed and refresh cookie rotated');
  });
  $('#copyBtn').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(auth.token); toast('Access token copied. Paste it into Swagger\'s Authorize.'); }
    catch { toast('Copy failed', true); }
  });

  // ---------------------------------------------------------------- access checks
  const CHECKS = [
    { path: '/api/demo/public', need: 'nobody: public' },
    { path: '/api/demo/user', need: 'any valid token' },
    { path: '/api/demo/moderator', need: 'permission content:moderate' },
    { path: '/api/demo/admin', need: 'role ADMIN' },
    { path: '/api/admin/users', need: 'permission users:read' },
    { path: '/api/admin/audit', need: 'permission audit:read' },
  ];

  function renderChecks() {
    $('#checks').innerHTML = CHECKS.map((c, i) => `
      <li><span class="ep">GET ${c.path}</span><span class="need">${c.need}</span>
        <span class="status"><button class="btn ghost sm" data-check="${i}">Test</button></span></li>`).join('');
    $$('[data-check]').forEach((b) => b.onclick = () => runCheck(Number(b.dataset.check)));
  }

  async function runCheck(i) {
    const slot = $$('#checks .status')[i];
    const { res, data } = await raw(CHECKS[i].path);
    const cls = res.ok ? 'ok' : res.status === 403 ? 'denied' : 'unauth';
    const label = res.ok ? `${res.status} OK` : `${res.status} ${data?.code || ''}`;
    slot.innerHTML = `<span class="code-pill ${cls}" title="${esc(data?.message || '')}">${esc(label)}</span>`;
  }

  $('#testAllBtn').addEventListener('click', () => CHECKS.forEach((_, i) => runCheck(i)));

  $('#tamperBtn').addEventListener('click', async () => {
    const [h, p, s] = auth.token.split('.');
    const payload = JSON.parse(b64(p));
    payload.role = 'ADMIN';
    payload.exp += 365 * 24 * 3600;   // also stretch the expiry by a year, so the payload always changes
    payload.perms = ['audit:read', 'content:moderate', 'profile:read', 'profile:write', 'users:read', 'users:write'];
    const forgedPayload = btoa(unescape(encodeURIComponent(JSON.stringify(payload)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const { res, data } = await raw('/api/demo/admin', { token: `${h}.${forgedPayload}.${s}` });
    const box = $('#tamperResult');
    box.hidden = false;
    box.className = `result ${res.ok ? 'bad' : ''}`;
    box.innerHTML = res.ok
      ? 'The forged token was accepted. That should never happen!'
      : `Rejected with <b>${res.status} ${esc(data?.code)}</b>: the HMAC signature no longer matches the edited payload, so the server can't be fooled into granting ADMIN or a longer life.`;
  });

  // ---------------------------------------------------------------- sessions
  async function loadSessions() {
    try {
      const sessions = await api('/api/account/sessions');
      $('#sessions').innerHTML = sessions.map((s) => `
        <li>
          <span class="dot good"></span>
          <div class="grow">
            <div class="title">${esc(s.device)}${s.current ? '<span class="tag">THIS DEVICE</span>' : ''}</div>
            <div class="meta">${esc(s.ipAddress)} · signed in ${ago(s.signedInAt)} · last refresh ${ago(s.lastRefreshedAt)}</div>
          </div>
          ${s.current ? '' : `<button class="btn ghost sm" data-revoke="${esc(s.id)}">Sign out</button>`}
        </li>`).join('') || '<li class="muted">No active sessions</li>';
      $$('[data-revoke]').forEach((b) => b.onclick = async () => {
        await api(`/api/account/sessions/${b.dataset.revoke}`, { method: 'DELETE' });
        toast('Device signed out. Its tokens stopped working immediately.');
        loadSessions();
        loadEvents();
      });
    } catch (e) { if (e.status !== 401) toast(e.message, true); }
  }

  $('#logoutAllBtn').addEventListener('click', async () => {
    if (!confirm('Sign out on every device, including this one?')) return;
    await api('/api/auth/logout-all', { method: 'POST' });
    signedOut('Signed out on every device.');
  });

  $('#logoutBtn').addEventListener('click', async () => {
    await raw('/api/auth/logout', { method: 'POST', token: null });
    signedOut();
    toast('Signed out');
  });

  // ---------------------------------------------------------------- activity + account
  const EVENT_TONE = {
    LOGIN_SUCCESS: 'good', REGISTERED: 'good', ACCOUNT_ENABLED: 'good', ACCOUNT_UNLOCKED: 'good',
    LOGIN_FAILED: 'warn', LOCKED_LOGIN_ATTEMPT: 'warn', SESSION_REVOKED: 'warn', LOGOUT_ALL: 'warn', ROLE_CHANGED: 'warn',
    ACCOUNT_LOCKED: 'bad', TOKEN_REUSE_DETECTED: 'bad', ACCOUNT_DISABLED: 'bad', SESSIONS_REVOKED_BY_ADMIN: 'bad',
  };
  const label = (t) => t.charAt(0) + t.slice(1).toLowerCase().replace(/_/g, ' ');

  async function loadEvents() {
    try {
      const events = await api('/api/account/events');
      $('#events').innerHTML = events.map((e) => `
        <li><span class="dot ${EVENT_TONE[e.type] || ''}"></span>
          <div class="grow"><div class="title">${esc(label(e.type))}</div>
          <div class="meta">${ago(e.occurredAt)} · ${esc(e.ipAddress || '')}${e.actor ? ` · by ${esc(e.actor)}` : ''}${e.detail ? ` · ${esc(e.detail)}` : ''}</div></div>
        </li>`).join('') || '<li class="muted">Nothing yet</li>';
    } catch (e) { if (e.status !== 401) toast(e.message, true); }
  }

  async function loadFacts() {
    try {
      const me = await api('/api/account');
      $('#facts').innerHTML = `
        <dt>Username</dt><dd>${esc(me.username)}</dd>
        <dt>Email</dt><dd>${esc(me.email)}</dd>
        <dt>Role</dt><dd><span class="pill ${me.role}">${me.role}</span></dd>
        <dt>Permissions</dt><dd>${me.permissions.map((p) => `<span class="perm">${esc(p)}</span>`).join('')}</dd>
        <dt>Member since</dt><dd>${when(me.createdAt)}</dd>
        <dt>Password set</dt><dd>${when(me.passwordChangedAt)}</dd>`;
    } catch (e) { if (e.status !== 401) toast(e.message, true); }
  }

  $('#passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const alert = $('.alert', f);
    alert.hidden = true;
    try {
      await api('/api/account/password', { method: 'PUT', body: { currentPassword: f.currentPassword.value, newPassword: f.newPassword.value } });
      f.reset();
      signedOut('Password changed. Every session was signed out; sign in with your new password.');
    } catch (err) {
      alert.textContent = err.fieldErrors ? Object.values(err.fieldErrors).join('. ') : err.message;
      alert.hidden = false;
    }
  });

  // ---------------------------------------------------------------- admin
  let searchTimer;
  $('#userSearch').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadUsers, 250); });

  async function loadUsers() {
    const canWrite = auth.user.permissions.includes('users:write');
    $('#adminNote').textContent = canWrite
      ? 'You have users:write: change roles, disable, unlock and sign users out. Changes apply to their tokens at once.'
      : 'You have users:read only (moderator): you can view users but not change them.';
    try {
      const page = await api(`/api/admin/users?size=50&q=${encodeURIComponent($('#userSearch').value)}`);
      const state = (u) => (!u.enabled ? '<span class="state disabled">Disabled</span>'
        : u.locked ? `<span class="state locked" title="until ${when(u.lockedUntil)}">Locked</span>` : '<span class="state active">Active</span>');
      $('#usersTable').innerHTML = `
        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Sessions</th><th>Last sign-in</th>${canWrite ? '<th>Actions</th>' : ''}</tr></thead>
        <tbody>${page.content.map((u) => {
          const self = u.id === auth.user.id;
          return `<tr>
            <td><b>${esc(u.username)}</b>${self ? ' <span class="muted">(you)</span>' : ''}<br><span class="muted">${esc(u.email)}</span></td>
            <td>${canWrite && !self
              ? `<select data-role="${u.id}" aria-label="Role of ${esc(u.username)}">${['USER', 'MODERATOR', 'ADMIN'].map((r) => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>`
              : `<span class="pill ${u.role}">${u.role}</span>`}</td>
            <td>${state(u)}${u.failedAttempts ? ` <span class="muted">${u.failedAttempts} failed</span>` : ''}</td>
            <td>${u.activeSessions}</td>
            <td>${u.lastLoginAt ? ago(u.lastLoginAt) : '<span class="muted">never</span>'}</td>
            ${canWrite ? `<td>${self ? '' : `
              <button class="btn ghost sm" data-status="${u.id}" data-enable="${!u.enabled}">${u.enabled ? 'Disable' : 'Enable'}</button>
              ${u.locked ? `<button class="btn ghost sm" data-unlock="${u.id}">Unlock</button>` : ''}
              ${u.activeSessions ? `<button class="btn ghost sm" data-kick="${u.id}">Sign out</button>` : ''}`}</td>` : ''}
          </tr>`;
        }).join('')}</tbody>`;

      const act = async (fn, msg) => {
        try { await fn(); toast(msg); loadUsers(); loadAudit(); } catch (e) { toast(e.message, true); loadUsers(); }
      };
      $$('[data-role]').forEach((s) => s.onchange = () => act(
        () => api(`/api/admin/users/${s.dataset.role}/role`, { method: 'PUT', body: { role: s.value } }), `Role changed to ${s.value}`));
      $$('[data-status]').forEach((b) => b.onclick = () => act(
        () => api(`/api/admin/users/${b.dataset.status}/status`, { method: 'PUT', body: { enabled: b.dataset.enable === 'true' } }),
        b.dataset.enable === 'true' ? 'Account enabled' : 'Account disabled and signed out everywhere'));
      $$('[data-unlock]').forEach((b) => b.onclick = () => act(
        () => api(`/api/admin/users/${b.dataset.unlock}/unlock`, { method: 'POST' }), 'Account unlocked'));
      $$('[data-kick]').forEach((b) => b.onclick = () => act(
        () => api(`/api/admin/users/${b.dataset.kick}/sessions`, { method: 'DELETE' }), 'User signed out everywhere'));
    } catch (e) { if (e.status !== 401) toast(e.message, true); }
  }

  const EVENT_TYPES = ['REGISTERED', 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'ACCOUNT_LOCKED', 'LOCKED_LOGIN_ATTEMPT', 'LOGOUT', 'LOGOUT_ALL',
    'TOKEN_REUSE_DETECTED', 'PASSWORD_CHANGED', 'PROFILE_UPDATED', 'SESSION_REVOKED', 'ROLE_CHANGED', 'ACCOUNT_DISABLED',
    'ACCOUNT_ENABLED', 'ACCOUNT_UNLOCKED', 'SESSIONS_REVOKED_BY_ADMIN'];
  $('#auditType').innerHTML = '<option value="">All events</option>' + EVENT_TYPES.map((t) => `<option value="${t}">${label(t)}</option>`).join('');
  $('#auditType').addEventListener('change', loadAudit);

  async function loadAudit() {
    if ($('#auditCard').hidden) return;
    try {
      const type = $('#auditType').value;
      const page = await api(`/api/admin/audit?size=30${type ? `&type=${type}` : ''}`);
      $('#auditTable').innerHTML = `
        <thead><tr><th>When</th><th>Event</th><th>Account</th><th>By</th><th>IP</th><th>Detail</th></tr></thead>
        <tbody>${page.content.map((e) => `<tr>
          <td>${when(e.occurredAt)}</td>
          <td><span class="dot ${EVENT_TONE[e.type] || ''}" style="display:inline-block;margin:0 6px 0 0"></span>${esc(label(e.type))}</td>
          <td>${esc(e.username || '—')}</td><td>${esc(e.actor || '')}</td><td>${esc(e.ipAddress || '')}</td>
          <td>${esc(e.detail || '')}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">No events</td></tr>'}</tbody>`;
    } catch (e) { if (e.status !== 401) toast(e.message, true); }
  }

  boot();
})();
