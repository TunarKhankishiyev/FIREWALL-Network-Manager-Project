(() => {
  const $ = id => document.getElementById(id);

  // ── Auth state ───────────────────────────────────────────────────────────
  let AUTH_TOKEN    = sessionStorage.getItem('fw_token')    || '';
  let AUTH_USERNAME = sessionStorage.getItem('fw_username') || '';
  let AUTH_ROLE     = sessionStorage.getItem('fw_role')     || '';
  let AUTH_ISADMIN  = AUTH_ROLE.toLowerCase() === 'admin';
  let API_BASE      = localStorage.getItem('fwApiBase') || '';

  // ── Fetch helpers ────────────────────────────────────────────────────────
  async function tryFetch(url, opts = {}, ms = 6000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
      const headers = { ...(opts.headers || {}) };
      if (AUTH_TOKEN) headers['Authorization'] = 'Bearer ' + AUTH_TOKEN;
      const res  = await fetch(url, { ...opts, headers, signal: ctrl.signal });
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch { }
      return { ok: res.ok, status: res.status, data, text };
    } catch (e) {
      return { ok: false, status: 0, data: null, text: String(e) };
    } finally { clearTimeout(t); }
  }

  async function detectBase() {
    const candidates = [
      API_BASE,
      location.origin.startsWith('http') ? location.origin : '',
      'http://localhost:2309',
      'http://127.0.0.1:2309',
    ].filter(Boolean);
    for (const base of candidates) {
      const r = await tryFetch(base + '/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '', password: '' })
      }, 1500);
      if (r.status !== 0) {
        API_BASE = base.replace(/\/+$/, '');
        localStorage.setItem('fwApiBase', API_BASE);
        return API_BASE;
      }
    }
    return null;
  }

  async function api(path, opts = {}) {
    if (!API_BASE) await detectBase();
    return tryFetch(API_BASE + path, opts);
  }

  async function guarded(path, opts = {}) {
    const r = await api(path, opts);
    if (r && r.status === 401) {
      AUTH_TOKEN = '';
      sessionStorage.removeItem('fw_token');
      showLogin('Session expired. Please sign in again.');
      return null;
    }
    return r;
  }

  // ── Toast message ────────────────────────────────────────────────────────
  let _msgTimer;
  function toast(text, color) {
    const el = $('msgBar');
    if (!el) return;
    el.textContent = text;
    el.style.borderLeftColor = color || 'var(--accent)';
    el.classList.add('show');
    clearTimeout(_msgTimer);
    _msgTimer = setTimeout(() => el.classList.remove('show'), 3500);
  }
  function setMsg(t) {
    const el = $('msg'); if (el) el.textContent = t || '';
    if (t) toast(t);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────
  function fmt(v) {
    if (!v) return '';
    const d = new Date(v);
    return isNaN(d.getTime()) ? String(v) : d.toLocaleString();
  }

  function bind(id, fn) {
    const el = $(id);
    if (!el) return;
    el.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); fn(); });
  }

  // ── Tab system ───────────────────────────────────────────────────────────
  function initTabs() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const panel = $('tab-' + tab);
        if (panel) panel.classList.add('active');
      });
    });
  }

  // ── Login / Logout ───────────────────────────────────────────────────────
  function showLogin(err) {
    $('loginScreen').style.display = 'flex';
    $('appShell').style.display    = 'none';
    $('loginError').textContent    = err || '';
    $('loginUser').value = '';
    $('loginPass').value = '';
    setTimeout(() => $('loginUser')?.focus(), 50);
  }

  function showMain() {
    $('loginScreen').style.display = 'none';
    $('appShell').style.display    = 'flex';

    // Update badges
    const badge = $('userBadge');
    if (badge) badge.textContent = AUTH_USERNAME + '  [' + AUTH_ROLE + ']';

    const role = $('roleBadge');
    if (role) {
      role.textContent = AUTH_ISADMIN ? '● ADMIN' : '● VIEWER';
      role.className   = AUTH_ISADMIN ? '' : 'viewer';
    }

    // Show/hide admin-only elements
    document.querySelectorAll('.admin-only').forEach(el => {
      el.style.display = AUTH_ISADMIN ? '' : 'none';
    });
  }

  async function doLogin() {
    const username = ($('loginUser')?.value || '').trim();
    const password = $('loginPass')?.value || '';
    if (!username) { $('loginError').textContent = 'Username is required.'; return; }

    const btn = $('loginBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Signing in...'; }

    const r = await api('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (btn) { btn.disabled = false; btn.textContent = 'SIGN IN  →'; }

    if (!r?.ok || !r.data?.token) {
      $('loginError').textContent = r?.data?.error || 'Invalid credentials.';
      $('loginForm').classList.add('shake');
      setTimeout(() => $('loginForm')?.classList.remove('shake'), 500);
      return;
    }

    AUTH_TOKEN    = r.data.token;
    AUTH_USERNAME = r.data.username;
    AUTH_ROLE     = r.data.role;
    AUTH_ISADMIN  = r.data.isAdmin;
    sessionStorage.setItem('fw_token',    AUTH_TOKEN);
    sessionStorage.setItem('fw_username', AUTH_USERNAME);
    sessionStorage.setItem('fw_role',     AUTH_ROLE);

    showMain();
    await refreshRules();
    await refreshLogs();
  }

  async function doLogout() {
    await api('/api/logout', { method: 'POST' });
    AUTH_TOKEN = AUTH_USERNAME = AUTH_ROLE = '';
    AUTH_ISADMIN = false;
    sessionStorage.clear();
    showLogin();
  }

  // ── Rules ────────────────────────────────────────────────────────────────
  let ALL_RULES = [], RULES_VISIBLE = 3, RULES_EXPANDED = false;
  const RULES_BASE = 3;

  function renderRules() {
    const tbody = $('rulesBody'), btn = $('btnToggleRules');
    if (!tbody) return;
    tbody.innerHTML = '';

    ALL_RULES.slice(0, RULES_VISIBLE).forEach((rule, idx) => {
      const name       = rule.name       ?? '';
      const remoteIp   = rule.remoteIp   ?? 'Any';
      const port       = rule.port       ?? 0;
      const protocol   = rule.protocol   ?? 'Any';
      const action     = rule.action     ?? '';
      const expiresText = rule.expiresText ?? 'Permanent';

      const isBlock  = action.toLowerCase() === 'block';
      const isPerm   = expiresText === 'Permanent';
      const actionBadge   = `<span class="badge ${isBlock ? 'badge-block' : 'badge-allow'}">${action}</span>`;
      const expiresBadge  = isPerm ? `<span class="badge badge-perm">Permanent</span>` : expiresText;

      const delBtn = AUTH_ISADMIN
        ? `<button class="btn btn-danger" style="padding:4px 10px;font-size:11px" data-name="${encodeURIComponent(name)}">✕ Remove</button>`
        : '';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${idx + 1}</td>
        <td>${remoteIp}</td>
        <td>${port === 0 ? '—' : port}</td>
        <td>${protocol}</td>
        <td>${actionBadge}</td>
        <td>${expiresBadge}</td>
        <td>${delBtn}</td>
      `;
      tr.querySelector('button')?.addEventListener('click', async e => {
        const enc = e.currentTarget.getAttribute('data-name');
        const del = await guarded('/api/rules?name=' + enc, { method: 'DELETE' });
        if (!del) return;
        if (!del.ok) { toast('Delete error: ' + (del.data?.error || del.status), 'var(--danger)'); return; }
        toast('Rule removed ✓', 'var(--success)');
        await refreshRules();
      });
      tbody.appendChild(tr);
    });

    if (!btn) return;
    if (ALL_RULES.length <= RULES_BASE) { btn.style.display = 'none'; return; }
    btn.style.display = 'inline-flex';
    btn.textContent   = RULES_VISIBLE < ALL_RULES.length
      ? `Show more (${ALL_RULES.length - RULES_VISIBLE} left)` : 'Show less';
    btn.dataset.mode  = RULES_VISIBLE < ALL_RULES.length ? 'more' : 'less';
  }

  async function refreshRules() {
    const r = await guarded('/api/rules');
    if (!r) return;
    if (!r.ok || !Array.isArray(r.data)) return;
    ALL_RULES     = r.data;
    RULES_VISIBLE = RULES_EXPANDED ? ALL_RULES.length : RULES_BASE;
    renderRules();
  }

  async function addRule() {
    const ip       = ($('ip')?.value || '').trim();
    const port     = parseInt($('port')?.value || '0') || 0;
    const protocol = $('protocol')?.value || 'Any';
    const action   = $('action')?.value   || 'Block';
    const perm     = !!$('permanent')?.checked;
    const minutes  = parseInt($('minutes')?.value || '0') || 0;
    if (!ip) return setMsg('Remote IP is required');

    const r = await guarded('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ remoteIp: ip, port, protocol, action, permanent: perm, minutes: perm ? 0 : minutes })
    });
    if (!r) return;
    if (!r.ok || r.data?.ok === false) { toast('Add error: ' + (r.data?.error || r.status), 'var(--danger)'); return; }
    toast('Rule added ✓', 'var(--success)');
    $('ip').value = '';
    await refreshRules();
  }

  async function blockAll() {
    const r = await guarded('/api/rules/blockall', { method: 'POST' });
    if (!r) return;
    if (!r.ok) { toast('BlockAll error: ' + (r.data?.error || r.status), 'var(--danger)'); return; }
    toast('Block ALL applied ✓', 'var(--success)');
    await refreshRules();
  }

  // ── Firewall toggles ─────────────────────────────────────────────────────
  async function toggle(path, label, statusId) {
    const r = await guarded(path, { method: 'POST' });
    if (!r) return;
    if (!r.ok || r.data?.ok === false) {
      toast(label + ' error: ' + (r.data?.error || r.status), 'var(--danger)');
      return;
    }
    toast(label + ' ✓', 'var(--success)');
    const el = $(statusId);
    if (el) el.textContent = 'Status: ' + label;
  }

  // ── Built-in rules ───────────────────────────────────────────────────────
  async function toggleBuiltin(action) {
    const isDisable = action === 'disable';
    if (isDisable && !confirm(
      '⚡ This will DISABLE all Windows built-in inbound rules\n' +
      'and set default inbound policy to BLOCK.\n\n' +
      'Only your FW- rules will control traffic.\n' +
      'This may break RDP, file sharing and other services.\n\nContinue?'
    )) return;

    const btn = $(isDisable ? 'btnDisableBuiltin' : 'btnRestoreBuiltin');
    const status = $('builtinStatus');
    if (btn) { btn.disabled = true; btn.textContent = 'Working...'; }
    if (status) status.textContent = '⏳ Running — may take a few seconds...';

    const r = await guarded('/api/firewall/builtin/' + action, { method: 'POST' });

    if (btn) {
      btn.disabled    = false;
      btn.textContent = isDisable ? '⚡ Disable All Built-in Rules' : '↩ Restore Built-in Rules';
    }
    if (!r) return;
    if (!r.ok) {
      if (status) status.textContent = '❌ Error: ' + (r.data?.error || r.status);
      toast('Failed: ' + (r.data?.error || ''), 'var(--danger)');
      return;
    }
    const msg = isDisable
      ? '✅ Built-in rules disabled — only FW- rules active. Default inbound: BLOCK.'
      : '✅ Built-in rules restored. Default inbound policy: ALLOW.';
    if (status) status.textContent = msg;
    toast(isDisable ? 'Built-in rules disabled ✓' : 'Built-in rules restored ✓',
          isDisable ? 'var(--danger)' : 'var(--success)');
    await refreshLogs();
  }

  // ── Ping ─────────────────────────────────────────────────────────────────
  async function doPing() {
    const host  = ($('pingHost')?.value || '').trim();
    const count = parseInt($('pingCount')?.value || '4') || 4;
    const out   = $('pingOut');
    if (!host) { out.textContent = 'Host is required.'; return; }
    out.textContent = '⏳ Pinging ' + host + '...';

    const r = await guarded('/api/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, count })
    });
    if (!r) return;
    if (!r.ok || r.data?.ok === false) { out.textContent = 'Error: ' + (r.data?.error || r.text); return; }

    const s = r.data.summary;
    let txt = `Host: ${r.data.host}\n`;
    txt += `Sent: ${s.sent}  Received: ${s.received}  Lost: ${s.lost}\n`;
    txt += `Min: ${s.minMs}ms  Max: ${s.maxMs}ms  Avg: ${s.avgMs}ms\n\n`;
    for (const x of r.data.results)
      txt += x.status === 'Success'
        ? `#${x.seq}  Reply from ${x.address}  time=${x.rttMs}ms\n`
        : x.status === 'Error' ? `#${x.seq}  Error: ${x.error}\n`
        : `#${x.seq}  ${x.status}\n`;
    out.textContent = txt;
  }

  // ── Logs ─────────────────────────────────────────────────────────────────
  let ALL_LOGS = [], LOGS_VISIBLE = 10, LOGS_EXPANDED = false;

  function logTypeBadge(type) {
    const t = (type || '').toUpperCase();
    const cls = t.includes('WINFW') ? 'log-WINFW'
              : t.includes('APPFW') ? 'log-APPFW'
              : t.includes('AUTOBLOCK') ? 'log-AUTOBLOCK'
              : t.includes('BLOCK') ? 'log-BLOCK'
              : 'log-INFO';
    return `<span class="log-type ${cls}">${type}</span>`;
  }

  function renderLogs() {
    const tbody = $('logsBody'), btn = $('btnToggleLogs');
    if (!tbody) return;
    tbody.innerHTML = '';
    ALL_LOGS.slice(0, LOGS_VISIBLE).forEach(x => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="white-space:nowrap;color:var(--dim);font-size:11px">${fmt(x.time ?? x.Time)}</td>
        <td>${logTypeBadge(x.type ?? x.Type ?? '')}</td>
        <td style="font-size:12px">${x.message ?? x.Message ?? ''}</td>
      `;
      tbody.appendChild(tr);
    });
    if (!btn) return;
    if (ALL_LOGS.length <= 10) { btn.style.display = 'none'; return; }
    btn.style.display = 'inline-flex';
    btn.textContent   = LOGS_VISIBLE < ALL_LOGS.length
      ? `Show more (${ALL_LOGS.length - LOGS_VISIBLE} left)` : 'Show less';
    btn.dataset.mode  = LOGS_VISIBLE < ALL_LOGS.length ? 'more' : 'less';
  }

  async function refreshLogs() {
    const r = await guarded('/api/logs');
    if (!r || !r.ok || !Array.isArray(r.data)) return;
    ALL_LOGS     = r.data;
    LOGS_VISIBLE = LOGS_EXPANDED ? ALL_LOGS.length : 10;
    renderLogs();
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  async function init() {
    await detectBase();
    initTabs();

    // Login wiring
    bind('loginBtn',   doLogin);
    bind('loginClose', () => window.close());
    $('loginPass')?.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    $('loginUser')?.addEventListener('keydown', e => { if (e.key === 'Enter') $('loginPass')?.focus(); });

    // Eye toggle
    const eye = $('loginEye');
    if (eye) eye.addEventListener('click', () => {
      const p = $('loginPass');
      p.type = p.type === 'password' ? 'text' : 'password';
      eye.style.color = p.type === 'text' ? 'var(--accent)' : 'var(--dim)';
    });

    // Main buttons
    bind('btnLogout',         doLogout);
    bind('btnAdd',            addRule);
    bind('btnBlockAll',       blockAll);
    bind('btnRefreshLogs',    refreshLogs);
    bind('btnPing',           doPing);
    bind('btnWinOn',   () => toggle('/api/firewall/windows/on',  'Windows Firewall ON',  'fwWinStatus'));
    bind('btnWinOff',  () => toggle('/api/firewall/windows/off', 'Windows Firewall OFF', 'fwWinStatus'));
    bind('btnAppOn',   () => toggle('/api/firewall/app/on',      'App Rules ON',         'fwAppStatus'));
    bind('btnAppOff',  () => toggle('/api/firewall/app/off',     'App Rules OFF',        'fwAppStatus'));
    bind('btnDisableBuiltin', () => toggleBuiltin('disable'));
    bind('btnRestoreBuiltin', () => toggleBuiltin('restore'));

    bind('btnToggleRules', () => {
      const btn = $('btnToggleRules'); if (!btn) return;
      if (btn.dataset.mode === 'more') { RULES_EXPANDED = true;  RULES_VISIBLE = ALL_RULES.length; }
      else                             { RULES_EXPANDED = false; RULES_VISIBLE = RULES_BASE; }
      renderRules();
    });
    bind('btnToggleLogs', () => {
      const btn = $('btnToggleLogs'); if (!btn) return;
      if (btn.dataset.mode === 'more') { LOGS_EXPANDED = true;  LOGS_VISIBLE = ALL_LOGS.length; }
      else                             { LOGS_EXPANDED = false; LOGS_VISIBLE = 10; }
      renderLogs();
    });

    // Auto-refresh
    setInterval(() => { if (AUTH_TOKEN) { refreshRules(); refreshLogs(); } }, 5000);

    // Restore session
    if (AUTH_TOKEN) {
      const check = await api('/api/me');
      if (!check?.data?.ok) {
        AUTH_TOKEN = '';
        sessionStorage.clear();
        showLogin('Session expired. Please sign in again.');
        return;
      }
      AUTH_USERNAME = check.data.username;
      AUTH_ROLE     = check.data.role;
      AUTH_ISADMIN  = check.data.isAdmin;
      showMain();
      await refreshRules();
      await refreshLogs();
    } else {
      showLogin();
    }
  }

  window.addEventListener('DOMContentLoaded', init);
})();
