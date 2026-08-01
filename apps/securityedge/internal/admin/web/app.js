'use strict';

const state = {
  token: sessionStorage.getItem('securityedge_token') || '',
  overview: null,
  policies: null,
  rules: [],
  bans: [],
  securityCursor: 0,
  securityHasMore: false,
  selectedPolicy: 'default',
  trend: []
};

const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString();
const pct = n => `${(Number(n || 0) * 100).toFixed(1)}%`;
const ms = n => `${Number(n || 0).toFixed(2)} ms`;
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const csv = value => String(value || '').split(',').map(x => x.trim()).filter(Boolean);

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${state.token}`);
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {...options, headers});
  let data = null;
  try { data = await response.json(); } catch {}
  if (response.status === 401) {
    lock();
    throw new Error('Invalid or expired admin token.');
  }
  if (response.status === 429) throw new Error('Admin authentication is temporarily locked.');
  if (!response.ok) throw new Error(data?.error?.message || `HTTP ${response.status}`);
  return data;
}

async function download(path, filename, contentType) {
  const response = await fetch(path, {headers: {Authorization: `Bearer ${state.token}`}});
  if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
  const blob = await response.blob();
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([blob], {type: contentType}));
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function toast(message) {
  const element = $('toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove('show'), 3000);
}

function lock() {
  $('login').classList.add('visible');
  $('live-dot').classList.remove('live');
  $('connection-label').textContent = 'Not connected';
  sessionStorage.removeItem('securityedge_token');
  state.token = '';
}

async function login(token) {
  state.token = token;
  await api('/api/v1/session');
  sessionStorage.setItem('securityedge_token', token);
  $('login').classList.remove('visible');
  $('live-dot').classList.add('live');
  $('connection-label').textContent = 'Connected';
  await refreshAll();
}

function setView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  document.querySelectorAll('.nav-item').forEach(v => v.classList.toggle('active', v.dataset.view === name));
  $('page-title').textContent = ({overview:'Overview',security:'Security events',protection:'Traffic protection',traffic:'Traffic & cache',routes:'Routes & origins',policies:'Policies',system:'System'})[name];
  if (name === 'security') loadSecurity(true);
  if (name === 'protection') loadBans();
  if (name === 'policies' && !state.policies) loadPolicies();
}

async function refreshAll() {
  try {
    const [overview, policies, rules, bans] = await Promise.all([
      api('/api/v1/dashboard/overview'),
      api('/api/v1/policies'),
      api('/api/v1/rules'),
      api('/api/v1/bans')
    ]);
    state.overview = overview;
    state.policies = policies;
    state.rules = rules.rules || [];
    state.bans = bans.bans || [];
    renderAll();
    $('last-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
    $('live-dot').classList.add('live');
  } catch (error) {
    toast(error.message);
    $('live-dot').classList.remove('live');
  }
}

function renderAll() {
  renderOverview();
  renderProtection();
  renderTraffic();
  renderRoutes();
  renderPolicies();
  renderSystem();
  renderRules();
  renderBans();
  loadEdgeLogs();
}

function rejectedCount(total) {
  return Number(total.blocked || 0) + Number(total.rate_limited || 0) + Number(total.overload_rejected || 0) + Number(total.banned_rejected || 0);
}

function renderOverview() {
  const overview = state.overview || {};
  const security = overview.security_metrics || {};
  const total = security.total || {};
  const edgeMetrics = overview.edgeproxy_metrics || {};
  const edgeTotal = edgeMetrics.total || {};
  const edgeStatus = overview.edgeproxy_status || {};
  $('kpi-requests').textContent = fmt(edgeTotal.requests);
  $('kpi-rps').textContent = `${Number(edgeMetrics.requests_per_second || 0).toFixed(2)} req/s`;
  $('kpi-blocked').textContent = fmt(rejectedCount(total));
  $('kpi-block-rate').textContent = `${pct(total.block_rate)} rejection rate`;
  $('kpi-detections').textContent = fmt(total.detections);
  $('kpi-detection-rate').textContent = `${pct(total.detection_rate)} detection rate`;
  $('kpi-cache').textContent = pct(edgeTotal.cache_hit_ratio);
  $('kpi-cache-counts').textContent = `${fmt(edgeTotal.cache_hits)} hits · ${fmt(edgeTotal.cache_misses)} misses`;
  $('kpi-p95').textContent = ms(total.latency?.p95_ms);
  $('kpi-upstream').textContent = `${ms(edgeTotal.upstream?.latency_ms?.average)} upstream avg`;
  const routes = edgeStatus.routes || [];
  const origins = routes.flatMap(route => route.upstreams || []);
  const healthy = origins.filter(origin => origin.healthy).length;
  $('kpi-origins').textContent = `${healthy}/${origins.length}`;
  $('kpi-routes').textContent = `${routes.filter(route => route.ready).length}/${routes.length} routes ready`;
  state.trend.push({requests: edgeTotal.requests || 0, blocked: rejectedCount(total), time: Date.now()});
  if (state.trend.length > 30) state.trend.shift();
  drawTrend();
  renderBars($('rule-bars'), total.rules || {});
  renderSecurityRows($('recent-security'), overview.security_logs?.entries || [], false, 7);
}

function drawTrend() {
  const canvas = $('trend-chart');
  const dpr = devicePixelRatio || 1;
  const width = canvas.clientWidth || 600;
  const height = 240;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const context = canvas.getContext('2d');
  context.scale(dpr, dpr);
  context.clearRect(0, 0, width, height);
  context.strokeStyle = '#25324c';
  context.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    const y = 20 + i * (height - 40) / 4;
    context.beginPath(); context.moveTo(0, y); context.lineTo(width, y); context.stroke();
  }
  const maximum = Math.max(1, ...state.trend.flatMap(point => [point.requests, point.blocked]));
  const draw = (key, color) => {
    context.strokeStyle = color; context.lineWidth = 2; context.beginPath();
    state.trend.forEach((point, index) => {
      const x = state.trend.length === 1 ? width / 2 : index * (width / (state.trend.length - 1));
      const y = height - 20 - (point[key] / maximum) * (height - 40);
      index ? context.lineTo(x, y) : context.moveTo(x, y);
    });
    context.stroke();
  };
  draw('requests', '#67a6ff');
  draw('blocked', '#ff7188');
}

function renderBars(element, values, limit = 8) {
  const entries = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, limit);
  if (!entries.length) {
    element.className = 'bar-list empty';
    element.textContent = 'No data yet.';
    return;
  }
  element.className = 'bar-list';
  const maximum = entries[0][1];
  element.innerHTML = entries.map(([name, value]) => `<div class="bar-row"><span>${esc(name)}</span><div class="bar-track"><div class="bar-fill" style="width:${value / maximum * 100}%"></div></div><strong>${fmt(value)}</strong></div>`).join('');
}

function actionClass(action) {
  const value = String(action || '').toLowerCase();
  return ['allow','log','block','rate_limit','overload','banned','admin'].includes(value) ? value : 'warn';
}

function renderSecurityRows(element, entries, full = true, limit = 100) {
  const rows = entries.slice(0, limit);
  if (!rows.length) {
    element.innerHTML = `<tr><td colspan="${full ? 9 : 8}" class="muted">No security events.</td></tr>`;
    return;
  }
  element.innerHTML = rows.map(entry => {
    const request = `<strong>${esc(entry.method || '—')}</strong> ${esc(entry.path || '—')}`;
    const rules = (entry.rule_ids || []).map(rule => `<span class="badge warn">${esc(rule)}</span>`).join(' ') || '<span class="muted">—</span>';
    const common = `<td><span class="badge ${actionClass(entry.action)}">${esc(entry.action || entry.event)}</span></td><td>${esc(entry.reason || '—')}</td><td>${esc(entry.route || '—')}</td><td>${esc(entry.client_ip || '—')}</td><td>${request}</td><td>${rules}</td><td>${fmt(entry.score)}</td>`;
    return full
      ? `<tr><td>${fmt(entry.sequence)}</td><td>${esc(new Date(entry.timestamp).toLocaleString())}</td>${common}</tr>`
      : `<tr><td>${esc(new Date(entry.timestamp).toLocaleTimeString())}</td>${common}</tr>`;
  }).join('');
}

async function loadSecurity(reset) {
  try {
    if (reset) state.securityCursor = 0;
    const form = new FormData($('security-filters'));
    const query = new URLSearchParams();
    for (const [key, value] of form) if (value) query.set(key, value);
    query.set('limit', '100');
    if (state.securityCursor) query.set('before_sequence', state.securityCursor);
    const data = await api(`/api/v1/logs?${query}`);
    renderSecurityRows($('security-table'), data.entries || [], true, 100);
    state.securityCursor = data.next_before_sequence || 0;
    state.securityHasMore = Boolean(data.has_more);
    $('older-security').disabled = !state.securityHasMore;
    $('security-count').textContent = `${data.returned || 0} shown · ${data.retained || 0} retained · ${data.dropped || 0} overwritten`;
  } catch (error) { toast(error.message); }
}

function metricRows(items) {
  return items.map(([key, value]) => `<div class="metric-row"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`).join('');
}

function renderProtection() {
  const total = state.overview?.security_metrics?.total || {};
  const status = state.overview?.security_status || {};
  $('protect-client-rate').textContent = fmt(total.client_rate_limited);
  $('protect-global-rate').textContent = fmt(total.global_rate_limited);
  $('protect-overload').textContent = fmt(total.overload_rejected);
  $('protect-bans').textContent = fmt(status.active_bans ?? state.bans.length);
  $('protect-buckets').textContent = fmt(status.rate_limit_buckets);
  $('protect-inflight').textContent = fmt(status.admission?.global_active ?? state.overview?.security_metrics?.inflight);
  $('protect-tracked').textContent = `${fmt(status.admission?.tracked_clients)} tracked clients`;
  const latency = total.latency || {};
  $('security-latency').innerHTML = metricRows([
    ['Average', ms(latency.average_ms)], ['Maximum', ms(latency.maximum_ms)],
    ['P50', ms(latency.p50_ms)], ['P95', ms(latency.p95_ms)], ['P99', ms(latency.p99_ms)]
  ]);
  renderBars($('reason-bars'), total.reasons || {});
}

async function loadBans() {
  try { state.bans = (await api('/api/v1/bans')).bans || []; renderBans(); } catch (error) { toast(error.message); }
}

function renderBans() {
  const element = $('ban-table');
  if (!state.bans.length) { element.innerHTML = '<tr><td colspan="4" class="muted">No active temporary bans.</td></tr>'; return; }
  element.innerHTML = state.bans.map(ban => `<tr><td>${esc(ban.client)}</td><td>${esc(new Date(ban.banned_until).toLocaleString())}</td><td>${fmt(ban.violations)}</td><td><button class="danger ghost" data-unban="${esc(ban.client)}">Remove</button></td></tr>`).join('');
  element.querySelectorAll('[data-unban]').forEach(button => button.onclick = async () => {
    await api(`/api/v1/bans/${encodeURIComponent(button.dataset.unban)}`, {method:'DELETE'});
    await loadBans(); toast('Temporary ban removed');
  });
}

function renderTraffic() {
  const total = state.overview?.edgeproxy_metrics?.total || {};
  $('cache-stats').innerHTML = metricRows([
    ['Hits', fmt(total.cache_hits)], ['Misses', fmt(total.cache_misses)], ['Stale', fmt(total.cache_stale)],
    ['Bypasses', fmt(total.cache_bypasses)], ['Stores', fmt(total.cache_stores)], ['Hit ratio', pct(total.cache_hit_ratio)]
  ]);
  const latency = total.response_latency_ms || {};
  $('latency-stats').innerHTML = metricRows([
    ['Average', ms(latency.average)], ['Minimum', ms(latency.minimum)], ['Maximum', ms(latency.maximum)],
    ['P50', ms(latency.p50)], ['P95', ms(latency.p95)], ['P99', ms(latency.p99)]
  ]);
}

async function loadEdgeLogs() {
  try {
    const data = await api('/api/v1/edgeproxy/logs?event=request_completed&limit=50');
    const rows = data.entries || [];
    $('edge-log-table').innerHTML = rows.length ? rows.map(entry => `<tr><td>${esc(new Date(entry.timestamp).toLocaleTimeString())}</td><td><span class="badge ${entry.status >= 500 ? 'error' : entry.status >= 400 ? 'warn' : 'allow'}">${entry.status}</span></td><td><span class="badge ${String(entry.cache_status).toLowerCase()}">${esc(entry.cache_status || '—')}</span></td><td>${esc(entry.route)}</td><td><strong>${esc(entry.method)}</strong> ${esc(entry.path)}</td><td>${ms(entry.duration_ms)}</td><td>${esc(entry.upstream || '—')}</td></tr>`).join('') : '<tr><td colspan="7" class="muted">No EdgeProxy logs.</td></tr>';
  } catch (error) { $('edge-log-table').innerHTML = `<tr><td colspan="7" class="muted">${esc(error.message)}</td></tr>`; }
}

function renderRoutes() {
  const routes = state.overview?.edgeproxy_status?.routes || [];
  if (!routes.length) { $('route-cards').innerHTML = '<article class="panel"><p>No route status available.</p></article>'; return; }
  $('route-cards').innerHTML = routes.map(route => {
    const cache = route.cache ? metricRows([['Cache entries',fmt(route.cache.entries)],['Cache bytes',fmt(route.cache.bytes)],['LRU evictions',fmt(route.cache.evictions)]]) : '<p class="muted">Cache disabled</p>';
    const origins = (route.upstreams || []).map(origin => `<div class="origin"><span>${esc(origin.url || origin.upstream)}</span><span class="badge ${origin.healthy ? 'ready' : 'error'}">${origin.healthy ? 'healthy' : 'unhealthy'}</span></div>`).join('');
    return `<article class="route-card"><div class="route-head"><h2>${esc(route.name)}</h2><span class="badge ${route.ready ? 'ready' : 'error'}">${route.ready ? 'READY' : 'NOT READY'}</span></div>${cache}<h3>Origins</h3>${origins}</article>`;
  }).join('');
}

async function loadPolicies() { state.policies = await api('/api/v1/policies'); renderPolicies(); }

function setField(form, name, value) { if (form.elements[name]) form.elements[name].value = value ?? ''; }
function setChecked(form, name, value) { if (form.elements[name]) form.elements[name].checked = Boolean(value); }

function renderPolicies() {
  if (!state.policies) return;
  const scopes = $('policy-scopes');
  const routes = state.policies.routes || [];
  scopes.innerHTML = `<button data-policy="default" class="${state.selectedPolicy === 'default' ? 'active' : ''}">Default policy</button>` + routes.map(route => `<button data-policy="${esc(route.name)}" class="${state.selectedPolicy === route.name ? 'active' : ''}">${esc(route.name)}${state.policies.route_policies?.[route.name] ? ' · override' : ''}</button>`).join('');
  scopes.querySelectorAll('button').forEach(button => button.onclick = () => { state.selectedPolicy = button.dataset.policy; renderPolicies(); });
  const isDefault = state.selectedPolicy === 'default';
  const policy = isDefault ? state.policies.default_policy : (state.policies.effective_policies?.[state.selectedPolicy] || state.policies.default_policy);
  const form = $('policy-form');
  $('policy-title').textContent = isDefault ? 'Default policy' : `${state.selectedPolicy} policy`;
  $('delete-override').classList.toggle('hidden', isDefault || !state.policies.route_policies?.[state.selectedPolicy]);
  setChecked(form,'enabled',policy.enabled); setField(form,'mode',policy.mode); setField(form,'anomaly_threshold',policy.anomaly_threshold);
  setField(form,'max_inspection_body_bytes',policy.max_inspection_body_bytes); setChecked(form,'inspect_request_body',policy.inspect_request_body);
  setChecked(form,'reject_encoded_request_bodies',policy.reject_encoded_request_bodies);
  setChecked(form,'reject_unsupported_body_types',policy.reject_unsupported_body_types); setChecked(form,'block_on_inspection_limit',policy.block_on_inspection_limit);
  setField(form,'max_path_bytes',policy.max_path_bytes); setField(form,'max_query_bytes',policy.max_query_bytes);
  setField(form,'max_header_count',policy.max_header_count); setField(form,'max_header_value_bytes',policy.max_header_value_bytes);
  setField(form,'allowed_methods',(policy.allowed_methods||[]).join(', ')); setField(form,'excluded_path_prefixes',(policy.excluded_path_prefixes||[]).join(', '));
  setField(form,'disabled_rules',(policy.disabled_rules||[]).join(', ')); setField(form,'ip_allowlist',(policy.ip_allowlist||[]).join(', ')); setField(form,'ip_denylist',(policy.ip_denylist||[]).join(', '));
  setChecked(form,'rate_enabled',policy.rate_limit?.enabled); setField(form,'requests_per_second',policy.rate_limit?.requests_per_second);
  setField(form,'burst',policy.rate_limit?.burst); setField(form,'global_requests_per_second',policy.rate_limit?.global_requests_per_second);
  setField(form,'global_burst',policy.rate_limit?.global_burst); setField(form,'max_buckets',policy.rate_limit?.max_buckets);
  setChecked(form,'auto_ban_enabled',policy.auto_ban?.enabled); setField(form,'violation_threshold',policy.auto_ban?.violation_threshold);
  setField(form,'ban_window',policy.auto_ban?.window); setField(form,'ban_duration',policy.auto_ban?.ban_duration); setField(form,'max_tracked_clients',policy.auto_ban?.max_tracked_clients);
  $('purge-route').innerHTML = routes.map(route => `<option value="${esc(route.name)}">${esc(route.name)}</option>`).join('');
}

async function savePolicy(event) {
  event.preventDefault();
  const base = state.selectedPolicy === 'default' ? state.policies.default_policy : (state.policies.effective_policies?.[state.selectedPolicy] || state.policies.default_policy);
  const form = event.currentTarget;
  const policy = structuredClone(base);
  policy.enabled = form.enabled.checked; policy.mode = form.mode.value; policy.anomaly_threshold = Number(form.anomaly_threshold.value);
  policy.max_inspection_body_bytes = Number(form.max_inspection_body_bytes.value); policy.inspect_request_body = form.inspect_request_body.checked;
  policy.reject_encoded_request_bodies = form.reject_encoded_request_bodies.checked;
  policy.reject_unsupported_body_types = form.reject_unsupported_body_types.checked; policy.block_on_inspection_limit = form.block_on_inspection_limit.checked;
  policy.max_path_bytes = Number(form.max_path_bytes.value); policy.max_query_bytes = Number(form.max_query_bytes.value);
  policy.max_header_count = Number(form.max_header_count.value); policy.max_header_value_bytes = Number(form.max_header_value_bytes.value);
  policy.allowed_methods = csv(form.allowed_methods.value).map(x => x.toUpperCase()); policy.excluded_path_prefixes = csv(form.excluded_path_prefixes.value);
  policy.disabled_rules = csv(form.disabled_rules.value).map(x => x.toUpperCase()); policy.ip_allowlist = csv(form.ip_allowlist.value); policy.ip_denylist = csv(form.ip_denylist.value);
  policy.rate_limit.enabled = form.rate_enabled.checked; policy.rate_limit.requests_per_second = Number(form.requests_per_second.value);
  policy.rate_limit.burst = Number(form.burst.value); policy.rate_limit.global_requests_per_second = Number(form.global_requests_per_second.value);
  policy.rate_limit.global_burst = Number(form.global_burst.value); policy.rate_limit.max_buckets = Number(form.max_buckets.value);
  policy.auto_ban.enabled = form.auto_ban_enabled.checked; policy.auto_ban.violation_threshold = Number(form.violation_threshold.value);
  policy.auto_ban.window = form.ban_window.value.trim(); policy.auto_ban.ban_duration = form.ban_duration.value.trim(); policy.auto_ban.max_tracked_clients = Number(form.max_tracked_clients.value);
  try {
    const path = state.selectedPolicy === 'default' ? '/api/v1/policies/default' : `/api/v1/policies/${encodeURIComponent(state.selectedPolicy)}`;
    await api(path, {method:'PUT', body:JSON.stringify(policy)});
    $('policy-result').textContent = 'Policy validated, saved, audited, and reloaded.';
    await loadPolicies(); toast('Policy saved');
  } catch (error) { $('policy-result').textContent = error.message; }
}

function renderSystem() {
  const metrics = state.overview?.security_metrics || {};
  const logs = state.overview?.security_logs || {};
  const status = state.overview?.security_status || {};
  const build = state.overview?.build || {};
  $('security-system').innerHTML = metricRows([
    ['Version',build.version||'—'],['Build commit',build.commit||'—'],['Runtime',`${build.go_version||'—'} · ${build.os||'—'}/${build.arch||'—'}`],
    ['Metrics schema',metrics.schema_version||'—'],['Uptime',`${fmt(metrics.uptime_seconds)} s`],['In flight',fmt(metrics.inflight)],
    ['Rate-limit buckets',fmt(status.rate_limit_buckets)],['Active temporary bans',fmt(status.active_bans)],
    ['Retained security events',fmt(logs.retained)],['Overwritten memory events',fmt(logs.dropped)],['Persistent log bytes',fmt(logs.file_bytes)],['Persistent log errors',fmt(logs.file_errors)]
  ]);
  const edgeStatus = state.overview?.edgeproxy_status_code;
  const routes = state.overview?.edgeproxy_status?.routes || [];
  $('edge-system').innerHTML = metricRows([
    ['Admin HTTP status',edgeStatus||'unavailable'],['Metrics schema',state.overview?.edgeproxy_metrics?.schema_version||'—'],
    ['Uptime',`${fmt(state.overview?.edgeproxy_metrics?.uptime_seconds)} s`],['In flight',fmt(state.overview?.edgeproxy_metrics?.inflight)],
    ['Ready routes',`${routes.filter(route=>route.ready).length}/${routes.length}`]
  ]);
}

function renderRules() {
  $('rules-table').innerHTML = state.rules.map(rule => `<tr><td><span class="badge warn">${esc(rule.id)}</span></td><td>${esc(rule.name)}</td><td>${esc(rule.category)}</td><td>${esc(rule.source)}</td><td>${fmt(rule.score)}</td><td>${esc(rule.description)}</td></tr>`).join('');
}

$('login-form').addEventListener('submit', async event => { event.preventDefault(); $('login-error').textContent=''; try { await login($('token').value.trim()); } catch (error) { $('login-error').textContent=error.message; } });
$('logout').onclick = lock;
$('refresh').onclick = refreshAll;
document.querySelectorAll('.nav-item').forEach(button => button.onclick = () => setView(button.dataset.view));
document.querySelectorAll('[data-go]').forEach(button => button.onclick = () => setView(button.dataset.go));
$('security-filters').onsubmit = event => { event.preventDefault(); loadSecurity(true); };
$('older-security').onclick = () => loadSecurity(false);
$('clear-security').onclick = async () => { if (!confirm('Clear all retained in-memory SecurityEdge events? Persistent NDJSON files are not deleted.')) return; await api('/api/v1/logs',{method:'DELETE'}); await loadSecurity(true); toast('In-memory security events cleared'); };
$('export-ndjson').onclick = () => download('/api/v1/logs/export?format=ndjson','security-events.ndjson','application/x-ndjson').catch(error=>toast(error.message));
$('export-csv').onclick = () => download('/api/v1/logs/export?format=csv','security-events.csv','text/csv').catch(error=>toast(error.message));
$('export-prometheus').onclick = () => download('/api/v1/metrics/prometheus','securityedge.prom','text/plain').catch(error=>toast(error.message));
$('clear-bans').onclick = async () => { if (!confirm('Clear all active temporary bans?')) return; await api('/api/v1/bans',{method:'DELETE'}); await loadBans(); toast('Temporary bans cleared'); };
$('policy-form').onsubmit = savePolicy;
$('delete-override').onclick = async () => { await api(`/api/v1/policies/${encodeURIComponent(state.selectedPolicy)}`,{method:'DELETE'}); await loadPolicies(); toast('Route override deleted'); };
$('purge-form').onsubmit = async event => { event.preventDefault(); const query=new URLSearchParams({route:$('purge-route').value}); if($('purge-host').value.trim())query.set('host',$('purge-host').value.trim()); if($('purge-path').value.trim())query.set('path_prefix',$('purge-path').value.trim()); try { const data=await api(`/api/v1/edgeproxy/cache/purge?${query}`,{method:'POST'}); $('purge-result').textContent=`Purged ${data.purged_entries} entries.`; toast('Cache purged'); await refreshAll(); } catch(error) { $('purge-result').textContent=error.message; } };
$('reload-config').onclick = async () => { await api('/api/v1/reload',{method:'POST'}); await refreshAll(); toast('Configuration reloaded'); };
window.addEventListener('resize', () => state.overview && drawTrend());

if (state.token) login(state.token).catch(lock);
setInterval(() => { if (state.token) refreshAll(); }, 5000);
