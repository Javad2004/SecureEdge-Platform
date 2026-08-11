'use strict';

function sessionGet(key) { try { return sessionStorage.getItem(key) || ''; } catch { return ''; } }
function sessionSet(key, value) { try { sessionStorage.setItem(key, value); } catch {} }
function sessionRemove(key) { try { sessionStorage.removeItem(key); } catch {} }

const state = {
  token: sessionGet('securityedge_token'),
  overview: null,
  policies: null,
  rules: [],
  bans: [],
  securityCursor: 0,
  securityHasMore: false,
  selectedPolicy: 'default',
  trend: [],
  edgeConfig: null,
  securityConfig: null,
  edgeWatch: null,
  securityWatch: null,
  edgeEditorDirty: false,
  securityEditorDirty: false,
  systemDirty: {},
  refreshPromise: null,
  refreshQueued: false
};

const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString();
const pct = n => `${(Number(n || 0) * 100).toFixed(1)}%`;
const ms = n => `${Number(n || 0).toFixed(2)} ms`;
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const csv = value => String(value || '').split(',').map(x => x.trim()).filter(Boolean);
const csvNumbers = value => csv(value).map(item => Number(item));
const bytesToMiB = value => Number(value || 0) / 1048576;
const mibToBytes = value => Math.round(Number(value || 0) * 1048576);
const requestTimeoutMS = 15000;

async function fetchWithTimeout(path, options = {}, timeout = requestTimeoutMS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try { return await fetch(path, {...options, signal:controller.signal}); }
  catch (error) {
    if (error?.name === 'AbortError') throw new Error(`Request timed out after ${Math.round(timeout / 1000)} seconds.`);
    throw error;
  } finally { clearTimeout(timer); }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${state.token}`);
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetchWithTimeout(path, {...options, headers});
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

async function download(path, filename) {
  const response = await fetchWithTimeout(path, {headers: {Authorization: `Bearer ${state.token}`}}, 30000);
  if (!response.ok) throw new Error(`Export failed: HTTP ${response.status}`);
  const blob = await response.blob();
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
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
  $('live-dot').classList.remove('live','degraded','down');
  $('connection-label').textContent = 'Console locked';
  sessionRemove('securityedge_token');
  state.token = '';
}

async function login(token) {
  state.token = token;
  await api('/api/v1/session');
  sessionSet('securityedge_token', token);
  $('login').classList.remove('visible');
  $('live-dot').classList.add('live');
  $('connection-label').textContent = 'Checking dependencies';
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
  if (state.refreshPromise) {
    state.refreshQueued = true;
    return state.refreshPromise;
  }
  state.refreshPromise = (async () => {
    do {
      state.refreshQueued = false;
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
        await loadControlData();
        renderAll();
        await loadEdgeLogs();
        $('last-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
        $('live-dot').classList.add('live');
      } catch (error) {
        toast(error.message);
        $('live-dot').classList.remove('live','degraded');
        $('live-dot').classList.add('down');
        $('connection-label').textContent = 'Operations API unavailable';
      }
    } while (state.refreshQueued && state.token);
  })();
  try { return await state.refreshPromise; }
  finally { state.refreshPromise = null; }
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
}

function rejectedCount(total) {
  return Number(total.blocked || 0) + Number(total.rate_limited || 0) + Number(total.overload_rejected || 0) + Number(total.banned_rejected || 0);
}

function normalizedStatus(value) {
  const status = String(value || 'unknown').toLowerCase();
  return ['healthy','degraded','down','unknown','not_applicable'].includes(status) ? status : 'unknown';
}

function statusLabel(value) {
  return ({healthy:'Healthy',degraded:'Degraded',down:'Down',unknown:'Unknown',not_applicable:'N/A'})[normalizedStatus(value)];
}

function statusBadge(value) {
  const status = normalizedStatus(value);
  return `<span class="status-pill ${status}">${esc(statusLabel(status).toUpperCase())}</span>`;
}

function dateText(value, fallback = 'Never') {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString();
}

function compactLatency(value) {
  const latency = Number(value || 0);
  return latency > 0 ? `${latency.toFixed(latency < 10 ? 2 : 1)} ms` : '—';
}

function componentByID(connectivity, id) {
  return (connectivity.components || []).find(component => component.id === id) || null;
}

function topologyNode(status, title, subtitle, meta = '') {
  const normalized = normalizedStatus(status);
  return `<div class="topology-node ${normalized}"><div class="topology-node-head"><span class="node-dot"></span><strong>${esc(title)}</strong></div><span>${esc(subtitle)}</span>${meta ? `<small>${esc(meta)}</small>` : ''}</div>`;
}

function renderConnectivity() {
  const connectivity = state.overview?.connectivity || {};
  const generated = connectivity.generated_at ? new Date(connectivity.generated_at) : null;
  const staleAfter = Number(connectivity.stale_after_seconds || 15) * 1000;
  const stale = generated && !Number.isNaN(generated.getTime()) && Date.now() - generated.getTime() > staleAfter;
  const overall = stale && connectivity.overall_status === 'healthy' ? 'degraded' : normalizedStatus(connectivity.overall_status);
  const liveDot = $('live-dot');
  liveDot.classList.remove('live','degraded','down');
  if (overall === 'healthy') liveDot.classList.add('live');
  else if (overall === 'degraded') liveDot.classList.add('degraded');
  else if (overall === 'down') liveDot.classList.add('down');
  $('connection-label').textContent = stale ? 'System status stale' : `System ${statusLabel(overall).toLowerCase()}`;
  const panel = $('connectivity-panel');
  panel.className = `panel connectivity-panel status-${overall}`;
  $('connectivity-overall').className = `status-pill ${overall}`;
  $('connectivity-overall').textContent = stale ? 'STALE' : statusLabel(overall).toUpperCase();
  $('connectivity-title').textContent = overall === 'healthy' ? 'All monitored service dependencies are operational' : overall === 'down' ? 'A critical service dependency is unavailable' : overall === 'degraded' ? 'One or more service dependencies are degraded' : 'Service health status is unavailable';
  $('connectivity-summary').textContent = stale ? 'The last probe is stale. Run a new check before relying on this status.' : (connectivity.summary || 'Waiting for the first dependency probe.');
  $('connectivity-updated').textContent = connectivity.generated_at ? `Checked ${dateText(connectivity.generated_at)}${stale ? ' · stale' : ''}` : 'Not checked';
  $('connectivity-traffic').innerHTML = statusBadge(connectivity.traffic_path_status);
  $('connectivity-dns').innerHTML = statusBadge(componentByID(connectivity, 'dns_resolution')?.status || 'not_applicable');
  $('connectivity-edge').innerHTML = statusBadge(connectivity.edgeproxy_connection_status);
  $('connectivity-observability').innerHTML = statusBadge(connectivity.observability_status);
  const counts = connectivity.counts || {};
  $('connectivity-routes').textContent = `${fmt(counts.ready_routes)}/${fmt(counts.total_routes)} ready`;
  $('connectivity-origins').textContent = `${fmt(counts.healthy_origins)}/${fmt(counts.total_origins)} origins healthy`;
  $('connectivity-health-count').textContent = `${fmt(counts.components_healthy)} healthy · ${fmt(counts.components_degraded)} degraded · ${fmt(counts.components_down)} down`;

  const dns = componentByID(connectivity, 'dns_resolution');
  const ingress = componentByID(connectivity, 'securityedge_ingress');
  const edgeHTTP = componentByID(connectivity, 'edgeproxy_data_http');
  const routeStatus = counts.total_routes ? (counts.ready_routes === counts.total_routes ? 'healthy' : counts.ready_routes > 0 ? 'degraded' : 'down') : 'unknown';
  const originStatus = counts.total_origins ? (counts.healthy_origins === counts.total_origins ? 'healthy' : counts.healthy_origins > 0 ? 'degraded' : 'down') : 'unknown';
  const topology = [
    topologyNode(dns?.status || 'not_applicable', 'DNS resolution', dns ? 'Configured hostname resolution' : 'DNS probe disabled', dns?.latency_ms ? `${compactLatency(dns.latency_ms)} · ${dns.endpoint || 'configured resolver'}` : 'Optional server-side probe'),
    '<span class="topology-arrow">→</span>',
    topologyNode(ingress?.status, 'SecurityEdge', 'Public application-security ingress', ingress?.endpoint || '—'),
    '<span class="topology-arrow">→</span>',
    topologyNode(connectivity.edgeproxy_connection_status, 'EdgeProxy', `${String(edgeHTTP?.details?.protocol || 'http').toUpperCase()} data plane + Admin API`, edgeHTTP ? compactLatency(edgeHTTP.latency_ms) : '—'),
    '<span class="topology-arrow">→</span>',
    topologyNode(routeStatus, 'Routes', `${fmt(counts.ready_routes)}/${fmt(counts.total_routes)} ready`, 'Route readiness'),
    '<span class="topology-arrow">→</span>',
    topologyNode(originStatus, 'Origins', `${fmt(counts.healthy_origins)}/${fmt(counts.total_origins)} healthy`, 'Reported by EdgeProxy health checks')
  ];
  $('connectivity-topology').innerHTML = topology.join('');

  const components = connectivity.components || [];
  $('connectivity-components').innerHTML = components.length ? components.map(component => {
    const status = normalizedStatus(component.status);
    const error = component.error ? `<div class="component-error">${esc(component.error)}</div>` : '';
    const endpoint = component.endpoint ? `<code>${esc(component.endpoint)}</code>` : '<span class="muted">No network endpoint</span>';
    return `<article class="component-check ${status}"><div class="component-check-head"><div><span class="node-dot"></span><strong>${esc(component.name)}</strong></div>${statusBadge(status)}</div><p>${esc(component.message || 'No detail')}</p>${error}<div class="component-meta"><span>${endpoint}</span><span>Latency <strong>${compactLatency(component.latency_ms)}</strong></span><span>Availability <strong>${Number(component.availability_percent || 0).toFixed(1)}%</strong></span><span>Failures <strong>${fmt(component.consecutive_failures)}</strong></span></div><div class="component-times"><span>Last success: ${esc(dateText(component.last_success_at))}</span><span>Last failure: ${esc(dateText(component.last_failure_at))}</span></div></article>`;
  }).join('') : '<div class="empty-state">No component checks are available.</div>';

  const history = [...(connectivity.history || [])].reverse().slice(0, 12);
  $('connectivity-history').innerHTML = history.length ? history.map(item => `<div class="transition-item"><span class="transition-time">${esc(dateText(item.timestamp))}</span><div><strong>${esc(item.component)}</strong><p>${statusBadge(item.from)} <span class="transition-arrow">→</span> ${statusBadge(item.to)}</p><small>${esc(item.message || '')}</small></div></div>`).join('') : '<div class="empty-state">No status transition has occurred during this process lifetime.</div>';
}

function renderRecentTraffic() {
  const traffic = state.overview?.recent_client_traffic || {};
  const active = traffic.status === 'traffic_observed' && Boolean(traffic.last_request);
  const panel = $('recent-traffic-panel');
  panel.classList.toggle('traffic-active', active);
  panel.classList.toggle('traffic-idle', !active);
  $('recent-traffic-title').textContent = active ? 'Recent client traffic observed' : 'No recent client traffic';
  $('recent-traffic-summary').textContent = traffic.summary || (active ? 'Requests are reaching the SecurityEdge ingress.' : 'Waiting for requests at the SecurityEdge ingress.');
  const windowMinutes = Math.max(1, Math.round(Number(traffic.window_seconds || 300) / 60));
  $('recent-traffic-window').textContent = `${windowMinutes}-minute activity window`;
  $('recent-traffic-last').textContent = active ? `Last observed ${dateText(traffic.last_observed_at)}` : `No requests in the last ${windowMinutes} minutes`;
  const request = traffic.last_request || {};
  $('recent-traffic-request').textContent = active ? `${request.method || '—'} ${request.path || '—'}` : '—';
  $('recent-traffic-host').textContent = active ? (request.host || 'Host unavailable') : 'No request metadata';
  $('recent-traffic-client').textContent = active ? (request.client_ip || 'Unknown') : '—';
  $('recent-traffic-route').textContent = active ? `${request.route || '__unmatched__'} route` : '— route';
  $('recent-traffic-action').innerHTML = active ? `<span class="badge ${actionClass(request.action)}">${esc(request.action || '—')}</span>` : '—';
  $('recent-traffic-reason').textContent = active ? (request.reason || 'Policy allowed') : '—';
  $('recent-traffic-status').textContent = active ? String(request.status || '—') : '—';
  $('recent-traffic-cache').textContent = active ? `${request.cache_status || 'Not reported'} cache` : '— cache';
  $('recent-traffic-count').textContent = fmt(traffic.requests_in_window);
  $('recent-traffic-clients').textContent = `${fmt(traffic.unique_clients)} unique clients · ${fmt(traffic.allowed)} allowed · ${fmt(traffic.rejected)} rejected`;
}

function renderOverview() {
  renderConnectivity();
  renderRecentTraffic();
  const overview = state.overview || {};
  const security = overview.security_metrics || {};
  const total = security.total || {};
  const edgeMetrics = overview.edgeproxy_metrics || {};
  const edgeTotal = edgeMetrics.total || {};
  const edgeStatus = overview.edgeproxy_status || {};
  const edgeConnected = normalizedStatus(overview.connectivity?.edgeproxy_connection_status) !== 'down' && Boolean(overview.edgeproxy_metrics);
  $('kpi-requests').textContent = edgeConnected ? fmt(edgeTotal.requests) : '—';
  $('kpi-rps').textContent = edgeConnected ? `${Number(edgeMetrics.requests_per_second || 0).toFixed(2)} req/s` : 'EdgeProxy unavailable';
  $('kpi-blocked').textContent = fmt(rejectedCount(total));
  $('kpi-block-rate').textContent = `${pct(total.block_rate)} rejection rate`;
  $('kpi-detections').textContent = fmt(total.detections);
  $('kpi-detection-rate').textContent = `${pct(total.detection_rate)} detection rate`;
  $('kpi-cache').textContent = edgeConnected ? pct(edgeTotal.cache_hit_ratio) : '—';
  $('kpi-cache-counts').textContent = edgeConnected ? `${fmt(edgeTotal.cache_hits)} hits · ${fmt(edgeTotal.cache_misses)} misses` : 'No cache telemetry';
  $('kpi-p95').textContent = ms(total.latency?.p95_ms);
  $('kpi-upstream').textContent = `${ms(edgeTotal.upstream?.latency_ms?.average)} upstream avg`;
  const routes = edgeStatus.routes || [];
  const origins = routes.flatMap(route => route.upstreams || []);
  const healthy = origins.filter(origin => origin.healthy).length;
  $('kpi-origins').textContent = `${healthy}/${origins.length}`;
  $('kpi-routes').textContent = `${routes.filter(route => route.ready).length}/${routes.length} routes ready`;
  const history = overview.telemetry_history?.samples || [];
  if (history.length) {
    state.trend = history.map(point => ({
      requests: Number(point.edgeproxy?.requests_per_second || 0),
      blocked: Number(point.security?.rejected_per_second || 0),
      time: Date.parse(point.generated_at) || Date.now()
    }));
  } else if (overview.edgeproxy_metrics) {
    state.trend = [{requests: Number(edgeMetrics.requests_per_second || 0), blocked: Number(security.requests_per_second || 0) * Number(total.block_rate || 0), time: Date.now()}];
  }
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
  const maximum = Math.max(1, Number(entries[0][1]) || 0);
  element.innerHTML = entries.map(([name, value]) => {
    const numericValue = Math.max(0, Number(value) || 0);
    return `<div class="bar-row"><span>${esc(name)}</span><div class="bar-track"><progress class="bar-progress" max="${maximum}" value="${numericValue}" aria-label="${esc(name)}"></progress></div><strong>${fmt(value)}</strong></div>`;
  }).join('');
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
  element.innerHTML = state.bans.map(ban => `<tr><td>${esc(ban.client)}</td><td>${esc(new Date(ban.banned_until).toLocaleString())}</td><td>${fmt(ban.violations)}</td><td class="table-actions-cell"><div class="table-actions"><button class="danger ghost" data-unban="${esc(ban.client)}">Remove</button></div></td></tr>`).join('');
  element.querySelectorAll('[data-unban]').forEach(button => button.onclick = async () => {
    await api(`/api/v1/bans/${encodeURIComponent(button.dataset.unban)}`, {method:'DELETE'});
    await loadBans(); toast('Temporary ban removed');
  });
}

function renderTraffic() {
  if (!state.overview?.edgeproxy_metrics) {
    $('cache-stats').innerHTML = '<div class="empty-state">EdgeProxy metrics are unavailable. Check the connectivity panel.</div>';
    $('latency-stats').innerHTML = '<div class="empty-state">No EdgeProxy latency telemetry is available.</div>';
    return;
  }
  const total = state.overview.edgeproxy_metrics.total || {};
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

async function loadControlData() {
  const requests = [
    api('/api/v1/edgeproxy/config'), api('/api/v1/edgeproxy/config/watch'),
    api('/api/v1/config'), api('/api/v1/config/watch')
  ];
  const [edgeConfig, edgeWatch, securityConfig, securityWatch] = await Promise.allSettled(requests);
  if (edgeConfig.status === 'fulfilled') state.edgeConfig = edgeConfig.value;
  if (edgeWatch.status === 'fulfilled') state.edgeWatch = edgeWatch.value;
  if (securityConfig.status === 'fulfilled') state.securityConfig = securityConfig.value;
  if (securityWatch.status === 'fulfilled') state.securityWatch = securityWatch.value;
}

const systemFormDefinitions = {
  'security-server': {api:'/api/v1/server', source:() => state.securityConfig?.server},
  'security-admin': {api:'/api/v1/admin', source:() => state.securityConfig?.admin},
  'security-edgeproxy': {api:'/api/v1/edgeproxy-settings', source:() => state.securityConfig?.edgeproxy},
  'security-waf': {api:'/api/v1/waf', source:() => state.securityConfig?.waf},
  'edge-server': {api:'/api/v1/edgeproxy/server', source:() => state.edgeConfig?.server},
  'edge-admin': {api:'/api/v1/edgeproxy/admin', source:() => state.edgeConfig?.admin}
};

function nestedValue(object, path) {
  return path.split('.').reduce((value, key) => value == null ? undefined : value[key], object);
}

function assignNested(object, path, value) {
  const parts = path.split('.');
  let target = object;
  parts.slice(0, -1).forEach(key => {
    if (!target[key] || typeof target[key] !== 'object' || Array.isArray(target[key])) target[key] = {};
    target = target[key];
  });
  target[parts.at(-1)] = value;
}

function populateSystemForm(form, source) {
  if (!form || !source || state.systemDirty[form.dataset.systemForm] || form.contains(document.activeElement)) return;
  form.querySelectorAll('[name]').forEach(field => {
    const value = nestedValue(source, field.name);
    if (field.dataset.secret === 'true') {
      field.value = '';
      field.placeholder = value ? 'Leave blank to preserve the current secret' : 'Enter a secret when required';
    } else if (field.type === 'checkbox') {
      field.checked = Boolean(value);
    } else if (field.dataset.kind === 'json') {
      field.value = JSON.stringify(value ?? [], null, 2);
    } else if (field.dataset.kind === 'csv' || field.dataset.kind === 'csv-number') {
      field.value = Array.isArray(value) ? value.join(', ') : '';
    } else {
      field.value = value ?? '';
    }
  });
}

function systemFormPayload(form, source) {
  const payload = {};
  form.querySelectorAll('[name]').forEach(field => {
    let value;
    if (field.dataset.secret === 'true' && !field.value) {
      value = nestedValue(source, field.name) ?? '';
    } else if (field.type === 'checkbox') {
      value = field.checked;
    } else if (field.dataset.kind === 'number' || field.type === 'number') {
      value = Number(field.value);
      if (!Number.isFinite(value)) throw new Error(`${field.closest('label')?.firstChild?.textContent?.trim() || field.name} must be a number.`);
    } else if (field.dataset.kind === 'csv') {
      value = csv(field.value);
    } else if (field.dataset.kind === 'csv-number') {
      value = csvNumbers(field.value);
      if (value.some(item => !Number.isFinite(item))) throw new Error(`${field.name} must contain only numbers.`);
    } else if (field.dataset.kind === 'json') {
      try { value = field.value.trim() ? JSON.parse(field.value) : []; }
      catch (error) { throw new Error(`${field.name} is not valid JSON: ${error.message}`); }
    } else {
      value = field.value.trim();
    }
    assignNested(payload, field.name, value);
  });
  return payload;
}

function renderSystemForms() {
  Object.entries(systemFormDefinitions).forEach(([key, definition]) => {
    populateSystemForm(document.querySelector(`[data-system-form="${key}"]`), definition.source());
  });
}

async function saveSystemForm(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const key = form.dataset.systemForm;
  const definition = systemFormDefinitions[key];
  const result = form.querySelector('[data-system-result]');
  const button = form.querySelector('button[type="submit"]');
  try {
    const payload = systemFormPayload(form, definition.source() || {});
    button.disabled = true;
    result.textContent = 'Validating and applying…';
    const response = await api(definition.api, {method:'PUT', body:JSON.stringify(payload)});
    state.systemDirty[key] = false;
    result.textContent = response.restart_required ? 'Accepted. A graceful generation restart is scheduled.' : 'Validated, persisted, and applied.';
    toast(response.restart_required ? 'Configuration accepted; restart scheduled' : 'Configuration applied');
    try { await loadControlData(); renderSystemForms(); } catch {}
    if (response.restart_required) setTimeout(() => refreshAll(), 1800);
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function watchSummary(status) {
  if (!status) return {state:'UNAVAILABLE', detail:'Control endpoint unavailable', cls:'error'};
  if (status.last_error) return {state:'ERROR', detail:status.last_error, cls:'error'};
  if (status.restart_scheduled) return {state:'RESTARTING', detail:`Revision ${fmt(status.revision)} · ${status.restart_fields?.join(', ') || 'process settings'}`, cls:'warn'};
  return {state:'WATCHING', detail:`Revision ${fmt(status.applied_revision ?? status.revision)} · ${status.last_source || status.last_changed_file || 'ready'}`, cls:'ready'};
}

function routeStatus(name) {
  return (state.overview?.edgeproxy_status?.routes || []).find(route => String(route.name).toLowerCase() === String(name).toLowerCase()) || null;
}
function routeMetrics(name) { const routes = state.overview?.edgeproxy_metrics?.routes || {}; const key = Object.keys(routes).find(item => item.toLowerCase() === String(name).toLowerCase()); return key ? routes[key] : {}; }
function statusOrigin(status, origin) {
  return (status?.upstreams || []).find(item => String(item.name || '').toLowerCase() === String(origin.name || '').toLowerCase()) ||
    (status?.upstreams || []).find(item => (item.url || item.upstream) === origin.url) || {};
}
function bytes(value) {
  const n = Number(value || 0); if (n < 1024) return `${n} B`; if (n < 1048576) return `${(n/1024).toFixed(1)} KiB`;
  if (n < 1073741824) return `${(n/1048576).toFixed(1)} MiB`; return `${(n/1073741824).toFixed(2)} GiB`;
}

function renderRoutes() {
  const routes = state.edgeConfig?.routes || [];
  const edgeWatch = watchSummary(state.edgeWatch);
  const securityWatch = watchSummary(state.securityWatch);
  $('edge-watch-state').textContent = edgeWatch.state; $('edge-watch-state').className = edgeWatch.cls; $('edge-watch-detail').textContent = edgeWatch.detail;
  $('security-watch-state').textContent = securityWatch.state; $('security-watch-state').className = securityWatch.cls; $('security-watch-detail').textContent = securityWatch.detail;
  $('managed-route-count').textContent = fmt(routes.length);
  $('managed-origin-count').textContent = `${fmt(routes.reduce((sum, route) => sum + (route.upstreams?.length || 0), 0))} origins`;
  $('scheduler-count').textContent = fmt(new Set(routes.map(route => route.load_balancing?.algorithm || 'round_robin')).size);

  if (!state.edgeEditorDirty && state.edgeConfig && document.activeElement !== $('edge-config-editor')) $('edge-config-editor').value = JSON.stringify(state.edgeConfig, null, 2);
  if (!state.securityEditorDirty && state.securityConfig && document.activeElement !== $('security-config-editor')) $('security-config-editor').value = JSON.stringify(state.securityConfig, null, 2);

  const preserveSelect = (id, values) => {
    const select = $(id); if (!select) return;
    const selected = select.value;
    select.innerHTML = values.map(route => `<option value="${esc(route.name)}">${esc(route.name)}</option>`).join('');
    if (values.some(route => route.name === selected)) select.value = selected;
  };
  preserveSelect('purge-route', routes);
  preserveSelect('cache-route-select', routes);
  if (routes.length && !$('cache-route-select').dataset.loaded) loadCacheEditor(routes[0].name);

  $('route-cards').innerHTML = routes.length ? routes.map(route => {
    const status = routeStatus(route.name), telemetry = routeMetrics(route.name);
    const origins = (route.upstreams || []).map(origin => {
      const live = statusOrigin(status, origin), om = telemetry.upstreams?.[origin.url] || {};
      return `<div class="origin-row"><div class="origin-identity"><strong>${esc(origin.name || origin.url)}</strong><span>${esc(origin.url)}</span></div><div class="origin-badges"><span class="badge ${live.healthy ? 'ready':'error'}">${live.healthy ? 'healthy':'unhealthy'}</span><span class="badge">w${fmt(origin.weight)} · p${fmt(origin.priority)}</span><span class="badge">${fmt(om.calls)} calls</span><span class="badge">${ms(live.ewma_latency_ms)}</span></div><div class="origin-actions"><button class="ghost compact-button" data-origin-edit="${esc(route.name)}" data-origin="${esc(origin.name)}">Edit</button><button class="ghost compact-button" data-origin-telemetry="${esc(route.name)}" data-origin="${esc(origin.name)}">Telemetry</button></div></div>`;
    }).join('');
    const algorithm = route.load_balancing?.algorithm || 'round_robin';
    const cache = route.cache || {}, health = route.health_check || {};
    return `<article class="route-card managed-route"><div class="route-head"><div><h2>${esc(route.name)}</h2><p>${esc((route.hosts || []).join(', '))} · ${esc(route.path_prefix || '/')}</p></div><span class="badge ${status?.ready ? 'ready' : 'error'}">${status?.ready ? 'READY' : 'NOT READY'}</span></div><div class="scheduler-banner"><span>Scheduler</span><strong>${esc(algorithm)}</strong><small>${fmt(telemetry.requests)} requests · ${pct(telemetry.cache_hit_ratio)}</small></div><div class="route-facts"><span>Cache <strong>${cache.enabled ? 'enabled':'disabled'}</strong> · ${esc(cache.default_ttl || '—')}</span><span>Health checks <strong>${health.enabled ? 'enabled':'disabled'}</strong> · ${esc(health.interval || '—')}</span><span>Retries <strong>${fmt(route.proxy?.retry_count)}</strong> · ${esc(route.proxy?.request_timeout || '—')} timeout</span></div><div class="route-actions"><button class="ghost" data-route-edit="${esc(route.name)}">Edit all settings</button><button class="ghost" data-origin-add="${esc(route.name)}">Add origin</button><button class="ghost" data-route-telemetry="${esc(route.name)}">Telemetry</button><button class="danger ghost" data-route-delete="${esc(route.name)}">Delete</button></div><h3>Origins</h3>${origins || '<p class="muted">No origins configured.</p>'}</article>`;
  }).join('') : '<article class="panel empty-state">No routes are configured. Create the first route with the validated form.</article>';

  $('route-telemetry-table').innerHTML = routes.length ? routes.map(route => {
    const m = routeMetrics(route.name), latency = m.response_latency_ms || {}, upstream = m.upstream || {};
    const errors = Number(m.client_errors||0)+Number(m.server_errors||0)+Number(m.proxy_errors||0);
    return `<tr><td><strong>${esc(route.name)}</strong><small class="table-subline">${esc(route.load_balancing?.algorithm || 'round_robin')}</small></td><td>${esc(route.load_balancing?.algorithm || 'round_robin')}</td><td>${fmt(m.requests)}</td><td>${pct(m.success_rate)} / ${pct(m.error_rate)}<small class="table-subline">${fmt(errors)} client-facing errors</small></td><td>${pct(m.cache_hit_ratio)}<small class="table-subline">${fmt(m.cache_hits)} hit · ${fmt(m.cache_misses)} miss · ${fmt(m.cache_stale)} stale</small></td><td>${ms(latency.minimum)} / ${ms(latency.average)} / ${ms(latency.maximum)}</td><td>${ms(latency.p50)} / ${ms(latency.p95)} / ${ms(latency.p99)}</td><td>${fmt(m.upstream_calls)} calls<small class="table-subline">${fmt(upstream.failures)} fail · ${fmt(upstream.timeouts)} timeout · ${fmt(m.retries)} retry</small></td><td>${bytes(m.bytes_in)} / ${bytes(m.bytes_out)}</td><td class="table-actions-cell"><div class="table-actions"><button class="ghost compact-button" data-route-telemetry="${esc(route.name)}">Details</button></div></td></tr>`;
  }).join('') : '<tr><td colspan="10" class="muted">No routes configured.</td></tr>';

  const originRows = [];
  routes.forEach(route => {
    const status = routeStatus(route.name), m = routeMetrics(route.name);
    (route.upstreams || []).forEach(origin => {
      const live = statusOrigin(status, origin), om = m.upstreams?.[origin.url] || {}, latency = om.latency_ms || {};
      originRows.push(`<tr><td><strong>${esc(route.name)}</strong><small class="table-subline">${esc(origin.name)}</small></td><td>${esc(origin.url)}</td><td><span class="badge ${live.healthy ? 'ready':'error'}">${live.healthy ? 'healthy':'unhealthy'}</span></td><td>${fmt(origin.weight)} / ${fmt(origin.priority)}</td><td>${fmt(om.calls)}</td><td>${pct(om.success_rate)}<small class="table-subline">${fmt(om.failures)} failures</small></td><td>${fmt(om.timeouts)} / ${fmt(om.retries)}</td><td>${ms(latency.p50)} / ${ms(latency.p95)} / ${ms(latency.p99)}</td><td>${fmt(live.active_requests)} / ${ms(live.ewma_latency_ms)}</td><td>${fmt(live.scheduler_selections)}<small class="table-subline">${fmt(live.health_failures)} fail · ${fmt(live.health_recoveries)} recovery</small></td><td class="table-actions-cell"><div class="table-actions"><button class="ghost compact-button" data-origin-edit="${esc(route.name)}" data-origin="${esc(origin.name)}">Edit</button><button class="ghost compact-button" data-origin-telemetry="${esc(route.name)}" data-origin="${esc(origin.name)}">Details</button></div></td></tr>`);
    });
  });
  $('origin-telemetry-table').innerHTML = originRows.join('') || '<tr><td colspan="11" class="muted">No origins configured.</td></tr>';
  bindRouteActions();
}

function findConfigRoute(name) { return (state.edgeConfig?.routes || []).find(route => String(route.name).toLowerCase() === String(name).toLowerCase()); }
function findConfigOrigin(route, name) { return (route?.upstreams || []).find(origin => String(origin.name).toLowerCase() === String(name).toLowerCase()); }

function defaultRouteTemplate() {
  return {
    name:'', hosts:[], path_prefix:'/', strip_prefix:false, preserve_host:false, upstreams:[],
    load_balancing:{algorithm:'round_robin', latency_sensitivity:1, ewma_alpha:0.25},
    proxy:{request_timeout:'20s', dial_timeout:'3s', response_header_timeout:'10s', idle_conn_timeout:'90s', retry_count:1, retry_backoff:'150ms', max_idle_conns:100, max_idle_conns_per_host:20, max_response_header_bytes:1048576},
    cache:{enabled:true, default_ttl:'30s', stale_if_error:'2m', max_entries:1000, max_bytes:67108864, max_object_bytes:4194304, respect_origin_headers:true, cache_authorized_requests:false, cache_cookie_requests:false, cache_set_cookie_responses:false, vary_request_headers:['Accept','Accept-Encoding'], cacheable_status_codes:[200,203,204,300,301,404,410]},
    health_check:{enabled:true, path:'/healthz', interval:'5s', timeout:'2s', healthy_statuses:[200]}
  };
}

function openRouteDialog(name = '') {
  const route = name ? findConfigRoute(name) : defaultRouteTemplate();
  if (!route && name) return toast('Route no longer exists.');
  $('route-dialog-title').textContent = name ? `Edit ${route.name}` : 'Add route';
  $('route-original-name').value = name ? route.name : '';
  $('route-name').value = route.name || ''; $('route-name').readOnly = Boolean(name);
  $('route-hosts').value = (route.hosts || []).join(', '); $('route-path').value = route.path_prefix || '/';
  $('route-strip-prefix').checked = Boolean(route.strip_prefix); $('route-preserve-host').checked = Boolean(route.preserve_host);
  $('route-algorithm').value = route.load_balancing?.algorithm || 'round_robin';
  $('route-sensitivity').value = route.load_balancing?.latency_sensitivity ?? 1; $('route-alpha').value = route.load_balancing?.ewma_alpha ?? 0.25;
  $('route-request-timeout').value = route.proxy?.request_timeout || '20s'; $('route-dial-timeout').value = route.proxy?.dial_timeout || '3s';
  $('route-response-header-timeout').value = route.proxy?.response_header_timeout || '10s'; $('route-idle-timeout').value = route.proxy?.idle_conn_timeout || '90s';
  $('route-retry-count').value = route.proxy?.retry_count ?? 1; $('route-retry-backoff').value = route.proxy?.retry_backoff || '150ms';
  $('route-max-idle').value = route.proxy?.max_idle_conns ?? 100; $('route-max-idle-host').value = route.proxy?.max_idle_conns_per_host ?? 20; $('route-max-response-header').value = route.proxy?.max_response_header_bytes ?? 1048576;
  $('route-cache-enabled').checked = Boolean(route.cache?.enabled); $('route-cache-ttl').value = route.cache?.default_ttl || '30s'; $('route-cache-stale').value = route.cache?.stale_if_error || '2m';
  $('route-cache-entries').value = route.cache?.max_entries ?? 1000; $('route-cache-mib').value = bytesToMiB(route.cache?.max_bytes || 67108864); $('route-cache-object-mib').value = bytesToMiB(route.cache?.max_object_bytes || 4194304);
  $('route-cache-respect-origin').checked = Boolean(route.cache?.respect_origin_headers); $('route-cache-authorized').checked = Boolean(route.cache?.cache_authorized_requests); $('route-cache-cookie').checked = Boolean(route.cache?.cache_cookie_requests); $('route-cache-set-cookie').checked = Boolean(route.cache?.cache_set_cookie_responses);
  $('route-cache-vary').value = (route.cache?.vary_request_headers || []).join(', '); $('route-cache-statuses').value = (route.cache?.cacheable_status_codes || []).join(', ');
  $('route-health-enabled').checked = Boolean(route.health_check?.enabled); $('route-health-path').value = route.health_check?.path || '/healthz'; $('route-health-interval').value = route.health_check?.interval || '5s'; $('route-health-timeout').value = route.health_check?.timeout || '2s'; $('route-health-statuses').value = (route.health_check?.healthy_statuses || [200]).join(', ');
  $('initial-origin-fields').classList.toggle('hidden', Boolean(name));
  $('route-origin-name').value = 'origin-1'; $('route-origin-url').value = ''; $('route-origin-weight').value = 1; $('route-origin-priority').value = 1; $('route-origin-insecure').checked = false;
  $('route-form-error').textContent = ''; $('route-dialog').showModal();
}

function openOriginDialog(routeName, originName = '') {
  const route = findConfigRoute(routeName), origin = originName ? findConfigOrigin(route, originName) : null;
  if (!route) return toast('Route no longer exists.');
  $('origin-dialog-title').textContent = origin ? `Edit ${origin.name}` : `Add origin to ${route.name}`;
  $('origin-route-name').value = route.name; $('origin-original-name').value = origin?.name || '';
  $('origin-name').value = origin?.name || `origin-${(route.upstreams?.length || 0)+1}`; $('origin-name').readOnly = Boolean(origin);
  $('origin-url').value = origin?.url || ''; $('origin-weight').value = origin?.weight || 1; $('origin-priority').value = origin?.priority || ((route.upstreams?.length || 0)+1);
  $('origin-insecure').checked = Boolean(origin?.insecure_skip_verify); $('origin-form-error').textContent = ''; $('origin-dialog').showModal();
}

function bindRouteActions() {
  document.querySelectorAll('[data-route-edit]').forEach(button => button.onclick = () => openRouteDialog(button.dataset.routeEdit));
  document.querySelectorAll('[data-origin-add]').forEach(button => button.onclick = () => openOriginDialog(button.dataset.originAdd));
  document.querySelectorAll('[data-origin-edit]').forEach(button => button.onclick = () => openOriginDialog(button.dataset.originEdit, button.dataset.origin));
  document.querySelectorAll('[data-route-telemetry]').forEach(button => button.onclick = () => openTelemetryDialog(button.dataset.routeTelemetry));
  document.querySelectorAll('[data-origin-telemetry]').forEach(button => button.onclick = () => openTelemetryDialog(button.dataset.originTelemetry, button.dataset.origin));
  document.querySelectorAll('[data-route-delete]').forEach(button => button.onclick = async () => {
    const name = button.dataset.routeDelete;
    if (!confirm(`Delete route ${name}, all of its origins, and any SecurityEdge policy override?`)) return;
    try { await api(`/api/v1/edgeproxy/routes/${encodeURIComponent(name)}`, {method:'DELETE'}); await refreshAll(); toast('Route deleted'); } catch(error) { toast(error.message); }
  });
}

async function saveRoute(event) {
  event.preventDefault(); $('route-form-error').textContent = '';
  try {
    const original = $('route-original-name').value;
    const base = structuredClone(original ? findConfigRoute(original) : defaultRouteTemplate());
    base.name = $('route-name').value.trim(); base.hosts = csv($('route-hosts').value); base.path_prefix = $('route-path').value.trim();
    base.strip_prefix = $('route-strip-prefix').checked; base.preserve_host = $('route-preserve-host').checked;
    base.load_balancing = {algorithm:$('route-algorithm').value, latency_sensitivity:Number($('route-sensitivity').value), ewma_alpha:Number($('route-alpha').value)};
    base.proxy = {request_timeout:$('route-request-timeout').value.trim(), dial_timeout:$('route-dial-timeout').value.trim(), response_header_timeout:$('route-response-header-timeout').value.trim(), idle_conn_timeout:$('route-idle-timeout').value.trim(), retry_count:Number($('route-retry-count').value), retry_backoff:$('route-retry-backoff').value.trim(), max_idle_conns:Number($('route-max-idle').value), max_idle_conns_per_host:Number($('route-max-idle-host').value), max_response_header_bytes:Number($('route-max-response-header').value)};
    base.cache = {enabled:$('route-cache-enabled').checked, default_ttl:$('route-cache-ttl').value.trim(), stale_if_error:$('route-cache-stale').value.trim(), max_entries:Number($('route-cache-entries').value), max_bytes:mibToBytes($('route-cache-mib').value), max_object_bytes:mibToBytes($('route-cache-object-mib').value), respect_origin_headers:$('route-cache-respect-origin').checked, cache_authorized_requests:$('route-cache-authorized').checked, cache_cookie_requests:$('route-cache-cookie').checked, cache_set_cookie_responses:$('route-cache-set-cookie').checked, vary_request_headers:csv($('route-cache-vary').value), cacheable_status_codes:csvNumbers($('route-cache-statuses').value)};
    base.health_check = {enabled:$('route-health-enabled').checked, path:$('route-health-path').value.trim(), interval:$('route-health-interval').value.trim(), timeout:$('route-health-timeout').value.trim(), healthy_statuses:csvNumbers($('route-health-statuses').value)};
    if (!original) {
      const originURL = $('route-origin-url').value.trim(); if (!originURL) throw new Error('Initial origin URL is required.');
      base.upstreams = [{name:$('route-origin-name').value.trim() || 'origin-1', url:originURL, weight:Number($('route-origin-weight').value), priority:Number($('route-origin-priority').value), insecure_skip_verify:$('route-origin-insecure').checked}];
    }
    const path = original ? `/api/v1/edgeproxy/routes/${encodeURIComponent(original)}` : '/api/v1/edgeproxy/routes';
    await api(path, {method:original ? 'PUT':'POST', body:JSON.stringify(base)});
    $('route-dialog').close(); await refreshAll(); toast(original ? 'Route settings updated' : 'Route created');
  } catch(error) { $('route-form-error').textContent = error.message; }
}

async function saveOrigin(event) {
  event.preventDefault(); $('origin-form-error').textContent = '';
  try {
    const route = $('origin-route-name').value, original = $('origin-original-name').value;
    const origin = {name:$('origin-name').value.trim(), url:$('origin-url').value.trim(), weight:Number($('origin-weight').value), priority:Number($('origin-priority').value), insecure_skip_verify:$('origin-insecure').checked};
    const base = `/api/v1/edgeproxy/routes/${encodeURIComponent(route)}/origins`;
    await api(original ? `${base}/${encodeURIComponent(original)}` : base, {method:original ? 'PUT':'POST', body:JSON.stringify(origin)});
    $('origin-dialog').close(); await refreshAll(); toast(original ? 'Origin updated' : 'Origin added');
  } catch(error) { $('origin-form-error').textContent = error.message; }
}

function loadCacheEditor(routeName) {
  const route = findConfigRoute(routeName);
  if (!route) return;
  const cache = route.cache || defaultRouteTemplate().cache;
  $('cache-route-select').value = route.name; $('cache-route-select').dataset.loaded = route.name;
  $('cache-editor-enabled').checked = Boolean(cache.enabled); $('cache-editor-ttl').value = cache.default_ttl || '30s'; $('cache-editor-stale').value = cache.stale_if_error || '2m';
  $('cache-editor-entries').value = cache.max_entries ?? 1000; $('cache-editor-max-mib').value = bytesToMiB(cache.max_bytes || 67108864); $('cache-editor-object-mib').value = bytesToMiB(cache.max_object_bytes || 4194304);
  $('cache-editor-statuses').value = (cache.cacheable_status_codes || []).join(', '); $('cache-editor-vary').value = (cache.vary_request_headers || []).join(', ');
  $('cache-editor-respect-origin').checked = Boolean(cache.respect_origin_headers); $('cache-editor-authorized').checked = Boolean(cache.cache_authorized_requests); $('cache-editor-cookie').checked = Boolean(cache.cache_cookie_requests); $('cache-editor-set-cookie').checked = Boolean(cache.cache_set_cookie_responses);
  $('cache-config-result').textContent = '';
}

async function saveCacheEditor() {
  const route = $('cache-route-select').value;
  if (!route) return toast('Select a route first.');
  const candidate = {
    enabled:$('cache-editor-enabled').checked,
    default_ttl:$('cache-editor-ttl').value.trim(), stale_if_error:$('cache-editor-stale').value.trim(),
    max_entries:Number($('cache-editor-entries').value), max_bytes:mibToBytes($('cache-editor-max-mib').value), max_object_bytes:mibToBytes($('cache-editor-object-mib').value),
    respect_origin_headers:$('cache-editor-respect-origin').checked, cache_authorized_requests:$('cache-editor-authorized').checked,
    cache_cookie_requests:$('cache-editor-cookie').checked, cache_set_cookie_responses:$('cache-editor-set-cookie').checked,
    vary_request_headers:csv($('cache-editor-vary').value), cacheable_status_codes:csvNumbers($('cache-editor-statuses').value)
  };
  try {
    await api(`/api/v1/edgeproxy/routes/${encodeURIComponent(route)}/cache`, {method:'PUT', body:JSON.stringify(candidate)});
    $('cache-config-result').textContent = 'Cache policy validated, persisted atomically, and hot-applied.';
    await refreshAll(); loadCacheEditor(route); toast('Route cache policy updated');
  } catch(error) { $('cache-config-result').textContent = error.message; }
}

async function openTelemetryDialog(routeName, originName = '') {
  try {
    const path = originName
      ? `/api/v1/edgeproxy/routes/${encodeURIComponent(routeName)}/origins/${encodeURIComponent(originName)}/telemetry`
      : `/api/v1/edgeproxy/routes/${encodeURIComponent(routeName)}/telemetry`;
    const data = await api(path);
    $('telemetry-dialog-title').textContent = originName ? `${routeName} / ${originName}` : `${routeName} route`;
    const m = data.metrics || {}, latency = originName ? (m.latency_ms || {}) : (m.response_latency_ms || {}), runtime = data.runtime || {};
    const items = originName ? [
      ['Endpoint',data.origin?.url||'—'],['Health',runtime.healthy ? 'Healthy':'Unhealthy'],['Weight / priority',`${fmt(data.origin?.weight)} / ${fmt(data.origin?.priority)}`],
      ['Calls',fmt(m.calls)],['Success / failures',`${fmt(m.success)} / ${fmt(m.failures)}`],['Success / error rate',`${pct(m.success_rate)} / ${pct(m.error_rate)}`],
      ['Timeouts / retries',`${fmt(m.timeouts)} / ${fmt(m.retries)}`],['Min / average / max',`${ms(latency.minimum)} / ${ms(latency.average)} / ${ms(latency.maximum)}`],
      ['P50 / P95 / P99',`${ms(latency.p50)} / ${ms(latency.p95)} / ${ms(latency.p99)}`],['Active requests',fmt(runtime.active_requests)],
      ['EWMA latency',ms(runtime.ewma_latency_ms)],['Scheduler selections',fmt(runtime.scheduler_selections)],['Health failures / recoveries',`${fmt(runtime.health_failures)} / ${fmt(runtime.health_recoveries)}`]
    ] : [
      ['Algorithm',data.route?.load_balancing?.algorithm||'round_robin'],['Ready',runtime.ready ? 'Ready':'Not ready'],['Requests',fmt(m.requests)],
      ['Success / client / server',`${fmt(m.success)} / ${fmt(m.client_errors)} / ${fmt(m.server_errors)}`],['Success / error rate',`${pct(m.success_rate)} / ${pct(m.error_rate)}`],['Proxy errors',fmt(m.proxy_errors)],
      ['Cache hit / miss / stale / bypass',`${fmt(m.cache_hits)} / ${fmt(m.cache_misses)} / ${fmt(m.cache_stale)} / ${fmt(m.cache_bypasses)}`],['Cache hit ratio',pct(m.cache_hit_ratio)],['Cache stores',fmt(m.cache_stores)],
      ['Min / average / max',`${ms(latency.minimum)} / ${ms(latency.average)} / ${ms(latency.maximum)}`],['P50 / P95 / P99',`${ms(latency.p50)} / ${ms(latency.p95)} / ${ms(latency.p99)}`],
      ['Upstream calls / retries',`${fmt(m.upstream_calls)} / ${fmt(m.retries)}`],['Bytes in / out',`${bytes(m.bytes_in)} / ${bytes(m.bytes_out)}`],['Methods',Object.entries(m.methods||{}).map(([k,v])=>`${k}:${v}`).join(' · ')||'—']
    ];
    $('telemetry-detail-metrics').innerHTML = metricRows(items);
    renderBars($('telemetry-status-bars'), m.status_codes || {} , 20);
    $('telemetry-raw').textContent = JSON.stringify(data, null, 2);
    $('telemetry-dialog').showModal();
  } catch(error) { toast(error.message); }
}

async function saveRawConfig(kind) {
  const edge = kind === 'edge', editor = $(edge ? 'edge-config-editor':'security-config-editor'), result = $(edge ? 'edge-config-result':'security-config-result');
  try {
    const candidate = JSON.parse(editor.value); const response = await api(edge ? '/api/v1/edgeproxy/config':'/api/v1/config', {method:'PUT', body:JSON.stringify(candidate)});
    if (edge) state.edgeEditorDirty = false; else state.securityEditorDirty = false;
    result.textContent = response.restart_required ? 'Saved. An automatic graceful restart is scheduled.' : 'Validated, saved, and hot-applied.';
    await refreshAll(); toast(edge ? 'EdgeProxy configuration saved' : 'SecurityEdge configuration saved');
  } catch(error) { result.textContent = error.message; }
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
  const history = state.overview?.telemetry_history || {};
  const build = state.overview?.build || {};
  const securityServer = state.securityConfig?.server || {};
  const ingress = securityServer.mode === 'gateway'
    ? `${securityServer.tls?.enabled ? 'HTTPS' : 'HTTP'} · ${securityServer.listen_addr || '—'}`
    : 'Embedded';
  $('security-system').innerHTML = metricRows([
    ['Ingress',ingress],['Version',build.version||'—'],['Build commit',build.commit||'—'],['Runtime',`${build.go_version||'—'} · ${build.os||'—'}/${build.arch||'—'}`],
    ['Metrics schema',metrics.schema_version||'—'],['Uptime',`${fmt(metrics.uptime_seconds)} s`],['In flight',fmt(metrics.inflight)],
    ['Rate-limit buckets',fmt(status.rate_limit_buckets)],['Active temporary bans',fmt(status.active_bans)],
    ['Retained security events',fmt(logs.retained)],['Overwritten memory events',fmt(logs.dropped)],['Persistent log bytes',fmt(logs.file_bytes)],['Persistent log errors',fmt(logs.file_errors)],
    ['Telemetry history',history.enabled ? `${fmt(history.samples?.length)} / ${fmt(history.capacity)} samples` : 'Disabled'],['History persistence',history.persistent ? (history.last_error ? `Degraded: ${history.last_error}` : 'Healthy') : 'Memory only']
  ]);
  const edgeStatus = state.overview?.edgeproxy_status_code;
  const routes = state.overview?.edgeproxy_status?.routes || [];
  const connection = state.overview?.connectivity || {};
  const edgeAdmin = componentByID(connection, 'edgeproxy_admin_health');
  const edgeData = componentByID(connection, 'edgeproxy_data_http');
  const edgeServer = state.edgeConfig?.server || {};
  const edgeProtocol = String(edgeData?.details?.protocol || (edgeServer.tls?.enabled ? 'https' : 'http')).toUpperCase();
  $('edge-system').innerHTML = metricRows([
    ['Overall connection',statusLabel(connection.edgeproxy_connection_status)],['Data-plane health',statusLabel(edgeData?.status)],
    ['Data-plane protocol',edgeProtocol],['Data-plane listener',edgeServer.listen_addr||'—'],
    ['Admin API',statusLabel(edgeAdmin?.status)],['Admin HTTP status',edgeStatus||'unavailable'],
    ['Last connectivity check',dateText(connection.generated_at)],['Data-plane latency',compactLatency(edgeData?.latency_ms)],
    ['Metrics schema',state.overview?.edgeproxy_metrics?.schema_version||'—'],['Uptime',`${fmt(state.overview?.edgeproxy_metrics?.uptime_seconds)} s`],
    ['In flight',fmt(state.overview?.edgeproxy_metrics?.inflight)],['Ready routes',`${routes.filter(route=>route.ready).length}/${routes.length}`]
  ]);
  renderSystemForms();
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
$('clear-security').onclick = async () => { if (!confirm('Clear all retained SecurityEdge events, the active NDJSON log, and rotated backups?')) return; await api('/api/v1/logs',{method:'DELETE'}); await loadSecurity(true); toast('Security events and persistent log files cleared'); };
$('export-ndjson').onclick = () => download('/api/v1/logs/export?format=ndjson','security-events.ndjson').catch(error=>toast(error.message));
$('export-csv').onclick = () => download('/api/v1/logs/export?format=csv','security-events.csv').catch(error=>toast(error.message));
$('export-prometheus').onclick = () => download('/api/v1/metrics/prometheus','securityedge.prom').catch(error=>toast(error.message));
$('clear-bans').onclick = async () => { if (!confirm('Clear all active temporary bans?')) return; await api('/api/v1/bans',{method:'DELETE'}); await loadBans(); toast('Temporary bans cleared'); };
$('policy-form').onsubmit = savePolicy;
$('delete-override').onclick = async () => { await api(`/api/v1/policies/${encodeURIComponent(state.selectedPolicy)}`,{method:'DELETE'}); await loadPolicies(); toast('Route override deleted'); };
$('purge-form').onsubmit = async event => { event.preventDefault(); const route=$('purge-route').value; const query=new URLSearchParams(); if($('purge-host').value.trim())query.set('host',$('purge-host').value.trim()); if($('purge-path').value.trim())query.set('path_prefix',$('purge-path').value.trim()); try { const suffix=query.toString()?`?${query}`:''; const data=await api(`/api/v1/edgeproxy/routes/${encodeURIComponent(route)}/cache/purge${suffix}`,{method:'POST'}); $('purge-result').textContent=`Purged ${data.purged} entries from ${route}.`; toast('Cache purged'); await refreshAll(); } catch(error) { $('purge-result').textContent=error.message; } };
$('check-connectivity').onclick = async () => {
  const button = $('check-connectivity');
  button.disabled = true;
  button.textContent = 'Running…';
  try {
    const connectivity = await api('/api/v1/connectivity/check', {method:'POST'});
    state.overview = {...(state.overview || {}), connectivity};
    renderConnectivity();
    toast('Connectivity check completed');
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.textContent = 'Run checks'; }
};
$('reload-config').onclick = async () => { await api('/api/v1/reload',{method:'POST'}); await refreshAll(); toast('Configuration reloaded'); };
document.querySelectorAll('[data-system-form]').forEach(form => {
  const key = form.dataset.systemForm;
  form.addEventListener('input', () => { state.systemDirty[key] = true; });
  form.addEventListener('change', () => { state.systemDirty[key] = true; });
  form.addEventListener('submit', saveSystemForm);
});
$('refresh-control').onclick = async () => { await loadControlData(); renderRoutes(); toast('Control-plane data refreshed'); };
$('add-route').onclick = () => openRouteDialog();
$('cache-route-select').onchange = event => loadCacheEditor(event.currentTarget.value); $('save-cache-config').onclick = saveCacheEditor;
$('route-form').onsubmit = saveRoute; $('origin-form').onsubmit = saveOrigin;
document.querySelectorAll('[data-close-dialog]').forEach(button => button.onclick = () => $(button.dataset.closeDialog).close());
$('edge-config-editor').addEventListener('input', () => { state.edgeEditorDirty = true; });
$('security-config-editor').addEventListener('input', () => { state.securityEditorDirty = true; });
$('save-edge-config').onclick = () => saveRawConfig('edge'); $('save-security-config').onclick = () => saveRawConfig('security');
$('reload-edge-config').onclick = async () => { try { await api('/api/v1/edgeproxy/config/reload',{method:'POST'}); state.edgeEditorDirty=false; await refreshAll(); toast('EdgeProxy configuration reloaded'); } catch(error) { $('edge-config-result').textContent=error.message; } };
$('reload-security-config').onclick = async () => { try { await api('/api/v1/reload',{method:'POST'}); state.securityEditorDirty=false; await refreshAll(); toast('SecurityEdge configuration reloaded'); } catch(error) { $('security-config-result').textContent=error.message; } };
window.addEventListener('resize', () => state.overview && drawTrend());

if (state.token) login(state.token).catch(lock);
setInterval(() => { if (state.token) refreshAll(); }, 5000);
