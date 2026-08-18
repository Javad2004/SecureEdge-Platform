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
  policyDirty: false,
  cacheEditorDirty: false,
  systemDirty: {},
  refreshPromise: null,
  refreshQueued: false
};

const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString();
function trimDecimalLabel(value) {
  return String(value).replace(/\.0+$/, '').replace(/(\.\d*?[1-9])0+$/, '$1');
}
function percentageLabel(percent) {
  const numeric = Number(percent);
  if (!Number.isFinite(numeric)) return '—';
  let decimals = 1;
  let fixed = numeric.toFixed(decimals);
  let rounded = Number(fixed);
  while (decimals < 6 && ((numeric > 0 && rounded === 0) || (numeric < 100 && rounded === 100))) {
    decimals += 1;
    fixed = numeric.toFixed(decimals);
    rounded = Number(fixed);
  }
  if (numeric > 0 && rounded === 0) return '<0.000001%';
  if (numeric < 100 && rounded === 100) return '>99.999999%';
  return `${fixed}%`;
}
const pct = n => percentageLabel(Number(n || 0) * 100);
function millisecondLabel(value, initialDecimals = 2) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return '—';
  let decimals = Math.max(0, Math.min(9, Number(initialDecimals) || 0));
  let fixed = numeric.toFixed(decimals);
  while (numeric > 0 && Number(fixed) === 0 && decimals < 9) {
    decimals += 1;
    fixed = numeric.toFixed(decimals);
  }
  if (numeric > 0 && Number(fixed) === 0) {
    const scientific = numeric.toExponential(2).replace(/\.00e/, 'e').replace(/(\.\d*[1-9])0+e/, '$1e').replace('e+', 'e');
    return `${scientific} ms`;
  }
  return `${fixed} ms`;
}
const ms = n => millisecondLabel(n, 2);
const pctIf = (n, available) => available ? pct(n) : '—';
const msIf = (n, available) => available ? ms(n) : '—';
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
  if (response.status === 429) {
    lock();
    throw new Error('Admin authentication is temporarily locked.');
  }
  if (!response.ok) throw new Error(data?.error?.message || `HTTP ${response.status}`);
  return data;
}

async function download(path, filename) {
  const response = await fetchWithTimeout(path, {headers: {Authorization: `Bearer ${state.token}`}}, 30000);
  if (response.status === 401) {
    lock();
    throw new Error('Invalid or expired admin token.');
  }
  if (response.status === 429) {
    lock();
    throw new Error('Admin authentication is temporarily locked.');
  }
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

function setConsoleLocked(locked, focusLogin = false) {
  const loginPanel = $('login');
  const shell = $('app-shell');
  loginPanel.classList.toggle('visible', locked);
  shell.inert = locked;
  if (locked && focusLogin) {
    requestAnimationFrame(() => $('token').focus({preventScroll:true}));
  } else if (!locked) {
    requestAnimationFrame(() => document.querySelector('.nav-item.active')?.focus({preventScroll:true}));
  }
}

function lock() {
  sessionRemove('securityedge_token');
  state.token = '';
  $('token').value = '';
  $('live-dot').classList.remove('live','degraded','down');
  $('connection-label').textContent = 'Console locked';
  setConsoleLocked(true, true);
}

async function login(token) {
  state.token = token;
  try {
    await api('/api/v1/session');
  } catch (error) {
    sessionRemove('securityedge_token');
    state.token = '';
    setConsoleLocked(true, true);
    throw error;
  }
  sessionSet('securityedge_token', token);
  $('token').value = '';
  setConsoleLocked(false);
  $('live-dot').classList.add('live');
  $('connection-label').textContent = 'Checking dependencies';
  await refreshAll();
}

function ensureActiveNavVisible() {
  if (!window.matchMedia('(max-width: 960px)').matches) return;
  const nav = $('nav');
  const active = nav?.querySelector('.nav-item.active');
  if (!nav || !active) return;

  const tolerance = 1;
  const navRect = nav.getBoundingClientRect();
  const activeRect = active.getBoundingClientRect();
  const visibleStart = nav.scrollLeft;
  const visibleEnd = visibleStart + nav.clientWidth;
  const activeStart = visibleStart + activeRect.left - navRect.left;
  const activeEnd = activeStart + activeRect.width;

  if (activeStart >= visibleStart - tolerance && activeEnd <= visibleEnd + tolerance) return;

  const maxScroll = Math.max(0, nav.scrollWidth - nav.clientWidth);
  let target = activeStart;
  if (activeEnd > visibleEnd + tolerance) {
    const minimumScroll = Math.max(0, activeEnd - nav.clientWidth);
    const itemBoundaries = [...nav.querySelectorAll('.nav-item')]
      .flatMap(item => {
        const rect = item.getBoundingClientRect();
        const start = visibleStart + rect.left - navRect.left;
        return [start, start + rect.width];
      })
      .filter(boundary => boundary >= minimumScroll - tolerance && boundary <= maxScroll + tolerance)
      .sort((a, b) => a - b);
    target = itemBoundaries[0] ?? minimumScroll;
  }
  nav.scrollLeft = Math.max(0, Math.min(maxScroll, target));
}

function setView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  document.querySelectorAll('.nav-item').forEach(v => v.classList.toggle('active', v.dataset.view === name));
  ensureActiveNavVisible();
  $('page-title').textContent = ({overview:'Overview',security:'Security events',protection:'Traffic protection',traffic:'Traffic & cache',routes:'Routes & origins',policies:'Policies',system:'System'})[name];
  if (name === 'security') loadSecurity(true);
  if (name === 'protection') loadBans();
  if (name === 'policies' && !state.policies) loadPolicies().catch(error => toast(error.message));
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
      } catch (error) {
        toast(error.message);
        // api() locks and clears the token on authentication failures. Preserve
        // that authoritative state instead of misreporting auth expiry as an
        // Operations API outage.
        if (!state.token) continue;
        $('live-dot').classList.remove('live','degraded','down');
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

function completedSecurityDecisions(total) {
  const requests = Math.max(0, Number(total?.requests || 0));
  const canceled = Math.max(0, Number(total?.canceled_requests || 0));
  return Math.max(0, requests - canceled);
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
  const latency = Number(value);
  return Number.isFinite(latency) && latency > 0 ? millisecondLabel(latency, latency < 10 ? 2 : 1) : '—';
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
    const availability = Number(component.checks || 0) > 0 ? percentageLabel(component.availability_percent) : '—';
    return `<article class="component-check ${status}"><div class="component-check-head"><div><span class="node-dot"></span><strong>${esc(component.name)}</strong></div>${statusBadge(status)}</div><p>${esc(component.message || 'No detail')}</p>${error}<div class="component-meta"><span>${endpoint}</span><span>Latency <strong>${compactLatency(component.latency_ms)}</strong></span><span>Availability <strong>${availability}</strong></span><span>Failures <strong>${fmt(component.consecutive_failures)}</strong></span></div><div class="component-times"><span>Last success: ${esc(dateText(component.last_success_at))}</span><span>Last failure: ${esc(dateText(component.last_failure_at))}</span></div></article>`;
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
  const retainedRequests = Number(traffic.requests_in_window || 0);
  const truncated = Boolean(traffic.window_truncated);
  const minimumRequests = Math.max(retainedRequests + (truncated ? 1 : 0), Number(traffic.minimum_requests_in_window || 0));
  $('recent-traffic-count').textContent = truncated ? `≥${fmt(minimumRequests)}` : fmt(retainedRequests);
  const retainedPrefix = truncated ? `${fmt(retainedRequests)} retained · ` : '';
  const capacitySuffix = truncated ? ` · capacity ${fmt(traffic.retention_capacity)}` : '';
  $('recent-traffic-clients').textContent = `${retainedPrefix}${fmt(traffic.unique_clients)} unique clients · ${fmt(traffic.allowed)} allowed · ${fmt(traffic.rejected)} rejected · ${fmt(traffic.canceled)} canceled${capacitySuffix}`;
}

function edgeMetricsSnapshot(overview = state.overview || {}) {
  const status = Number(overview.edgeproxy_metrics_status_code || 0);
  const metrics = overview.edgeproxy_metrics;
  return status >= 200 && status < 300 && typeof metrics?.schema_version === 'string' && metrics.schema_version.trim() ? metrics : null;
}

function edgeStatusSnapshot(overview = state.overview || {}) {
  const status = Number(overview.edgeproxy_status_code || 0);
  const runtime = overview.edgeproxy_status;
  return status >= 200 && status < 300 && Array.isArray(runtime?.routes) ? runtime : null;
}

function renderOverview() {
  renderConnectivity();
  renderRecentTraffic();
  const overview = state.overview || {};
  const security = overview.security_metrics || {};
  const total = security.total || {};
  const edgeMetrics = edgeMetricsSnapshot(overview);
  const edgeMetricsAvailable = Boolean(edgeMetrics);
  const edgeTotal = edgeMetrics?.total || {};
  const edgeStatus = edgeStatusSnapshot(overview);
  const edgeStatusAvailable = Boolean(edgeStatus);
  const securityRequests = Number(total.requests || 0);
  const securityCanceled = Number(total.canceled_requests || 0);
  const securityDecisions = completedSecurityDecisions(total);
  const cancellationSuffix = securityCanceled > 0 ? ` · ${fmt(securityCanceled)} canceled` : '';
  const cacheLookups = Number(edgeTotal.cache_hits || 0) + Number(edgeTotal.cache_misses || 0);
  const upstreamSamples = Number(edgeTotal.upstream?.latency_ms?.count || 0);
  $('kpi-requests').textContent = edgeMetricsAvailable ? fmt(edgeTotal.requests) : '—';
  $('kpi-rps').textContent = edgeMetricsAvailable ? `${trendRateLabel(edgeMetrics.requests_per_second)} req/s avg since start · ${fmt(edgeTotal.canceled_requests)} canceled` : 'EdgeProxy metrics unavailable';
  $('kpi-blocked').textContent = fmt(rejectedCount(total));
  $('kpi-block-rate').textContent = securityDecisions > 0 ? `${pct(total.block_rate)} rejection rate${cancellationSuffix}` : securityRequests > 0 ? `${fmt(securityCanceled)} canceled · no completed decisions` : 'No requests yet';
  $('kpi-detections').textContent = fmt(total.detections);
  $('kpi-detection-rate').textContent = securityDecisions > 0 ? `${pct(total.detection_rate)} detection rate${cancellationSuffix}` : securityRequests > 0 ? 'No completed security decisions' : 'No requests yet';
  $('kpi-cache').textContent = edgeMetricsAvailable ? pctIf(edgeTotal.cache_hit_ratio, cacheLookups > 0) : '—';
  $('kpi-cache-counts').textContent = edgeMetricsAvailable ? `${fmt(edgeTotal.cache_hits)} hits · ${fmt(edgeTotal.cache_misses)} misses${cacheLookups > 0 ? '' : ' · no cache lookups'}` : 'No cache telemetry';
  $('kpi-p95').textContent = msIf(total.latency?.p95_ms, securityDecisions > 0);
  $('kpi-upstream').textContent = edgeMetricsAvailable ? (upstreamSamples > 0 ? `${ms(edgeTotal.upstream?.latency_ms?.average)} upstream avg` : 'No upstream samples') : 'EdgeProxy metrics unavailable';
  const routes = edgeStatus?.routes || [];
  const origins = routes.flatMap(route => route.upstreams || []);
  const healthy = origins.filter(origin => origin.healthy).length;
  $('kpi-origins').textContent = edgeStatusAvailable ? `${healthy}/${origins.length}` : '—';
  $('kpi-routes').textContent = edgeStatusAvailable ? `${routes.filter(route => route.ready).length}/${routes.length} routes ready` : 'EdgeProxy status unavailable';
  const history = overview.telemetry_history?.samples || [];
  state.trend = normalizeTrendHistory(history);
  drawTrend();
  renderBars($('rule-bars'), total.rules || {});
  renderSecurityRows($('recent-security'), overview.security_logs?.entries || [], false, 7);
}

function cssColor(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function nonNegativeRate(value) {
  if (value === null || value === undefined || value === '') return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

function normalizeTrendHistory(history) {
  return (Array.isArray(history) ? history : []).map(point => {
    const parsedTime = Date.parse(point.generated_at);
    return {
      requests: point.edgeproxy?.available === true && point.edgeproxy?.request_rate_available === true
        ? nonNegativeRate(point.edgeproxy.requests_per_second)
        : null,
      blocked: point.security?.rejected_rate_available === true
        ? nonNegativeRate(point.security.rejected_per_second)
        : null,
      time: Number.isFinite(parsedTime) ? parsedTime : null
    };
  });
}

function trendDisplayPoints(points) {
  const mapped = Array.isArray(points) ? points : [];
  const hasRate = point => Number.isFinite(point?.requests) || Number.isFinite(point?.blocked);
  const first = mapped.findIndex(hasRate);
  if (first < 0) return [];
  let last = mapped.length - 1;
  while (last > first && !hasRate(mapped[last])) last -= 1;
  return mapped.slice(first, last + 1);
}

function niceTrendMaximum(value) {
  const maximum = Math.max(0, Number(value) || 0);
  if (maximum === 0) return 0.1;
  const padded = maximum * 1.08;
  const exponent = Math.floor(Math.log10(padded));
  const magnitude = 10 ** exponent;
  const fraction = padded / magnitude;
  const steps = [1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10];
  const step = steps.find(candidate => fraction <= candidate) || 10;
  return step * magnitude;
}

function trendQuantile(sortedValues, quantile) {
  if (!sortedValues.length) return 0;
  const bounded = Math.min(1, Math.max(0, Number(quantile) || 0));
  const position = (sortedValues.length - 1) * bounded;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sortedValues[lower];
  const weight = position - lower;
  return sortedValues[lower] * (1 - weight) + sortedValues[upper] * weight;
}

function trendSeriesScaleProfile(values) {
  const finite = (Array.isArray(values) ? values : []).map(nonNegativeRate).filter(Number.isFinite);
  const rawMaximum = finite.length ? Math.max(...finite) : 0;
  const positive = finite.filter(value => value > 0).sort((a, b) => a - b);
  if (positive.length < 8 || rawMaximum <= 0) {
    return {ordinaryMaximum:rawMaximum, rawMaximum, outlierCount:0};
  }

  const median = trendQuantile(positive, 0.5);
  const deviations = positive.map(value => Math.abs(value - median)).sort((a, b) => a - b);
  const mad = trendQuantile(deviations, 0.5);
  const robustUpper = mad > 0 ? median + 6 * 1.4826 * mad : median * 3;
  const ordinary = positive.filter(value => value <= robustUpper);
  const outlierCount = positive.length - ordinary.length;
  const ordinaryMaximum = ordinary.length ? Math.max(...ordinary) : median;
  const outlierLimit = Math.max(2, Math.ceil(positive.length * 0.15));
  const clearlySeparated = ordinaryMaximum > 0 && rawMaximum >= ordinaryMaximum * 2.5;
  if (outlierCount > 0 && outlierCount <= outlierLimit && clearlySeparated) {
    return {ordinaryMaximum, rawMaximum, outlierCount};
  }
  return {ordinaryMaximum:rawMaximum, rawMaximum, outlierCount:0};
}

function trendScaleModel(seriesValues) {
  const series = Array.isArray(seriesValues) && seriesValues.some(Array.isArray)
    ? seriesValues
    : [Array.isArray(seriesValues) ? seriesValues : []];
  const profiles = series.map(trendSeriesScaleProfile);
  const rawMaximum = profiles.length ? Math.max(...profiles.map(profile => profile.rawMaximum)) : 0;
  const ordinaryMaximum = profiles.length ? Math.max(...profiles.map(profile => profile.ordinaryMaximum)) : 0;
  const outlierCount = profiles.reduce((total, profile) => total + profile.outlierCount, 0);
  if (outlierCount > 0 && ordinaryMaximum > 0 && ordinaryMaximum < rawMaximum) {
    const maximum = niceTrendMaximum(ordinaryMaximum * 1.18);
    if (maximum > 0 && maximum < rawMaximum) {
      return {maximum, rawMaximum, outlierCount, clipped:true};
    }
  }
  return {maximum:niceTrendMaximum(rawMaximum), rawMaximum, outlierCount:0, clipped:false};
}

function trendRateLabel(value, scaleMaximum = value) {
  const numeric = Math.max(0, Number(value) || 0);
  const scale = Math.max(0, Number(scaleMaximum) || 0);
  let decimals = 0;
  if (scale < 0.01) decimals = 4;
  else if (scale < 0.1) decimals = 3;
  else if (scale < 10) decimals = 2;
  else if (scale < 100) decimals = 1;
  let fixed = numeric.toFixed(decimals);
  while (numeric > 0 && Number(fixed) === 0 && decimals < 9) {
    decimals += 1;
    fixed = numeric.toFixed(decimals);
  }
  if (numeric > 0 && Number(fixed) === 0) {
    return numeric.toExponential(2).replace(/\.00e/, 'e').replace(/(\.\d*[1-9])0+e/, '$1e').replace('e+', 'e');
  }
  return trimDecimalLabel(fixed);
}

function trendTimeLabel(timestamp, includeSeconds = false) {
  if (!Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit', ...(includeSeconds ? {second: '2-digit'} : {})
  });
}

function trendSameLocalDay(firstTimestamp, secondTimestamp) {
  if (!Number.isFinite(firstTimestamp) || !Number.isFinite(secondTimestamp)) return false;
  const first = new Date(firstTimestamp);
  const second = new Date(secondTimestamp);
  return first.getFullYear() === second.getFullYear() &&
    first.getMonth() === second.getMonth() &&
    first.getDate() === second.getDate();
}

function trendDateLabel(timestamp, includeYear = false) {
  if (!Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toLocaleDateString([], {
    month:'short', day:'numeric', ...(includeYear ? {year:'numeric'} : {})
  });
}

function trendDateTimeLabel(timestamp, includeSeconds = false, includeYear = false) {
  if (!Number.isFinite(timestamp)) return '—';
  return `${trendDateLabel(timestamp, includeYear)} ${trendTimeLabel(timestamp, includeSeconds)}`;
}

function trendTimeBounds(points) {
  const times = points.map(point => point.time).filter(Number.isFinite);
  if (!times.length) return {minimum:null, maximum:null};
  return {minimum:Math.min(...times), maximum:Math.max(...times)};
}

function trendTemporalGaps(points) {
  const mapped = Array.isArray(points) ? points : [];
  const deltas = [];
  for (let index = 1; index < mapped.length; index += 1) {
    const previous = mapped[index - 1]?.time;
    const current = mapped[index]?.time;
    if (Number.isFinite(previous) && Number.isFinite(current) && current > previous) deltas.push(current - previous);
  }
  if (deltas.length < 4) return [];
  const sorted = [...deltas].sort((a, b) => a - b);
  const cadence = trendQuantile(sorted, 0.5);
  if (!(cadence > 0)) return [];
  const threshold = cadence * 4;
  const gaps = [];
  for (let index = 1; index < mapped.length; index += 1) {
    const previous = mapped[index - 1]?.time;
    const current = mapped[index]?.time;
    if (!Number.isFinite(previous) || !Number.isFinite(current) || current <= previous) continue;
    const duration = current - previous;
    if (duration > threshold) gaps.push({beforeIndex:index, start:previous, end:current, duration});
  }
  return gaps;
}

function trendSeriesUnavailableRuns(points, key, temporalGapIndexes = new Set()) {
  const mapped = Array.isArray(points) ? points : [];
  const excluded = temporalGapIndexes instanceof Set ? temporalGapIndexes : new Set();
  const runs = [];
  let startIndex = null;

  const finishRun = endIndex => {
    if (startIndex === null || endIndex < startIndex) return;
    const previousIndex = Math.max(0, startIndex - 1);
    const previousTime = mapped[previousIndex]?.time;
    const endTime = mapped[endIndex]?.time;
    runs.push({
      startIndex,
      endIndex,
      count:endIndex - startIndex + 1,
      duration:Number.isFinite(previousTime) && Number.isFinite(endTime) && endTime > previousTime
        ? endTime - previousTime
        : 0
    });
    startIndex = null;
  };

  // Index zero is the normal baseline boundary for derived interval rates. A
  // missing value there does not prove that an observed interval was lost.
  for (let index = 1; index < mapped.length; index += 1) {
    const unavailable = !Number.isFinite(mapped[index]?.[key]);
    const belongsToTelemetryGap = excluded.has(index);
    if (unavailable && !belongsToTelemetryGap) {
      if (startIndex === null) startIndex = index;
      continue;
    }
    finishRun(index - 1);
  }
  finishRun(mapped.length - 1);
  return runs;
}

function trendGapDurationLabel(milliseconds) {
  const totalSeconds = Math.max(0, Math.round((Number(milliseconds) || 0) / 1000));
  if (totalSeconds >= 86400) {
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.round((totalSeconds % 86400) / 3600);
    return hours ? `${days}d ${hours}h` : `${days}d`;
  }
  if (totalSeconds >= 3600) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.round((totalSeconds % 3600) / 60);
    return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
  }
  if (totalSeconds >= 60) return `${Math.round(totalSeconds / 60)}m`;
  return `${totalSeconds}s`;
}

function trendTimelineLayout(points, plotWidth) {
  const mapped = Array.isArray(points) ? points : [];
  const width = Math.max(1, Number(plotWidth) || 1);
  if (!mapped.length) return {positions:[], gaps:[], compressed:false};
  if (mapped.length === 1) return {positions:[width / 2], gaps:[], compressed:false};

  const gaps = trendTemporalGaps(mapped);
  const gapIndexes = new Set(gaps.map(gap => gap.beforeIndex));
  const positiveDeltas = [];
  for (let index = 1; index < mapped.length; index += 1) {
    const previous = mapped[index - 1]?.time;
    const current = mapped[index]?.time;
    if (Number.isFinite(previous) && Number.isFinite(current) && current > previous && !gapIndexes.has(index)) {
      positiveDeltas.push(current - previous);
    }
  }
  const fallbackCadence = positiveDeltas.length
    ? trendQuantile([...positiveDeltas].sort((a, b) => a - b), 0.5)
    : 1;
  const intervalWeights = [];
  for (let index = 1; index < mapped.length; index += 1) {
    if (gapIndexes.has(index)) {
      intervalWeights.push(null);
      continue;
    }
    const previous = mapped[index - 1]?.time;
    const current = mapped[index]?.time;
    const delta = Number.isFinite(previous) && Number.isFinite(current) && current > previous
      ? current - previous
      : fallbackCadence;
    intervalWeights.push(Math.max(1, delta));
  }

  const gapWidth = gaps.length
    ? Math.max(2, Math.min(width < 420 ? 16 : 22, (width * 0.24) / gaps.length))
    : 0;
  const reservedGapWidth = gapWidth * gaps.length;
  const regularWidth = Math.max(1, width - reservedGapWidth);
  const regularWeight = intervalWeights.reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);
  const regularIntervals = intervalWeights.filter(Number.isFinite).length;
  const positions = [0];
  let cursor = 0;
  intervalWeights.forEach(value => {
    if (!Number.isFinite(value)) {
      cursor += gapWidth;
    } else if (regularWeight > 0) {
      cursor += regularWidth * (value / regularWeight);
    } else {
      cursor += regularWidth / Math.max(1, regularIntervals);
    }
    positions.push(cursor);
  });

  const finalOffset = positions[positions.length - 1];
  if (finalOffset > 0 && Math.abs(finalOffset - width) > 0.001) {
    const factor = width / finalOffset;
    for (let index = 0; index < positions.length; index += 1) positions[index] *= factor;
  }
  const gapLayouts = gaps.map(gap => ({
    ...gap,
    startOffset:positions[Math.max(0, gap.beforeIndex - 1)],
    endOffset:positions[gap.beforeIndex]
  }));
  return {positions, gaps:gapLayouts, compressed:gaps.length > 0};
}

function trendAxisTickIndexes(layout, count) {
  const positions = Array.isArray(layout?.positions) ? layout.positions : [];
  if (!positions.length || count <= 0) return [];
  if (positions.length === 1 || count === 1) return [0];
  const maximum = positions[positions.length - 1];
  const indexes = [];
  for (let tick = 0; tick < count; tick += 1) {
    if (tick === 0) { indexes.push(0); continue; }
    if (tick === count - 1) { indexes.push(positions.length - 1); continue; }
    const target = maximum * (tick / (count - 1));
    let bestIndex = 0;
    let bestDistance = Number.POSITIVE_INFINITY;
    positions.forEach((position, index) => {
      const distance = Math.abs(position - target);
      if (distance < bestDistance) { bestDistance = distance; bestIndex = index; }
    });
    indexes.push(bestIndex);
  }
  return [...new Set(indexes)];
}

function trendLatestValue(key) {
  if (!state.trend.length) return null;
  const value = state.trend[state.trend.length - 1][key];
  return Number.isFinite(value) ? value : null;
}

function trendRangeText(bounds) {
  if (!Number.isFinite(bounds?.minimum) || !Number.isFinite(bounds?.maximum)) return 'Time unavailable';
  if (bounds.minimum === bounds.maximum) return trendDateTimeLabel(bounds.minimum, true);
  const span = Math.max(0, bounds.maximum - bounds.minimum);
  const includeSeconds = span > 0 && span < 10 * 60 * 1000;
  if (trendSameLocalDay(bounds.minimum, bounds.maximum)) {
    return `${trendTimeLabel(bounds.minimum, includeSeconds)}–${trendTimeLabel(bounds.maximum, includeSeconds)}`;
  }
  const minimumDate = new Date(bounds.minimum);
  const maximumDate = new Date(bounds.maximum);
  const includeYear = minimumDate.getFullYear() !== maximumDate.getFullYear();
  return `${trendDateTimeLabel(bounds.minimum, false, includeYear)}–${trendDateTimeLabel(bounds.maximum, false, includeYear)}`;
}

function trendMetaItem(id, label, value, detail = '') {
  const item = $(id);
  if (!item) return null;
  item.className = 'trend-meta-item';
  item.replaceChildren();
  const labelNode = document.createElement('small');
  labelNode.className = 'trend-meta-label';
  labelNode.textContent = label;
  const valueNode = document.createElement('strong');
  valueNode.className = 'trend-meta-value';
  valueNode.textContent = value;
  item.append(labelNode, valueNode);
  if (detail) {
    const detailNode = document.createElement('small');
    detailNode.className = 'trend-meta-detail';
    detailNode.textContent = detail;
    item.appendChild(detailNode);
  }
  return item;
}

function renderTrendNotes(notes) {
  const summary = $('trend-chart-summary');
  if (!summary) return;
  summary.replaceChildren();
  notes.filter(note => note?.text).forEach(note => {
    const item = document.createElement('span');
    item.className = `trend-status-item${note.emphasis ? ' is-emphasis' : ''}`;
    const label = document.createElement('strong');
    label.textContent = note.label;
    const text = document.createElement('span');
    text.textContent = note.text;
    item.append(label, text);
    summary.appendChild(item);
  });
}

function drawTrend() {
  const canvas = $('trend-chart');
  if (!canvas) return;
  const dpr = devicePixelRatio || 1;
  const width = Math.max(280, canvas.clientWidth || 600);
  const height = 240;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const context = canvas.getContext('2d');
  if (!context) return;
  context.scale(dpr, dpr);
  context.clearRect(0, 0, width, height);

  const compact = width < 460;
  const plot = {
    left: compact ? 46 : 58,
    right: width - 12,
    top: 20,
    bottom: height - 34
  };
  const plotWidth = Math.max(1, plot.right - plot.left);
  const plotHeight = Math.max(1, plot.bottom - plot.top);
  const displayTrend = trendDisplayPoints(state.trend);
  const requestValues = displayTrend.map(point => point.requests).filter(Number.isFinite);
  const blockedValues = displayTrend.map(point => point.blocked).filter(Number.isFinite);
  const values = [...requestValues, ...blockedValues];
  const scaleModel = trendScaleModel([requestValues, blockedValues]);
  const rawMaximum = scaleModel.rawMaximum;
  const maximum = scaleModel.maximum;
  const plotBounds = trendTimeBounds(displayTrend);
  const retainedBounds = trendTimeBounds(state.trend);
  const timelineLayout = trendTimelineLayout(displayTrend, plotWidth);
  const temporalGaps = timelineLayout.gaps;
  const temporalGapIndexes = new Set(temporalGaps.map(gap => gap.beforeIndex));
  const timeSpan = Number.isFinite(plotBounds.minimum) && Number.isFinite(plotBounds.maximum)
    ? Math.max(0, plotBounds.maximum - plotBounds.minimum)
    : 0;
  const includeSeconds = timeSpan > 0 && timeSpan < 10 * 60 * 1000;
  const spansMultipleDays = Number.isFinite(plotBounds.minimum) && Number.isFinite(plotBounds.maximum) &&
    !trendSameLocalDay(plotBounds.minimum, plotBounds.maximum);
  const spansMultipleYears = spansMultipleDays &&
    new Date(plotBounds.minimum).getFullYear() !== new Date(plotBounds.maximum).getFullYear();

  context.font = `${compact ? 10 : 11}px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
  context.fillStyle = cssColor('--muted', '#98a6bd');
  context.strokeStyle = cssColor('--chart-grid', '#25324c');
  context.lineWidth = 1;
  context.textBaseline = 'middle';
  const yTickCount = 4;
  for (let index = 0; index <= yTickCount; index += 1) {
    const ratio = index / yTickCount;
    const y = plot.top + ratio * plotHeight;
    const value = maximum * (1 - ratio);
    context.beginPath();
    context.moveTo(plot.left, y);
    context.lineTo(plot.right, y);
    context.stroke();
    context.textAlign = 'right';
    context.fillText(trendRateLabel(value, maximum), plot.left - 7, y);
  }
  context.textAlign = 'left';
  context.textBaseline = 'alphabetic';
  context.fillText('req/s', 4, 11);

  if (Number.isFinite(plotBounds.minimum) && Number.isFinite(plotBounds.maximum)) {
    const singleTimestamp = plotBounds.minimum === plotBounds.maximum;
    const tickCount = singleTimestamp ? 1 : compact ? 2 : 3;
    const tickIndexes = trendAxisTickIndexes(timelineLayout, tickCount);
    context.textBaseline = 'alphabetic';
    tickIndexes.forEach((pointIndex, tickIndex) => {
      const point = displayTrend[pointIndex];
      if (!point || !Number.isFinite(point.time)) return;
      const x = plot.left + (timelineLayout.positions[pointIndex] ?? plotWidth / 2);
      const label = spansMultipleDays
        ? trendDateTimeLabel(point.time, false, spansMultipleYears)
        : trendTimeLabel(point.time, includeSeconds);
      context.textAlign = tickIndexes.length === 1 ? 'center' : tickIndex === 0 ? 'left' : tickIndex === tickIndexes.length - 1 ? 'right' : 'center';
      context.fillText(label, x, height - 8);
    });
  }

  const xForPoint = (_point, index) => plot.left + (timelineLayout.positions[index] ?? (displayTrend.length <= 1
    ? plotWidth / 2
    : index * (plotWidth / Math.max(1, displayTrend.length - 1))));
  const yForValue = value => plot.bottom - (Math.min(maximum, Math.max(0, value)) / maximum) * plotHeight;

  const draw = (key, color, lineDash = []) => {
    context.save();
    context.strokeStyle = color;
    context.fillStyle = color;
    context.lineWidth = key === 'blocked' ? 1.35 : 2.8;
    context.lineJoin = 'round';
    context.lineCap = 'round';
    if (typeof context.setLineDash === 'function') context.setLineDash(lineDash);
    context.beginPath();
    let segmentStarted = false;
    displayTrend.forEach((point, index) => {
      if (temporalGapIndexes.has(index)) segmentStarted = false;
      const value = point[key];
      if (!Number.isFinite(value)) { segmentStarted = false; return; }
      const x = xForPoint(point, index);
      const y = yForValue(value);
      if (segmentStarted) context.lineTo(x, y);
      else { context.moveTo(x, y); segmentStarted = true; }
    });
    context.stroke();
    if (typeof context.setLineDash === 'function') context.setLineDash([]);
    const observedCount = displayTrend.reduce((count, point) => count + (Number.isFinite(point[key]) ? 1 : 0), 0);
    const denseSeries = observedCount > (compact ? 32 : 48);
    displayTrend.forEach((point, index) => {
      const value = point[key];
      if (!Number.isFinite(value)) return;
      const previousValue = index > 0 ? displayTrend[index - 1]?.[key] : null;
      const nextValue = index + 1 < displayTrend.length ? displayTrend[index + 1]?.[key] : null;
      const segmentBoundary = index === 0 || index === displayTrend.length - 1 ||
        !Number.isFinite(previousValue) || !Number.isFinite(nextValue) ||
        temporalGapIndexes.has(index) || temporalGapIndexes.has(index + 1);
      const clippedPeak = scaleModel.clipped && value > maximum;
      if (!denseSeries || segmentBoundary || clippedPeak) {
        const x = xForPoint(point, index);
        context.beginPath();
        const pointRadius = key === 'blocked' ? (compact ? 1.2 : 1.45) : (compact ? 1.7 : 2.1);
        context.arc(x, yForValue(value), pointRadius, 0, Math.PI * 2);
        context.fill();
      }
      if (clippedPeak) {
        const x = xForPoint(point, index);
        context.save();
        context.font = `${compact ? 11 : 12}px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
        context.textAlign = 'center';
        context.textBaseline = 'top';
        context.fillText('▲', x, plot.top + 2);
        context.restore();
      }
    });
    context.restore();
  };
  const requestColor = cssColor('--chart-requests', '#67a6ff');
  const blockedColor = cssColor('--chart-blocked', '#ff7188');
  draw('requests', requestColor);
  draw('blocked', blockedColor);

  const requestUnavailableRuns = trendSeriesUnavailableRuns(displayTrend, 'requests', temporalGapIndexes);
  const blockedUnavailableRuns = trendSeriesUnavailableRuns(displayTrend, 'blocked', temporalGapIndexes);
  const clampedLabelX = (text, x, fontSize) => {
    const estimatedHalfWidth = Math.min(plotWidth / 2, String(text || '').length * Math.max(1, Number(fontSize) || 10) * 0.28);
    return Math.min(plot.right - estimatedHalfWidth - 2, Math.max(plot.left + estimatedHalfWidth + 2, x));
  };
  const drawSeriesUnavailable = (runs, color, label, xShift, labelRow) => {
    if (!runs.length) return;
    context.save();
    context.strokeStyle = color;
    context.fillStyle = color;
    context.lineWidth = 1.15;
    if (typeof context.setLineDash === 'function') context.setLineDash([3, 3]);
    runs.forEach(run => {
      const firstOffset = timelineLayout.positions[Math.max(0, run.startIndex - 1)];
      const lastOffset = timelineLayout.positions[run.endIndex];
      if (!Number.isFinite(firstOffset) || !Number.isFinite(lastOffset)) return;
      const x = plot.left + (firstOffset + lastOffset) / 2 + xShift;
      context.beginPath();
      context.moveTo(x, plot.top + 2);
      context.lineTo(x, plot.bottom);
      context.stroke();
    });
    if (typeof context.setLineDash === 'function') context.setLineDash([]);
    context.font = `${compact ? 10 : 11}px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
    context.textAlign = 'center';
    context.textBaseline = 'alphabetic';
    runs.forEach(run => {
      const firstOffset = timelineLayout.positions[Math.max(0, run.startIndex - 1)];
      const lastOffset = timelineLayout.positions[run.endIndex];
      if (!Number.isFinite(firstOffset) || !Number.isFinite(lastOffset)) return;
      const x = plot.left + (firstOffset + lastOffset) / 2 + xShift;
      context.fillText('×', x, plot.bottom + 13);
    });
    if (!compact) {
      const labeledRuns = runs.length <= 2
        ? runs
        : [...runs].sort((first, second) => second.duration - first.duration || second.count - first.count).slice(0, 1);
      labeledRuns.forEach(run => {
        const firstOffset = timelineLayout.positions[Math.max(0, run.startIndex - 1)];
        const lastOffset = timelineLayout.positions[run.endIndex];
        if (!Number.isFinite(firstOffset) || !Number.isFinite(lastOffset)) return;
        const x = plot.left + (firstOffset + lastOffset) / 2 + xShift;
        const suffix = run.count > 1 ? ` · ${run.count} intervals` : '';
        const labelText = `${label} unavailable${suffix}`;
        context.textBaseline = 'top';
        context.fillText(labelText, clampedLabelX(labelText, x, compact ? 10 : 11), plot.top + 6 + labelRow * 14);
      });
    }
    context.restore();
  };

  // A series-specific unavailable rate is different from a telemetry time gap:
  // the sample exists, but one derived metric cannot be trusted for that
  // interval (for example after a process restart or counter reset). Keep the
  // line disconnected and mark the exact interval in the series color.
  drawSeriesUnavailable(requestUnavailableRuns, requestColor, 'EdgeProxy request rate', -2, 0);
  drawSeriesUnavailable(blockedUnavailableRuns, blockedColor, 'SecurityEdge rejection rate', 2, 1);

  if (temporalGaps.length) {
    context.save();
    const gapColor = cssColor('--muted', '#98a6bd');
    context.strokeStyle = gapColor;
    context.fillStyle = gapColor;
    context.lineWidth = 1;
    if (typeof context.setLineDash === 'function') context.setLineDash([2, 3]);
    temporalGaps.forEach(gap => {
      const x = plot.left + (gap.startOffset + gap.endOffset) / 2;
      context.beginPath();
      context.moveTo(x, plot.top + 2);
      context.lineTo(x, plot.bottom);
      context.stroke();
    });
    if (typeof context.setLineDash === 'function') context.setLineDash([]);
    context.font = `${compact ? 9 : 10}px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`;
    context.textAlign = 'center';
    context.textBaseline = 'alphabetic';
    temporalGaps.forEach(gap => {
      const x = plot.left + (gap.startOffset + gap.endOffset) / 2;
      context.fillText('//', x, plot.bottom + 13);
    });
    if (!compact) {
      // Keep the reason for a time break visible without turning a dense old
      // history into a wall of overlapping labels. With one or two gaps we
      // label every break; with many gaps the longest break gets the explicit
      // label while the summary below the chart reports the complete count.
      const labeledGaps = temporalGaps.length <= 2
        ? temporalGaps
        : [...temporalGaps].sort((first, second) => second.duration - first.duration).slice(0, 1);
      labeledGaps.forEach(gap => {
        const x = plot.left + (gap.startOffset + gap.endOffset) / 2;
        const labelText = `Telemetry gap · ${trendGapDurationLabel(gap.duration)}`;
        context.textBaseline = 'top';
        context.fillText(labelText, clampedLabelX(labelText, x, compact ? 9 : 10), plot.top + 6);
      });
    }
    context.restore();
  }

  const retainedCount = state.trend.length;
  const requestCount = state.trend.filter(point => Number.isFinite(point.requests)).length;
  const blockedCount = state.trend.filter(point => Number.isFinite(point.blocked)).length;
  const requestLatest = trendLatestValue('requests');
  const blockedLatest = trendLatestValue('blocked');
  const rateText = value => Number.isFinite(value) ? `${trendRateLabel(value)} req/s` : 'Unavailable';
  $('trend-requests-latest').textContent = rateText(requestLatest);
  $('trend-blocked-latest').textContent = rateText(blockedLatest);

  const coverageText = (kind, key, count, seriesValues) => {
    if (!retainedCount) return 'Waiting for rate samples';
    const sampleText = `${retainedCount} sample${retainedCount === 1 ? '' : 's'} retained`;
    if (!count) return `No rate intervals available · ${sampleText}`;
    const intervalText = `${count} rate interval${count === 1 ? '' : 's'} available from ${retainedCount} sample${retainedCount === 1 ? '' : 's'}`;
    if (seriesValues.length && seriesValues.every(value => value === 0)) {
      // A zero is only evidence about an interval that was actually observed.
      // Keep the concise wording for complete histories (including the normal
      // first-sample baseline), but scope the claim when later intervals or
      // whole time spans are unavailable so missing telemetry is never read as
      // evidence of zero traffic.
      const unavailableAfterBaseline = state.trend.slice(1).some(point => !Number.isFinite(point[key]));
      const qualifier = unavailableAfterBaseline || temporalGaps.length ? ' in observed intervals' : '';
      return kind === 'blocked' ? `No rejections${qualifier} · ${intervalText}` : `No requests${qualifier} · ${intervalText}`;
    }
    return intervalText;
  };
  $('trend-requests-coverage').textContent = coverageText('requests', 'requests', requestCount, state.trend.map(point => point.requests).filter(Number.isFinite));
  $('trend-blocked-coverage').textContent = coverageText('blocked', 'blocked', blockedCount, state.trend.map(point => point.blocked).filter(Number.isFinite));

  const retainedRangeText = trendRangeText(retainedBounds);
  const retainedCountText = `${retainedCount} sample${retainedCount === 1 ? '' : 's'}`;
  const sampleInterval = String(state.overview?.telemetry_history?.sample_interval || '').trim();
  const retainedDetailText = sampleInterval ? `${retainedCountText} · server-side ${sampleInterval}` : retainedCountText;
  const scaleValueText = values.length ? `0–${trendRateLabel(maximum, maximum)} req/s` : 'Waiting for rates';
  const scaleDetailText = !values.length
    ? ''
    : scaleModel.clipped
      ? `${scaleModel.outlierCount} peak${scaleModel.outlierCount === 1 ? '' : 's'} · max ${trendRateLabel(rawMaximum, rawMaximum)} req/s`
      : 'Adaptive scale';

  trendMetaItem('trend-window', 'History', retainedCount ? retainedRangeText : 'Waiting for history', retainedDetailText);
  trendMetaItem('trend-scale', 'Scale', scaleValueText, scaleDetailText);

  const empty = $('trend-empty');
  empty.hidden = values.length > 0;
  if (!values.length) empty.textContent = 'No interval-rate history available yet.';

  if (values.length) {
    const notes = [];
    const retainedTemporalGaps = trendTemporalGaps(state.trend);
    const retainedTemporalGapIndexes = new Set(retainedTemporalGaps.map(gap => gap.beforeIndex));
    const retainedRequestUnavailableRuns = trendSeriesUnavailableRuns(state.trend, 'requests', retainedTemporalGapIndexes);
    const retainedBlockedUnavailableRuns = trendSeriesUnavailableRuns(state.trend, 'blocked', retainedTemporalGapIndexes);
    const requestUnavailableIntervals = retainedRequestUnavailableRuns.reduce((total, run) => total + run.count, 0);
    const blockedUnavailableIntervals = retainedBlockedUnavailableRuns.reduce((total, run) => total + run.count, 0);

    if (temporalGaps.length) {
      const longestGap = Math.max(...temporalGaps.map(gap => gap.duration));
      notes.push({
        label:'Gaps',
        text:`${temporalGaps.length} telemetry gap${temporalGaps.length === 1 ? '' : 's'} · long gaps compressed on the time axis${longestGap > 0 ? ` (longest ${trendGapDurationLabel(longestGap)})` : ''}; missing time spans remain blank and are never zero-filled.`
      });
    }
    if (requestUnavailableIntervals > 0 || blockedUnavailableIntervals > 0) {
      const availabilityParts = [];
      if (requestUnavailableIntervals > 0) {
        availabilityParts.push(`EdgeProxy request rate unavailable for ${requestUnavailableIntervals} observed interval${requestUnavailableIntervals === 1 ? '' : 's'}`);
      }
      if (blockedUnavailableIntervals > 0) {
        availabilityParts.push(`SecurityEdge rejection rate unavailable for ${blockedUnavailableIntervals} observed interval${blockedUnavailableIntervals === 1 ? '' : 's'}`);
      }
      notes.push({
        label:'Availability',
        text:`${availabilityParts.join('; ')}. Color-coded dashed markers identify these series-specific intervals; values remain blank and are never zero-filled.`
      });
    }
    if (!notes.length) {
      notes.push({
        label:'Status',
        text:scaleModel.clipped ? 'Isolated peaks are marked at the chart ceiling; exact values remain in the scale summary.' : 'Observed rate intervals are shown at full scale with no telemetry gaps.'
      });
    }
    renderTrendNotes(notes);
  } else if (retainedCount) {
    renderTrendNotes([{label:'Status', text:`No interval rates are available yet across ${retainedCountText}.`}]);
  } else {
    renderTrendNotes([{label:'Status', text:'Waiting for persisted interval-rate history.'}]);
  }
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
  const latency = total.latency || {}, latencyAvailable = completedSecurityDecisions(total) > 0;
  $('security-latency').innerHTML = metricRows([
    ['Average', msIf(latency.average_ms, latencyAvailable)], ['Maximum', msIf(latency.maximum_ms, latencyAvailable)],
    ['P50', msIf(latency.p50_ms, latencyAvailable)], ['P95', msIf(latency.p95_ms, latencyAvailable)], ['P99', msIf(latency.p99_ms, latencyAvailable)]
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
    try {
      await api(`/api/v1/bans/${encodeURIComponent(button.dataset.unban)}`, {method:'DELETE'});
      await loadBans(); toast('Temporary ban removed');
    } catch (error) { toast(error.message); }
  });
}

function renderTraffic() {
  const edgeMetrics = edgeMetricsSnapshot();
  if (!edgeMetrics) {
    $('cache-stats').innerHTML = '<div class="empty-state">EdgeProxy metrics are unavailable. Check the connectivity panel.</div>';
    $('latency-stats').innerHTML = '<div class="empty-state">No EdgeProxy latency telemetry is available.</div>';
    return;
  }
  const total = edgeMetrics.total || {};
  const cacheLookups = Number(total.cache_hits || 0) + Number(total.cache_misses || 0);
  $('cache-stats').innerHTML = metricRows([
    ['Hits', fmt(total.cache_hits)], ['Misses', fmt(total.cache_misses)], ['Stale', fmt(total.cache_stale)],
    ['Bypasses', fmt(total.cache_bypasses)], ['Stores', fmt(total.cache_stores)], ['Hit ratio', pctIf(total.cache_hit_ratio, cacheLookups > 0)]
  ]);
  const latency = total.response_latency_ms || {}, latencyAvailable = Number(latency.count || 0) > 0;
  $('latency-stats').innerHTML = metricRows([
    ['Average', msIf(latency.average, latencyAvailable)], ['Minimum', msIf(latency.minimum, latencyAvailable)], ['Maximum', msIf(latency.maximum, latencyAvailable)],
    ['P50', msIf(latency.p50, latencyAvailable)], ['P95', msIf(latency.p95, latencyAvailable)], ['P99', msIf(latency.p99, latencyAvailable)]
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
  const results = await Promise.allSettled(requests);
  const [edgeConfig, edgeWatch, securityConfig, securityWatch] = results;
  if (edgeConfig.status === 'fulfilled') state.edgeConfig = edgeConfig.value;
  if (edgeWatch.status === 'fulfilled') state.edgeWatch = edgeWatch.value;
  if (securityConfig.status === 'fulfilled') state.securityConfig = securityConfig.value;
  if (securityWatch.status === 'fulfilled') state.securityWatch = securityWatch.value;
  return {
    successful: results.filter(result => result.status === 'fulfilled').length,
    failures: results.filter(result => result.status === 'rejected').map(result => result.reason?.message || 'Control-plane request failed.')
  };
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
  return (edgeStatusSnapshot()?.routes || []).find(route => String(route.name).toLowerCase() === String(name).toLowerCase()) || null;
}
function routeMetrics(name) {
  const routes = edgeMetricsSnapshot()?.routes || {};
  const key = Object.keys(routes).find(item => item.toLowerCase() === String(name).toLowerCase());
  return key ? routes[key] : null;
}
function statusOrigin(status, origin) {
  return (status?.upstreams || []).find(item => String(item.name || '').toLowerCase() === String(origin.name || '').toLowerCase()) ||
    (status?.upstreams || []).find(item => (item.url || item.upstream) === origin.url) || null;
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
  const cacheSelect = $('cache-route-select');
  const loadedCacheRoute = cacheSelect.dataset.loaded || '';
  preserveSelect('cache-route-select', routes);
  const cacheForm = $('cache-config-form');
  const cacheAvailable = routes.length > 0;
  cacheForm.querySelectorAll('input,select').forEach(control => { control.disabled = !cacheAvailable; });
  $('save-cache-config').disabled = !cacheAvailable;
  $('purge-form').querySelector('button[type="submit"]').disabled = !cacheAvailable;
  if (!cacheAvailable) {
    cacheForm.reset();
    cacheSelect.dataset.loaded = '';
    state.cacheEditorDirty = false;
    $('cache-config-result').textContent = 'No routes are configured.';
  } else {
    const selectedCacheRoute = cacheSelect.value || routes[0].name;
    const loadedStillExists = routes.some(route => route.name === loadedCacheRoute);
    if (!loadedStillExists || loadedCacheRoute !== selectedCacheRoute) {
      state.cacheEditorDirty = false;
      loadCacheEditor(selectedCacheRoute);
    } else if (!state.cacheEditorDirty) loadCacheEditor(selectedCacheRoute);
  }

  $('route-cards').innerHTML = routes.length ? routes.map(route => {
    const status = routeStatus(route.name), telemetry = routeMetrics(route.name);
    const routeReadyKnown = typeof status?.ready === 'boolean';
    const origins = (route.upstreams || []).map(origin => {
      const live = statusOrigin(status, origin), om = telemetry?.upstreams?.[origin.url] || null;
      const healthKnown = typeof live?.healthy === 'boolean';
      const healthClass = healthKnown ? (live.healthy ? 'ready' : 'error') : '';
      const healthText = healthKnown ? (live.healthy ? 'healthy' : 'unhealthy') : 'unknown';
      const callsText = om ? `${fmt(om.calls)} calls` : 'telemetry unavailable';
      const latencyText = live && Number(live.scheduler_selections || 0) > 0 ? ms(live.ewma_latency_ms) : '—';
      return `<div class="origin-row"><div class="origin-identity"><strong>${esc(origin.name || origin.url)}</strong><span>${esc(origin.url)}</span></div><div class="origin-badges"><span class="badge ${healthClass}">${healthText}</span><span class="badge">w${fmt(origin.weight)} · p${fmt(origin.priority)}</span><span class="badge">${callsText}</span><span class="badge">${latencyText}</span></div><div class="origin-actions"><button class="ghost compact-button" data-origin-edit="${esc(route.name)}" data-origin="${esc(origin.name)}">Edit</button><button class="ghost compact-button" data-origin-telemetry="${esc(route.name)}" data-origin="${esc(origin.name)}">Telemetry</button></div></div>`;
    }).join('');
    const algorithm = route.load_balancing?.algorithm || 'round_robin';
    const cache = route.cache || {}, health = route.health_check || {};
    const routeClass = routeReadyKnown ? (status.ready ? 'ready' : 'error') : '';
    const routeLabel = routeReadyKnown ? (status.ready ? 'READY' : 'NOT READY') : 'UNKNOWN';
    const routeCacheLookups = Number(telemetry?.cache_hits || 0) + Number(telemetry?.cache_misses || 0);
    const telemetrySummary = telemetry ? `${fmt(telemetry.requests)} requests · ${fmt(telemetry.canceled_requests)} canceled · ${routeCacheLookups > 0 ? pct(telemetry.cache_hit_ratio) : 'no cache lookups'}` : 'Telemetry unavailable';
    return `<article class="route-card managed-route"><div class="route-head"><div><h2>${esc(route.name)}</h2><p>${esc((route.hosts || []).join(', '))} · ${esc(route.path_prefix || '/')}</p></div><span class="badge ${routeClass}">${routeLabel}</span></div><div class="scheduler-banner"><span>Scheduler</span><strong>${esc(algorithm)}</strong><small>${telemetrySummary}</small></div><div class="route-facts"><span>Cache <strong>${cache.enabled ? 'enabled':'disabled'}</strong> · ${esc(cache.default_ttl || '—')}</span><span>Health checks <strong>${health.enabled ? 'enabled':'disabled'}</strong> · ${esc(health.interval || '—')}</span><span>Retries <strong>${fmt(route.proxy?.retry_count)}</strong> · ${esc(route.proxy?.request_timeout || '—')} timeout</span></div><div class="route-actions"><button class="ghost" data-route-edit="${esc(route.name)}">Edit all settings</button><button class="ghost" data-origin-add="${esc(route.name)}">Add origin</button><button class="ghost" data-route-telemetry="${esc(route.name)}">Telemetry</button><button class="danger ghost" data-route-delete="${esc(route.name)}">Delete</button></div><h3>Origins</h3>${origins || '<p class="muted">No origins configured.</p>'}</article>`;
  }).join('') : '<article class="panel empty-state">No routes are configured. Create the first route with the validated form.</article>';

  $('route-telemetry-table').innerHTML = routes.length ? routes.map(route => {
    const m = routeMetrics(route.name);
    if (!m) return `<tr><td><strong>${esc(route.name)}</strong><small class="table-subline">${esc(route.load_balancing?.algorithm || 'round_robin')}</small></td><td>${esc(route.load_balancing?.algorithm || 'round_robin')}</td><td colspan="7" class="muted">EdgeProxy telemetry unavailable.</td><td class="table-actions-cell"><div class="table-actions"><button class="ghost compact-button" data-route-telemetry="${esc(route.name)}">Details</button></div></td></tr>`;
    const latency = m.response_latency_ms || {}, upstream = m.upstream || {};
    const errors = Number(m.client_errors||0)+Number(m.server_errors||0);
    const completedOutcomes = Number(m.success || 0) + errors;
    const canceledRequests = Number(m.canceled_requests || 0);
    const cacheLookups = Number(m.cache_hits || 0) + Number(m.cache_misses || 0);
    const latencyAvailable = Number(latency.count || 0) > 0;
    const requestRates = completedOutcomes > 0 ? `${pct(m.success_rate)} / ${pct(m.error_rate)}` : '— / —';
    const errorSummary = completedOutcomes > 0
      ? `${fmt(errors)} client-facing errors${canceledRequests > 0 ? ` · ${fmt(canceledRequests)} canceled` : ''}`
      : (canceledRequests > 0 ? `${fmt(canceledRequests)} canceled · no completed responses` : 'No requests yet');
    return `<tr><td><strong>${esc(route.name)}</strong><small class="table-subline">${esc(route.load_balancing?.algorithm || 'round_robin')}</small></td><td>${esc(route.load_balancing?.algorithm || 'round_robin')}</td><td>${fmt(m.requests)}<small class="table-subline">${fmt(canceledRequests)} canceled</small></td><td>${requestRates}<small class="table-subline">${errorSummary}</small></td><td>${pctIf(m.cache_hit_ratio, cacheLookups > 0)}<small class="table-subline">${fmt(m.cache_hits)} hit · ${fmt(m.cache_misses)} miss · ${fmt(m.cache_stale)} stale</small></td><td>${msIf(latency.minimum, latencyAvailable)} / ${msIf(latency.average, latencyAvailable)} / ${msIf(latency.maximum, latencyAvailable)}</td><td>${msIf(latency.p50, latencyAvailable)} / ${msIf(latency.p95, latencyAvailable)} / ${msIf(latency.p99, latencyAvailable)}</td><td>${fmt(m.upstream_calls)} calls<small class="table-subline">${fmt(upstream.failures)} fail · ${fmt(upstream.timeouts)} timeout · ${fmt(m.retries)} retry</small></td><td>${bytes(m.bytes_in)} / ${bytes(m.bytes_out)}</td><td class="table-actions-cell"><div class="table-actions"><button class="ghost compact-button" data-route-telemetry="${esc(route.name)}">Details</button></div></td></tr>`;
  }).join('') : '<tr><td colspan="10" class="muted">No routes configured.</td></tr>';

  const originRows = [];
  routes.forEach(route => {
    const status = routeStatus(route.name), m = routeMetrics(route.name);
    (route.upstreams || []).forEach(origin => {
      const live = statusOrigin(status, origin), om = m?.upstreams?.[origin.url] || null, latency = om?.latency_ms || {};
      const healthKnown = typeof live?.healthy === 'boolean';
      const healthClass = healthKnown ? (live.healthy ? 'ready' : 'error') : '';
      const healthText = healthKnown ? (live.healthy ? 'healthy' : 'unhealthy') : 'unknown';
      const latencyAvailable = Number(latency.count || 0) > 0;
      const metricsCells = om
        ? `<td>${fmt(om.calls)}<small class="table-subline">${fmt(om.canceled)} canceled</small></td><td>${pctIf(om.success_rate, latencyAvailable)}<small class="table-subline">${fmt(om.failures)} failures</small></td><td>${fmt(om.timeouts)} / ${fmt(om.retries)}</td><td>${msIf(latency.p50, latencyAvailable)} / ${msIf(latency.p95, latencyAvailable)} / ${msIf(latency.p99, latencyAvailable)}</td>`
        : '<td colspan="4" class="muted">EdgeProxy telemetry unavailable.</td>';
      const runtimeCells = live
        ? `<td>${fmt(live.active_requests)} / ${msIf(live.ewma_latency_ms, Number(live.scheduler_selections || 0) > 0)}</td><td>${fmt(live.scheduler_selections)}<small class="table-subline">${fmt(live.health_failures)} fail · ${fmt(live.health_recoveries)} recovery</small></td>`
        : '<td colspan="2" class="muted">Runtime health unavailable.</td>';
      originRows.push(`<tr><td><strong>${esc(route.name)}</strong><small class="table-subline">${esc(origin.name)}</small></td><td>${esc(origin.url)}</td><td><span class="badge ${healthClass}">${healthText}</span></td><td>${fmt(origin.weight)} / ${fmt(origin.priority)}</td>${metricsCells}${runtimeCells}<td class="table-actions-cell"><div class="table-actions"><button class="ghost compact-button" data-origin-edit="${esc(route.name)}" data-origin="${esc(origin.name)}">Edit</button><button class="ghost compact-button" data-origin-telemetry="${esc(route.name)}" data-origin="${esc(origin.name)}">Details</button></div></td></tr>`);
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
  state.cacheEditorDirty = false;
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
    state.cacheEditorDirty = false;
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
      ['Calls / canceled',`${fmt(m.calls)} / ${fmt(m.canceled)}`],['Success / failures',`${fmt(m.success)} / ${fmt(m.failures)}`],['Success / error rate',Number(m.success || 0) + Number(m.failures || 0) > 0 ? `${pct(m.success_rate)} / ${pct(m.error_rate)}` : '— / —'],
      ['Timeouts / retries',`${fmt(m.timeouts)} / ${fmt(m.retries)}`],['Min / average / max',`${msIf(latency.minimum, Number(latency.count || 0) > 0)} / ${msIf(latency.average, Number(latency.count || 0) > 0)} / ${msIf(latency.maximum, Number(latency.count || 0) > 0)}`],
      ['P50 / P95 / P99',`${msIf(latency.p50, Number(latency.count || 0) > 0)} / ${msIf(latency.p95, Number(latency.count || 0) > 0)} / ${msIf(latency.p99, Number(latency.count || 0) > 0)}`],['Active requests',fmt(runtime.active_requests)],
      ['EWMA latency',msIf(runtime.ewma_latency_ms, Number(runtime.scheduler_selections || 0) > 0)],['Scheduler selections',fmt(runtime.scheduler_selections)],['Health failures / recoveries',`${fmt(runtime.health_failures)} / ${fmt(runtime.health_recoveries)}`]
    ] : [
      ['Algorithm',data.route?.load_balancing?.algorithm||'round_robin'],['Ready',runtime.ready ? 'Ready':'Not ready'],['Requests / canceled',`${fmt(m.requests)} / ${fmt(m.canceled_requests)}`],
      ['Success / client / server',`${fmt(m.success)} / ${fmt(m.client_errors)} / ${fmt(m.server_errors)}`],['Success / error rate',Number(m.success || 0) + Number(m.client_errors || 0) + Number(m.server_errors || 0) > 0 ? `${pct(m.success_rate)} / ${pct(m.error_rate)}` : '— / —'],['Proxy errors',fmt(m.proxy_errors)],
      ['Cache hit / miss / stale / bypass',`${fmt(m.cache_hits)} / ${fmt(m.cache_misses)} / ${fmt(m.cache_stale)} / ${fmt(m.cache_bypasses)}`],['Cache hit ratio',pctIf(m.cache_hit_ratio, Number(m.cache_hits || 0) + Number(m.cache_misses || 0) > 0)],['Cache stores',fmt(m.cache_stores)],
      ['Min / average / max',`${msIf(latency.minimum, Number(latency.count || 0) > 0)} / ${msIf(latency.average, Number(latency.count || 0) > 0)} / ${msIf(latency.maximum, Number(latency.count || 0) > 0)}`],['P50 / P95 / P99',`${msIf(latency.p50, Number(latency.count || 0) > 0)} / ${msIf(latency.p95, Number(latency.count || 0) > 0)} / ${msIf(latency.p99, Number(latency.count || 0) > 0)}`],
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
  if (state.selectedPolicy !== 'default') {
    const selectedRoute = routes.find(route => String(route.name).toLowerCase() === String(state.selectedPolicy).toLowerCase());
    if (selectedRoute) state.selectedPolicy = selectedRoute.name;
    else { state.selectedPolicy = 'default'; state.policyDirty = false; }
  }
  scopes.innerHTML = `<button data-policy="default" class="${state.selectedPolicy === 'default' ? 'active' : ''}">Default policy</button>` + routes.map(route => `<button data-policy="${esc(route.name)}" class="${state.selectedPolicy === route.name ? 'active' : ''}">${esc(route.name)}${state.policies.route_policies?.[route.name] ? ' · override' : ''}</button>`).join('');
  scopes.querySelectorAll('button').forEach(button => button.onclick = () => {
    state.selectedPolicy = button.dataset.policy;
    state.policyDirty = false;
    renderPolicies();
  });
  const isDefault = state.selectedPolicy === 'default';
  const policy = isDefault ? state.policies.default_policy : (state.policies.effective_policies?.[state.selectedPolicy] || state.policies.default_policy);
  const form = $('policy-form');
  $('policy-title').textContent = isDefault ? 'Default policy' : `${state.selectedPolicy} policy`;
  $('delete-override').classList.toggle('hidden', isDefault || !state.policies.route_policies?.[state.selectedPolicy]);
  if (state.policyDirty) return;
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
    state.policyDirty = false;
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
    ['Telemetry history',history.enabled ? `${fmt(history.samples?.length)} / ${fmt(history.capacity)} samples` : 'Disabled'],['History sampling',history.enabled ? `Server-side · ${history.sample_interval || '—'}` : 'Disabled'],['History persistence',history.persistent ? (history.last_error ? `Degraded: ${history.last_error}` : 'Healthy') : 'Memory only']
  ]);
  const edgeStatus = state.overview?.edgeproxy_status_code;
  const edgeRuntime = edgeStatusSnapshot();
  const edgeMetrics = edgeMetricsSnapshot();
  const routes = edgeRuntime?.routes || [];
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
    ['Metrics schema',edgeMetrics?.schema_version||'—'],['Uptime',edgeMetrics ? `${fmt(edgeMetrics.uptime_seconds)} s` : '—'],
    ['In flight',edgeMetrics ? fmt(edgeMetrics.inflight) : '—'],['Ready routes',edgeRuntime ? `${routes.filter(route=>route.ready).length}/${routes.length}` : '—']
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
window.addEventListener('resize', () => requestAnimationFrame(ensureActiveNavVisible));
if (window.ResizeObserver) {
  const navResizeObserver = new ResizeObserver(() => requestAnimationFrame(ensureActiveNavVisible));
  navResizeObserver.observe($('nav'));
}
document.querySelectorAll('[data-go]').forEach(button => button.onclick = () => setView(button.dataset.go));
$('security-filters').onsubmit = event => { event.preventDefault(); loadSecurity(true); };
$('older-security').onclick = () => loadSecurity(false);
$('clear-security').onclick = async () => {
  if (!confirm('Clear all retained SecurityEdge events, the active NDJSON log, and rotated backups?')) return;
  try { await api('/api/v1/logs',{method:'DELETE'}); await loadSecurity(true); toast('Security events and persistent log files cleared'); }
  catch (error) { toast(error.message); }
};
$('export-ndjson').onclick = () => download('/api/v1/logs/export?format=ndjson','security-events.ndjson').catch(error=>toast(error.message));
$('export-csv').onclick = () => download('/api/v1/logs/export?format=csv','security-events.csv').catch(error=>toast(error.message));
$('export-prometheus').onclick = () => download('/api/v1/metrics/prometheus','securityedge.prom').catch(error=>toast(error.message));
$('clear-bans').onclick = async () => {
  if (!confirm('Clear all active temporary bans?')) return;
  try { await api('/api/v1/bans',{method:'DELETE'}); await loadBans(); toast('Temporary bans cleared'); }
  catch (error) { toast(error.message); }
};
$('policy-form').onsubmit = savePolicy;
$('policy-form').addEventListener('input', () => { state.policyDirty = true; });
$('policy-form').addEventListener('change', () => { state.policyDirty = true; });
$('delete-override').onclick = async () => {
  try {
    await api(`/api/v1/policies/${encodeURIComponent(state.selectedPolicy)}`,{method:'DELETE'});
    state.policyDirty = false;
    await loadPolicies(); toast('Route override deleted');
  } catch (error) { toast(error.message); }
};
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
$('reload-config').onclick = async () => {
  try { await api('/api/v1/reload',{method:'POST'}); await refreshAll(); toast('Configuration reloaded'); }
  catch (error) { toast(error.message); }
};
document.querySelectorAll('[data-system-form]').forEach(form => {
  const key = form.dataset.systemForm;
  form.addEventListener('input', () => { state.systemDirty[key] = true; });
  form.addEventListener('change', () => { state.systemDirty[key] = true; });
  form.addEventListener('submit', saveSystemForm);
});
$('refresh-control').onclick = async () => {
  const result = await loadControlData();
  renderRoutes();
  if (!result.failures.length) toast('Control-plane data refreshed');
  else if (result.successful) toast(`Control-plane data partially refreshed · ${result.failures.length} request${result.failures.length === 1 ? '' : 's'} unavailable`);
  else toast(result.failures[0]);
};
$('add-route').onclick = () => openRouteDialog();
$('cache-config-form').addEventListener('input', event => { if (event.target !== $('cache-route-select')) state.cacheEditorDirty = true; });
$('cache-config-form').addEventListener('change', event => { if (event.target !== $('cache-route-select')) state.cacheEditorDirty = true; });
$('cache-route-select').onchange = event => { state.cacheEditorDirty = false; loadCacheEditor(event.currentTarget.value); };
$('save-cache-config').onclick = saveCacheEditor;
$('route-form').onsubmit = saveRoute; $('origin-form').onsubmit = saveOrigin;
document.querySelectorAll('[data-close-dialog]').forEach(button => button.onclick = () => $(button.dataset.closeDialog).close());
$('edge-config-editor').addEventListener('input', () => { state.edgeEditorDirty = true; });
$('security-config-editor').addEventListener('input', () => { state.securityEditorDirty = true; });
$('save-edge-config').onclick = () => saveRawConfig('edge'); $('save-security-config').onclick = () => saveRawConfig('security');
$('reload-edge-config').onclick = async () => { try { await api('/api/v1/edgeproxy/config/reload',{method:'POST'}); state.edgeEditorDirty=false; await refreshAll(); toast('EdgeProxy configuration reloaded'); } catch(error) { $('edge-config-result').textContent=error.message; } };
$('reload-security-config').onclick = async () => { try { await api('/api/v1/reload',{method:'POST'}); state.securityEditorDirty=false; await refreshAll(); toast('SecurityEdge configuration reloaded'); } catch(error) { $('security-config-result').textContent=error.message; } };
window.addEventListener('resize', () => state.overview && drawTrend());
window.addEventListener('securityedge:themechange', () => state.overview && drawTrend());

if (state.token) login(state.token).catch(lock);
else setConsoleLocked(true, true);
setInterval(() => { if (state.token) refreshAll(); }, 5000);
