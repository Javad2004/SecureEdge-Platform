#!/usr/bin/env node
'use strict';

import {spawn} from 'node:child_process';
import {existsSync, mkdtempSync, readFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

function argument(name, fallback = '') {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}
function browserCandidates() {
  const env = process.env;
  return [
    argument('browser'), env.CHROMIUM_PATH, env.CHROME_PATH,
    '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome',
    env.LOCALAPPDATA && join(env.LOCALAPPDATA, 'Google/Chrome/Application/chrome.exe'),
    env.LOCALAPPDATA && join(env.LOCALAPPDATA, 'Microsoft/Edge/Application/msedge.exe'),
    env.PROGRAMFILES && join(env.PROGRAMFILES, 'Google/Chrome/Application/chrome.exe'),
    env.PROGRAMFILES && join(env.PROGRAMFILES, 'Microsoft/Edge/Application/msedge.exe'),
    env['PROGRAMFILES(X86)'] && join(env['PROGRAMFILES(X86)'], 'Microsoft/Edge/Application/msedge.exe')
  ].filter(Boolean);
}
function sleep(ms) { return new Promise(resolvePromise => setTimeout(resolvePromise, ms)); }
async function eventually(check, description, timeout = 15000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try { if (await check()) return; } catch (error) { last = error; }
    await sleep(100);
  }
  throw new Error(`${description} did not become ready${last ? `: ${last.message}` : ''}`);
}

class CDP {
  constructor(url) {
    this.nextID = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.socket = new WebSocket(url);
  }
  async open() {
    if (this.socket.readyState === WebSocket.OPEN) return;
    await new Promise((resolvePromise, reject) => {
      this.socket.addEventListener('open', resolvePromise, {once: true});
      this.socket.addEventListener('error', () => reject(new Error('DevTools WebSocket connection failed')), {once: true});
    });
    this.socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(`${pending.method}: ${message.error.message}`));
        else pending.resolve(message.result || {});
        return;
      }
      for (const listener of this.listeners.get(message.method) || []) listener(message.params || {});
    });
  }
  on(method, listener) {
    const values = this.listeners.get(method) || [];
    values.push(listener);
    this.listeners.set(method, values);
  }
  send(method, params = {}) {
    const id = this.nextID++;
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, {resolve: resolvePromise, reject, method});
      this.socket.send(JSON.stringify({id, method, params}));
    });
  }
  async evaluate(expression, awaitPromise = false) {
    const result = await this.send('Runtime.evaluate', {expression, awaitPromise, returnByValue: true, userGesture: true});
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || 'browser evaluation failed');
    return result.result?.value;
  }
  close() { this.socket.close(); }
}

function fixturePayload(root) {
  const edgePath = join(root, 'integration', 'edgeproxy-local-behind-waf.json');
  const securityPath = join(root, 'apps', 'securityedge', 'configs', 'local-dev.json');
  const htmlPath = join(root, 'apps', 'securityedge', 'internal', 'admin', 'web', 'index.html');
  const appPath = join(root, 'apps', 'securityedge', 'internal', 'admin', 'web', 'app.js');
  const stylesPath = join(root, 'apps', 'securityedge', 'internal', 'admin', 'web', 'styles.css');
  for (const path of [edgePath, securityPath, htmlPath, appPath, stylesPath]) {
    if (!existsSync(path)) throw new Error(`Fixture file not found: ${path}`);
  }
  const edge = JSON.parse(readFileSync(edgePath, 'utf8'));
  const security = JSON.parse(readFileSync(securityPath, 'utf8'));
  const route = edge.routes?.[0];
  const origin = route?.upstreams?.[0];
  if (!route || !origin) throw new Error('Fixture EdgeProxy config must contain at least one Route and Origin.');

  const latency = {count:20, average:10, minimum:1, maximum:50, p50:8, p95:30, p99:45, distribution:[]};
  const upstream = {calls:20, success:20, failures:0, timeouts:0, retries:0, success_rate:1, error_rate:0, status_codes:{'200':20}, latency_ms:latency};
  const routeMetric = {
    requests:20, success:20, client_errors:0, server_errors:0, proxy_errors:0,
    upstream_calls:20, retries:0, bytes_in:1000, bytes_out:5000,
    cache_hits:5, cache_misses:5, cache_stale:0, cache_bypasses:10, cache_stores:5,
    cache_hit_ratio:0.5, success_rate:1, error_rate:0, status_codes:{'200':20}, methods:{GET:20},
    response_latency_ms:latency, upstream, upstreams:{[origin.url]:upstream}
  };
  const routeRuntime = {
    name:route.name, ready:true, algorithm:route.load_balancing?.algorithm || 'round_robin',
    upstreams:route.upstreams.map(item => ({
      name:item.name, url:item.url, healthy:true, active_requests:0, ewma_latency_ms:8,
      scheduler_selections:20, health_failures:0, health_recoveries:1
    }))
  };
  const now = new Date().toISOString();
  const connectivity = {
    generated_at:now, stale_after_seconds:15, overall_status:'healthy', summary:'All fixture dependencies are healthy.',
    traffic_path_status:'healthy', edgeproxy_connection_status:'healthy', observability_status:'healthy',
    counts:{ready_routes:1,total_routes:1,healthy_origins:1,total_origins:1,components_healthy:4,components_degraded:0,components_down:0},
    components:[
      {id:'securityedge_ingress',name:'SecurityEdge public ingress',layer:'securityedge',status:'healthy',critical:true,endpoint:'http://127.0.0.1:8081',message:'Public gateway listener is reachable.',latency_ms:1,checks:20,successful_checks:20,availability_percent:100},
      {id:'edgeproxy_data_http',name:'EdgeProxy data plane',layer:'edgeproxy',status:'healthy',critical:true,endpoint:'http://127.0.0.1:8080',message:'Configured Route probe is healthy.',latency_ms:2,checks:20,successful_checks:20,availability_percent:100},
      {id:'edgeproxy_admin_health',name:'EdgeProxy Admin API',layer:'observability',status:'healthy',critical:true,endpoint:'http://127.0.0.1:9090',message:'Admin health endpoint is healthy.',latency_ms:2,checks:20,successful_checks:20,availability_percent:100},
      {id:'edgeproxy_metrics',name:'EdgeProxy metrics & cache',layer:'observability',status:'healthy',critical:false,endpoint:'http://127.0.0.1:9090/api/v1/metrics',message:'Metrics endpoint is available.',latency_ms:2,checks:20,successful_checks:20,availability_percent:100}
    ], history:[]
  };
  const overview = {
    generated_at:now, connectivity,
    recent_client_traffic:{status:'no_recent_traffic',requests_in_window:0,unique_clients:0,allowed:0,rejected:0},
    security_metrics:{schema_version:'1',uptime_seconds:60,inflight:0,total:{
      blocked:0,rate_limited:0,client_rate_limited:0,global_rate_limited:0,overload_rejected:0,banned_rejected:0,
      block_rate:0,detections:0,detection_rate:0,latency:{average_ms:1,maximum_ms:2,p50_ms:1,p95_ms:2,p99_ms:2},rules:{},reasons:{}
    }},
    security_logs:{entries:[],retained:0,dropped:0,file_bytes:0,file_errors:0},
    security_status:{rate_limit_buckets:0,active_bans:0,admission:{global_active:0,tracked_clients:0}},
    edgeproxy_status_code:200,
    edgeproxy_status:{routes:[routeRuntime]},
    edgeproxy_metrics:{schema_version:'1',uptime_seconds:60,inflight:0,requests_per_second:1,total:routeMetric,routes:{[route.name]:routeMetric}},
    build:{version:'fixture',commit:'fixture',go_version:'fixture',os:'fixture',arch:'fixture'}
  };
  const policies = {
    default_policy:security.default_policy,
    route_policies:security.route_policies || {},
    effective_policies:Object.fromEntries(edge.routes.map(item => [item.name, security.route_policies?.[item.name] || security.default_policy])),
    routes:edge.routes.map(item => ({name:item.name}))
  };
  const watch = {revision:1,applied_revision:1,restart_scheduled:false,last_source:'fixture',last_changed_file:'fixture'};
  const responses = {
    '/api/v1/session':{},
    '/api/v1/dashboard/overview':overview,
    '/api/v1/policies':policies,
    '/api/v1/rules':{rules:[]},
    '/api/v1/bans':{bans:[]},
    '/api/v1/edgeproxy/config':edge,
    '/api/v1/edgeproxy/config/watch':watch,
    '/api/v1/config':security,
    '/api/v1/config/watch':watch,
    '/api/v1/server':security.server,
    '/api/v1/admin':security.admin,
    '/api/v1/edgeproxy-settings':security.edgeproxy,
    '/api/v1/waf':security.waf,
    '/api/v1/edgeproxy/server':edge.server,
    '/api/v1/edgeproxy/admin':edge.admin,
    [`/api/v1/edgeproxy/routes/${encodeURIComponent(route.name)}/cache`]:route.cache
  };
  let html = readFileSync(htmlPath, 'utf8');
  const styles = readFileSync(stylesPath, 'utf8');
  html = html.replace(/<link\b[^>]*>/gi, '').replace(/<script\b[^>]*src=["'][^"']+["'][^>]*><\/script>/gi, '');
  html = html.replace('</head>', `<style>${styles}</style></head>`);
  return {html, app:readFileSync(appPath, 'utf8'), responses, routeName:route.name};
}

async function stopBrowser(processHandle) {
  if (processHandle.exitCode !== null) return;
  const exited = new Promise(resolvePromise => processHandle.once('exit', resolvePromise));
  processHandle.kill('SIGTERM');
  await Promise.race([exited, sleep(2000)]);
  if (processHandle.exitCode === null) {
    processHandle.kill('SIGKILL');
    await Promise.race([exited, sleep(1000)]);
  }
}

const fixtureRootArg = argument('fixture-root');
const fixtureRoot = fixtureRootArg ? resolve(fixtureRootArg) : '';
const mode = fixtureRoot ? 'fixture' : 'live';
const url = argument('url', process.env.SECURITYEDGE_DASHBOARD_URL || 'http://127.0.0.1:9191');
const token = argument('token', process.env.SECURITYEDGE_ADMIN_TOKEN || (fixtureRoot ? 'fixture-token' : ''));
if (!token) {
  console.error('Provide --token or SECURITYEDGE_ADMIN_TOKEN. Fixture mode supplies a safe default token.');
  process.exit(2);
}
const browser = browserCandidates().find(existsSync);
if (!browser) {
  console.error('Chrome, Edge, or Chromium was not found. Use --browser <path>.');
  process.exit(2);
}

const profile = mkdtempSync(join(tmpdir(), 'securityedge-dashboard-'));
const browserArgs = [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--no-proxy-server',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'
];
if (typeof process.getuid === 'function' && process.getuid() === 0) browserArgs.unshift('--no-sandbox');
const processHandle = spawn(browser, browserArgs, {stdio: ['ignore', 'ignore', 'pipe']});
let browserErrors = '';
processHandle.stderr.on('data', value => { browserErrors += value.toString(); });

let cdp;
const exceptions = [];
try {
  const activePort = join(profile, 'DevToolsActivePort');
  await eventually(() => existsSync(activePort), 'Chromium DevTools endpoint');
  const [port] = readFileSync(activePort, 'utf8').trim().split(/\r?\n/);
  const targetResponse = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent('about:blank')}`, {method: 'PUT'});
  if (!targetResponse.ok) throw new Error(`create browser target: HTTP ${targetResponse.status}`);
  const target = await targetResponse.json();
  cdp = new CDP(target.webSocketDebuggerUrl);
  await cdp.open();

  cdp.on('Runtime.exceptionThrown', event => exceptions.push(event.exceptionDetails?.exception?.description || event.exceptionDetails?.text || 'uncaught exception'));
  cdp.on('Log.entryAdded', event => {
    if (event.entry?.level === 'error') exceptions.push(event.entry.text || 'browser log error');
  });
  await Promise.all([cdp.send('Page.enable'), cdp.send('Runtime.enable'), cdp.send('Log.enable')]);
  if (fixtureRoot) {
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
  }

  let expectedRoute = '';
  if (fixtureRoot) {
    const fixture = fixturePayload(fixtureRoot);
    expectedRoute = fixture.routeName;
    const {frameTree} = await cdp.send('Page.getFrameTree');
    await cdp.send('Page.setDocumentContent', {frameId:frameTree.frame.id, html:fixture.html});
    await eventually(async () => await cdp.evaluate(`document.readyState === 'complete'`), 'Fixture Dashboard document');
    const mockScript = `(() => {
      const payloads = ${JSON.stringify(fixture.responses)};
      window.__fixtureRequests = [];
      window.__fixtureFetchCounts = {};
      window.__fixtureActiveFetches = 0;
      window.__fixtureMaxActiveFetches = 0;
      window.fetch = async (input, init = {}) => {
        const raw = typeof input === 'string' ? input : input.url;
        const parsed = new URL(raw, 'http://fixture.local');
        const key = parsed.pathname;
        const method = String(init.method || 'GET').toUpperCase();
        window.__fixtureFetchCounts[key] = (window.__fixtureFetchCounts[key] || 0) + 1;
        window.__fixtureActiveFetches++;
        window.__fixtureMaxActiveFetches = Math.max(window.__fixtureMaxActiveFetches, window.__fixtureActiveFetches);
        if (key === '/api/v1/dashboard/overview') await new Promise(resolve => setTimeout(resolve, 75));
        let body;
        if (method === 'PUT' || method === 'POST' || method === 'DELETE') {
          let requestBody = null;
          try { requestBody = init.body ? JSON.parse(init.body) : null; } catch {}
          window.__fixtureRequests.push({method, key, body:requestBody});
          body = {applied:true, restart_required:false, watch:{revision:2, applied_revision:2}};
        } else if (key === '/api/v1/edgeproxy/logs' || key === '/api/v1/logs') body = {entries:[],returned:0,retained:0,dropped:0,has_more:false};
        else body = payloads[key];
        window.__fixtureActiveFetches--;
        if (body === undefined) return new Response(JSON.stringify({error:{message:'fixture endpoint not found: ' + key}}), {status:404,headers:{'Content-Type':'application/json'}});
        return new Response(JSON.stringify(body), {status:200,headers:{'Content-Type':'application/json'}});
      };
      window.confirm = () => true;
    })()`;
    await cdp.evaluate(mockScript);
    await cdp.evaluate(`(() => { const script=document.createElement('script'); script.textContent=${JSON.stringify(fixture.app)}; document.body.appendChild(script); })()`);
  } else {
    await cdp.send('Page.navigate', {url});
    await eventually(async () => await cdp.evaluate(`location.href.startsWith(${JSON.stringify(url)}) && document.readyState === 'complete'`), 'Dashboard document');
  }
  await eventually(async () => await cdp.evaluate('typeof login === "function"'), 'Dashboard application script');

  await cdp.evaluate(`login(${JSON.stringify(token)})`, true);
  await eventually(async () => await cdp.evaluate(`!document.getElementById('login').classList.contains('visible') && !!state.edgeConfig`), 'Authenticated Dashboard data');

  let sidebarLayout = null;
  if (fixtureRoot) {
    sidebarLayout = await cdp.evaluate(`(async () => {
      const sidebar = document.querySelector('.sidebar');
      const footer = document.querySelector('.sidebar-foot');
      const before = sidebar.getBoundingClientRect();
      const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
      window.scrollTo(0, Math.min(480, maxScroll));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const after = sidebar.getBoundingClientRect();
      const footerRect = footer.getBoundingClientRect();
      const style = getComputedStyle(sidebar);
      window.scrollTo(0, 0);
      return {
        viewportHeight: window.innerHeight,
        beforeTop: before.top, beforeBottom: before.bottom, beforeHeight: before.height,
        afterTop: after.top, afterBottom: after.bottom, afterHeight: after.height,
        footerBottom: footerRect.bottom, position: style.position, overflowY: style.overflowY
      };
    })()`, true);
    if (Math.abs(sidebarLayout.beforeTop) > 1 || Math.abs(sidebarLayout.beforeBottom - sidebarLayout.viewportHeight) > 1 ||
        Math.abs(sidebarLayout.afterTop) > 1 || Math.abs(sidebarLayout.afterBottom - sidebarLayout.viewportHeight) > 1) {
      throw new Error(`Desktop sidebar does not span the full viewport while scrolling: ${JSON.stringify(sidebarLayout)}`);
    }
    if (sidebarLayout.position !== 'fixed' || !['auto','scroll'].includes(sidebarLayout.overflowY)) {
      throw new Error(`Desktop sidebar rail is not configured as a stable full-height region: ${JSON.stringify(sidebarLayout)}`);
    }
  }

  let overviewTopologyLayout = null;
  if (fixtureRoot) {
    overviewTopologyLayout = await cdp.evaluate(`(() => {
      const topology = document.querySelector('.connectivity-topology');
      if (!topology) return null;
      return {clientWidth:topology.clientWidth, scrollWidth:topology.scrollWidth};
    })()`);
    if (!overviewTopologyLayout || overviewTopologyLayout.scrollWidth > overviewTopologyLayout.clientWidth + 1) {
      throw new Error(`Overview dependency topology should fit without a desktop scrollbar: ${JSON.stringify(overviewTopologyLayout)}`);
    }
  }

  let refreshCoalescing = null;
  if (fixtureRoot) {
    refreshCoalescing = await cdp.evaluate(`(async () => {
      const before = window.__fixtureFetchCounts['/api/v1/dashboard/overview'] || 0;
      await Promise.all([refreshAll(), refreshAll(), refreshAll()]);
      const after = window.__fixtureFetchCounts['/api/v1/dashboard/overview'] || 0;
      return {overviewRequests: after - before, refreshPending: !!state.refreshPromise};
    })()`, true);
    if (refreshCoalescing.overviewRequests !== 2 || refreshCoalescing.refreshPending) {
      throw new Error(`Dashboard refresh coalescing failed: ${JSON.stringify(refreshCoalescing)}`);
    }
  }

  const contract = await cdp.evaluate(`(() => {
    const required = [
      'route-strip-prefix','route-request-timeout','route-cache-enabled','route-health-enabled',
      'cache-config-form','cache-route-select','telemetry-dialog','route-algorithm','route-retry-count',
      'route-cache-statuses','route-health-statuses','system-security-server-form','system-security-admin-form',
      'system-security-edgeproxy-form','system-waf-form','system-edge-server-form','system-edge-admin-form'
    ];
    return {missing: required.filter(id => !document.getElementById(id)), title: document.title};
  })()`);
  if (contract.missing.length) throw new Error(`Dashboard controls missing: ${contract.missing.join(', ')}`);

  await cdp.evaluate(`document.querySelector('[data-view="routes"]').click()`);
  await eventually(async () => await cdp.evaluate(`document.getElementById('view-routes').classList.contains('active')`), 'Routes view');
  const hasRoute = await cdp.evaluate(`!!document.querySelector('[data-route-edit]')`);
  if (!hasRoute) throw new Error('No managed route card was rendered.');
  await cdp.evaluate(`document.querySelector('[data-route-edit]').click()`);
  await eventually(async () => await cdp.evaluate(`document.getElementById('route-dialog').open`), 'Complete Route editor');
  let routeEditorLayout = null;
  if (fixtureRoot) {
    routeEditorLayout = await cdp.evaluate(`(() => {
      const compact = document.getElementById('route-health-enabled').closest('.switch-row.compact').getBoundingClientRect();
      const probe = document.getElementById('route-health-path').getBoundingClientRect();
      const cacheCompact = document.getElementById('route-cache-enabled').closest('.switch-row.compact').getBoundingClientRect();
      const cacheTTL = document.getElementById('route-cache-ttl').getBoundingClientRect();
      const close = document.querySelector('#route-dialog .icon-button');
      const closeStyle = getComputedStyle(close);
      return {
        compactTopDelta: Math.abs(compact.top - probe.top),
        compactBottomDelta: Math.abs(compact.bottom - probe.bottom),
        cacheTopDelta: Math.abs(cacheCompact.top - cacheTTL.top),
        cacheBottomDelta: Math.abs(cacheCompact.bottom - cacheTTL.bottom),
        closeDisplay: closeStyle.display,
        closePlaceItems: closeStyle.placeItems
      };
    })()`);
    if (routeEditorLayout.compactTopDelta > 1 || routeEditorLayout.compactBottomDelta > 1 ||
        routeEditorLayout.cacheTopDelta > 1 || routeEditorLayout.cacheBottomDelta > 1) {
      throw new Error(`Compact Route controls are not aligned with their adjacent inputs: ${JSON.stringify(routeEditorLayout)}`);
    }
    if (routeEditorLayout.closeDisplay !== 'grid' || !routeEditorLayout.closePlaceItems.includes('center')) {
      throw new Error(`Dialog close control is not geometrically centered: ${JSON.stringify(routeEditorLayout)}`);
    }
  }
  const routeEditor = await cdp.evaluate(`({
    name: document.getElementById('route-name').value,
    algorithm: document.getElementById('route-algorithm').value,
    ttl: document.getElementById('route-cache-ttl').value,
    health: document.getElementById('route-health-interval').value
  })`);
  if (!routeEditor.name || !routeEditor.algorithm || !routeEditor.ttl || !routeEditor.health) {
    throw new Error(`Route editor was not populated: ${JSON.stringify(routeEditor)}`);
  }
  if (expectedRoute && routeEditor.name !== expectedRoute) throw new Error(`Unexpected fixture Route: ${routeEditor.name}`);
  await cdp.evaluate(`document.getElementById('route-dialog').close()`);

  let rawConfigLayout = null;
  if (fixtureRoot) {
    rawConfigLayout = await cdp.evaluate(`(() => {
      const panel = document.querySelector('.config-editor-grid .panel');
      const actions = panel?.querySelector('.panel-head .top-actions');
      if (!panel || !actions) return null;
      const panelRect = panel.getBoundingClientRect();
      const actionsRect = actions.getBoundingClientRect();
      const paddingRight = parseFloat(getComputedStyle(panel).paddingRight) || 0;
      return {rightDelta: Math.abs((panelRect.right - paddingRight) - actionsRect.right)};
    })()`);
    if (!rawConfigLayout || rawConfigLayout.rightDelta > 1) {
      throw new Error(`Raw configuration actions are not anchored to the card's right content edge: ${JSON.stringify(rawConfigLayout)}`);
    }
  }

  let responsiveLayouts = [];
  let mobileDialogLayouts = [];
  if (fixtureRoot) {
    for (const width of [680, 390]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:false});
      await sleep(100);
      await cdp.evaluate(`document.querySelector('[data-route-edit]').click()`);
      await eventually(async () => await cdp.evaluate(`document.getElementById('route-dialog').open`), `Route dialog at ${width}px`);
      const layout = await cdp.evaluate(`(() => {
        const root = document.documentElement;
        const wraps = [...document.querySelectorAll('#view-routes .table-wrap')];
        const scrollableTables = wraps.filter(node => node.scrollWidth > node.clientWidth + 1).length;
        const originActions = document.querySelector('.origin-actions');
        const tableAction = document.querySelector('.table-actions-cell');
        const dialog = document.getElementById('route-dialog').getBoundingClientRect();
        return {
          horizontalScrollbarPx: window.innerHeight - root.clientHeight,
          pageOverflowX: getComputedStyle(root).overflowX,
          bodyOverflowX: getComputedStyle(document.body).overflowX,
          scrollableTables,
          originActionGap: originActions ? getComputedStyle(originActions).gap : '',
          tableActionAlign: tableAction ? getComputedStyle(tableAction).textAlign : '',
          dialogLeft: dialog.left,
          dialogRight: dialog.right,
          dialogWidth: dialog.width,
          viewportWidth: root.clientWidth
        };
      })()`);
      await cdp.evaluate(`document.getElementById('route-dialog').close()`);
      layout.width = width;
      responsiveLayouts.push(layout);
      if (layout.horizontalScrollbarPx > 1 || layout.pageOverflowX !== 'hidden' || layout.bodyOverflowX !== 'hidden') {
        throw new Error(`Dashboard exposes a page-level horizontal scrollbar at ${width}px: ${JSON.stringify(layout)}`);
      }
      if (layout.dialogLeft < -1 || layout.dialogRight > layout.viewportWidth + 1) {
        throw new Error(`Route dialog escapes the viewport at ${width}px: ${JSON.stringify(layout)}`);
      }
      if (layout.scrollableTables < 1) {
        throw new Error(`Responsive telemetry tables lost their internal horizontal scrolling at ${width}px: ${JSON.stringify(layout)}`);
      }
      if (layout.originActionGap !== '8px' || layout.tableActionAlign !== 'right') {
        throw new Error(`Responsive action alignment contract failed at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    for (const width of [680, 390]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:true});
      await sleep(100);
      await cdp.evaluate(`document.querySelector('[data-route-edit]').click()`);
      await eventually(async () => await cdp.evaluate(`document.getElementById('route-dialog').open`), `Mobile Route dialog at ${width}px`);
      const mobileLayout = await cdp.evaluate(`(() => {
        const root = document.documentElement;
        const dialogNode = document.getElementById('route-dialog');
        const dialog = dialogNode.getBoundingClientRect();
        const form = dialogNode.querySelector('.editor-form');
        return {dialogLeft:dialog.left, dialogRight:dialog.right, dialogWidth:dialog.width, viewportWidth:root.clientWidth,
          dialogClientWidth:dialogNode.clientWidth, dialogScrollWidth:dialogNode.scrollWidth,
          formClientWidth:form.clientWidth, formScrollWidth:form.scrollWidth};
      })()`);
      mobileLayout.width = width;
      mobileDialogLayouts.push(mobileLayout);
      await cdp.evaluate(`document.getElementById('route-dialog').close()`);
      if (mobileLayout.dialogLeft < -1 || mobileLayout.dialogRight > mobileLayout.viewportWidth + 1) {
        throw new Error(`Mobile Route dialog escapes the viewport at ${width}px: ${JSON.stringify(mobileLayout)}`);
      }
      if (mobileLayout.dialogScrollWidth > mobileLayout.dialogClientWidth + 1 ||
          mobileLayout.formScrollWidth > mobileLayout.formClientWidth + 1) {
        throw new Error(`Mobile Route dialog leaks horizontal overflow internally at ${width}px: ${JSON.stringify(mobileLayout)}`);
      }
    }
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(100);
  }

  await cdp.evaluate(`document.querySelector('[data-view="traffic"]').click()`);
  await eventually(async () => await cdp.evaluate(`document.getElementById('view-traffic').classList.contains('active')`), 'Traffic and cache view');
  const cacheOptions = await cdp.evaluate(`document.getElementById('cache-route-select').options.length`);
  if (cacheOptions < 1) throw new Error('Per-route cache editor has no Route options.');

  await cdp.evaluate(`document.querySelector('[data-view="system"]').click()`);
  await eventually(async () => await cdp.evaluate(`document.getElementById('view-system').classList.contains('active')`), 'System view');
  const systemForms = await cdp.evaluate(`(() => ({
    securityListen: document.querySelector('#system-security-server-form [name="listen_addr"]').value,
    securityAdmin: document.querySelector('#system-security-admin-form [name="listen_addr"]').value,
    edgeAdminURL: document.querySelector('#system-security-edgeproxy-form [name="admin_url"]').value,
    wafMaximum: document.querySelector('#system-waf-form [name="maximum_matches_per_request"]').value,
    edgeListen: document.querySelector('#system-edge-server-form [name="listen_addr"]').value,
    edgeAdmin: document.querySelector('#system-edge-admin-form [name="listen_addr"]').value
  }))()`);
  if (Object.values(systemForms).some(value => !String(value).trim())) {
    throw new Error(`Structured System forms were not populated: ${JSON.stringify(systemForms)}`);
  }
  let systemHeaderLayout = null;
  if (fixtureRoot) {
    systemHeaderLayout = await cdp.evaluate(`(() => {
      const head = document.querySelector('.system-control-intro .panel-head').getBoundingClientRect();
      const button = document.getElementById('reload-config').getBoundingClientRect();
      return {centerDelta:Math.abs((head.top + head.height / 2) - (button.top + button.height / 2))};
    })()`);
    if (systemHeaderLayout.centerDelta > 1) {
      throw new Error(`Reload configuration action is not vertically centered: ${JSON.stringify(systemHeaderLayout)}`);
    }
  }
  let systemFormSubmission = false;
  if (fixtureRoot) {
    await cdp.evaluate(`(() => {
      const field = document.querySelector('#system-waf-form [name="maximum_matches_per_request"]');
      field.value = '48';
      field.dispatchEvent(new Event('input', {bubbles:true}));
      document.getElementById('system-waf-form').requestSubmit();
    })()`);
    await eventually(async () => await cdp.evaluate(`window.__fixtureRequests.some(request => request.method === 'PUT' && request.key === '/api/v1/waf' && request.body?.maximum_matches_per_request === 48)`), 'Structured WAF form submission');
    systemFormSubmission = true;
  }
  await sleep(500);
  if (exceptions.length) throw new Error(`Browser console/runtime errors: ${exceptions.join(' | ')}`);

  console.log(JSON.stringify({
    ok:true, mode, browser, url:fixtureRoot ? 'fixture://dashboard' : url,
    title:contract.title, route:routeEditor.name, algorithm:routeEditor.algorithm,
    cache_route_options:cacheOptions, system_forms_populated:true, system_form_submission:systemFormSubmission, live_mutations_skipped:!fixtureRoot,
    refresh_coalescing:refreshCoalescing, responsive_layouts:responsiveLayouts, mobile_dialog_layouts:mobileDialogLayouts,
    route_editor_layout:routeEditorLayout, raw_config_layout:rawConfigLayout, system_header_layout:systemHeaderLayout,
    sidebar_layout:sidebarLayout, overview_topology_layout:overviewTopologyLayout
  }, null, 2));
} catch (error) {
  console.error(error.stack || error.message);
  if (exceptions.length) console.error(`Captured browser errors: ${exceptions.join(' | ')}`);
  if (browserErrors.trim()) console.error(browserErrors.trim().split(/\r?\n/).slice(-10).join('\n'));
  process.exitCode = 1;
} finally {
  try { cdp?.close(); } catch {}
  await stopBrowser(processHandle);
  for (let attempt = 0; attempt < 5; attempt++) {
    try { rmSync(profile, {recursive:true, force:true}); break; }
    catch { await sleep(100); }
  }
}
