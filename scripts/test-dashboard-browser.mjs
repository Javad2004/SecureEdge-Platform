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
  const themePath = join(root, 'apps', 'securityedge', 'internal', 'admin', 'web', 'theme.js');
  const stylesPath = join(root, 'apps', 'securityedge', 'internal', 'admin', 'web', 'styles.css');
  for (const path of [edgePath, securityPath, htmlPath, appPath, themePath, stylesPath]) {
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
    security_metrics:{schema_version:'2.0',uptime_seconds:60,inflight:0,requests_per_second:20/60,total:{
      requests:20,allowed:20,blocked:0,logged:0,rate_limited:0,client_rate_limited:0,global_rate_limited:0,overload_rejected:0,banned_rejected:0,
      block_rate:0,detections:0,detection_rate:0,latency:{average_ms:1,maximum_ms:2,p50_ms:1,p95_ms:2,p99_ms:2},rules:{},reasons:{}
    }},
    security_logs:{entries:[],retained:0,dropped:0,file_bytes:0,file_errors:0},
    security_status:{rate_limit_buckets:0,active_bans:0,admission:{global_active:0,tracked_clients:0}},
    edgeproxy_status_code:200, edgeproxy_metrics_status_code:200,
    edgeproxy_status:{routes:[routeRuntime]},
    edgeproxy_metrics:{schema_version:'2.0',uptime_seconds:60,inflight:0,requests_per_second:20/60,total:routeMetric,routes:{[route.name]:routeMetric}},
    build:{version:'fixture',commit:'fixture',go_version:'fixture',os:'fixture',arch:'fixture'}
  };
  const policies = {
    default_policy:security.default_policy,
    route_policies:security.route_policies || {},
    effective_policies:Object.fromEntries(edge.routes.map(item => [item.name, security.route_policies?.[item.name] || security.default_policy])),
    routes:edge.routes.map(item => ({name:item.name}))
  };
  const watch = {revision:1,applied_revision:1,restart_scheduled:false,last_source:'fixture',last_changed_file:'fixture'};
  const originTelemetryMetrics = {
    ...upstream,
    calls:999,
    success:321,
    failures:678,
    success_rate:321 / 999,
    error_rate:678 / 999,
    status_codes:{'502':678,'200':321}
  };
  const responses = {
    '/api/v1/session':{},
    '/api/v1/dashboard/overview':overview,
    '/api/v1/policies':policies,
    '/api/v1/rules':{rules:[]},
    '/api/v1/bans':{bans:[]},
    '/api/v1/edgeproxy/config':edge,
    '/api/v1/edgeproxy/config/watch':watch,
    [`/api/v1/edgeproxy/routes/${encodeURIComponent(route.name)}/telemetry`]:{route,runtime:routeRuntime,metrics:routeMetric},
    [`/api/v1/edgeproxy/routes/${encodeURIComponent(route.name)}/origins/${encodeURIComponent(origin.name)}/telemetry`]:{route,origin,runtime:routeRuntime.upstreams[0],metrics:originTelemetryMetrics},
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
  return {html, app:readFileSync(appPath, 'utf8'), theme:readFileSync(themePath, 'utf8'), responses, routeName:route.name};
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
    await cdp.send('Emulation.setEmulatedMedia', {features:[{name:'prefers-color-scheme',value:'light'}]});
  }

  let expectedRoute = '';
  if (fixtureRoot) {
    const fixture = fixturePayload(fixtureRoot);
    expectedRoute = fixture.routeName;
    const {frameTree} = await cdp.send('Page.getFrameTree');
    await cdp.send('Page.setDocumentContent', {frameId:frameTree.frame.id, html:fixture.html});
    await eventually(async () => await cdp.evaluate(`document.readyState === 'complete'`), 'Fixture Dashboard document');
    await cdp.evaluate(`(() => {
      const values = new Map();
      Object.defineProperty(window, 'localStorage', {configurable:true, value:{
        getItem:key => values.has(String(key)) ? values.get(String(key)) : null,
        setItem:(key,value) => values.set(String(key), String(value)),
        removeItem:key => values.delete(String(key)),
        clear:() => values.clear()
      }});
    })()`);
    await cdp.evaluate(`(() => { window.__fixtureThemeSource=${JSON.stringify(fixture.theme)}; const script=document.createElement('script'); script.textContent=window.__fixtureThemeSource; document.head.appendChild(script); })()`);
    await eventually(async () => await cdp.evaluate(`!!window.SecurityEdgeTheme`), 'Fixture Dashboard theme bootstrap');
    const mockScript = `(() => {
      const payloads = ${JSON.stringify(fixture.responses)};
      window.__fixtureRequests = [];
      window.__fixtureFetchCounts = {};
      window.__fixtureIntervals = [];
      const fixtureSetInterval = window.setInterval.bind(window);
      window.setInterval = (handler, timeout, ...args) => {
        const id = fixtureSetInterval(handler, timeout, ...args);
        window.__fixtureIntervals.push(id);
        return id;
      };
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

  let authenticationUIContract = null;
  if (fixtureRoot) {
    await eventually(async () => await cdp.evaluate(`document.activeElement?.id === 'token'`), 'Locked Dashboard login focus');
    authenticationUIContract = await cdp.evaluate(`(async () => {
      const shell = document.getElementById('app-shell');
      const loginPanel = document.getElementById('login');
      const tokenInput = document.getElementById('token');
      const activeNav = document.querySelector('.nav-item.active');
      const originalFetch = window.fetch;
      const frame = () => new Promise(resolve => requestAnimationFrame(() => resolve()));
      const snapshot = () => ({
        shellInert:Boolean(shell?.inert),
        loginVisible:Boolean(loginPanel?.classList.contains('visible')),
        activeElement:document.activeElement?.id || document.activeElement?.className || document.activeElement?.tagName || '',
        stateToken:state.token,
        storedToken:sessionGet('securityedge_token'),
        inputValue:tokenInput?.value || ''
      });

      const initial = snapshot();
      activeNav?.focus();
      const backgroundFocusBlocked = document.activeElement !== activeNav;

      tokenInput.value = 'temporary-lock-secret';
      state.token = 'temporary-lock-secret';
      sessionSet('securityedge_token', state.token);
      lock();
      await frame();
      const explicitLock = snapshot();

      let failedLoginError = '';
      tokenInput.value = 'blocked-login-secret';
      window.fetch = async () => new Response(JSON.stringify({error:{message:'locked'}}), {status:429,headers:{'Content-Type':'application/json'}});
      try { await login(tokenInput.value); } catch (error) { failedLoginError = error.message; }
      await frame();
      const failedLogin = snapshot();

      let expiredDownloadError = '';
      tokenInput.value = 'download-secret';
      state.token = 'download-secret';
      sessionSet('securityedge_token', state.token);
      window.fetch = async () => new Response(JSON.stringify({error:{message:'expired'}}), {status:401,headers:{'Content-Type':'application/json'}});
      try { await download('/api/v1/logs/export?format=csv', 'fixture.csv'); } catch (error) { expiredDownloadError = error.message; }
      await frame();
      const expiredDownload = snapshot();

      state.token = 'refresh-expired-secret';
      sessionSet('securityedge_token', state.token);
      setConsoleLocked(false);
      document.getElementById('live-dot').className = 'dot live';
      document.getElementById('connection-label').textContent = 'System healthy';
      window.fetch = async () => new Response(JSON.stringify({error:{message:'expired'}}), {status:401,headers:{'Content-Type':'application/json'}});
      await refreshAll();
      await frame();
      const expiredRefresh = {
        ...snapshot(),
        connectionLabel:document.getElementById('connection-label').textContent,
        liveClasses:[...document.getElementById('live-dot').classList]
      };
      window.fetch = originalFetch;

      const dialogsNamed = [...document.querySelectorAll('dialog')].every(dialog => {
        const labelledBy = dialog.getAttribute('aria-labelledby');
        return Boolean(labelledBy && document.getElementById(labelledBy));
      });
      return {initial, backgroundFocusBlocked, explicitLock, failedLogin, failedLoginError, expiredDownload, expiredDownloadError, expiredRefresh, dialogsNamed};
    })()`, true);
    if (!authenticationUIContract.initial.shellInert || !authenticationUIContract.initial.loginVisible ||
        authenticationUIContract.initial.activeElement !== 'token' || !authenticationUIContract.backgroundFocusBlocked) {
      throw new Error(`Locked Dashboard does not isolate and focus the authentication modal: ${JSON.stringify(authenticationUIContract)}`);
    }
    if (!authenticationUIContract.explicitLock.shellInert || !authenticationUIContract.explicitLock.loginVisible ||
        authenticationUIContract.explicitLock.stateToken || authenticationUIContract.explicitLock.storedToken ||
        authenticationUIContract.explicitLock.inputValue || authenticationUIContract.explicitLock.activeElement !== 'token') {
      throw new Error(`Explicit console lock does not clear credentials and restore modal focus: ${JSON.stringify(authenticationUIContract)}`);
    }
    if (!authenticationUIContract.failedLogin.shellInert || authenticationUIContract.failedLogin.stateToken ||
        authenticationUIContract.failedLogin.storedToken || authenticationUIContract.failedLogin.inputValue ||
        authenticationUIContract.failedLoginError !== 'Admin authentication is temporarily locked.') {
      throw new Error(`Failed login leaves authenticated state behind: ${JSON.stringify(authenticationUIContract)}`);
    }
    if (!authenticationUIContract.expiredDownload.shellInert || authenticationUIContract.expiredDownload.stateToken ||
        authenticationUIContract.expiredDownload.storedToken || authenticationUIContract.expiredDownload.inputValue ||
        authenticationUIContract.expiredDownloadError !== 'Invalid or expired admin token.') {
      throw new Error(`Expired export authentication does not lock and clear the console: ${JSON.stringify(authenticationUIContract)}`);
    }
    if (!authenticationUIContract.expiredRefresh.shellInert || authenticationUIContract.expiredRefresh.stateToken ||
        authenticationUIContract.expiredRefresh.storedToken || authenticationUIContract.expiredRefresh.inputValue ||
        authenticationUIContract.expiredRefresh.connectionLabel !== 'Console locked' ||
        authenticationUIContract.expiredRefresh.liveClasses.some(name => ['live','degraded','down'].includes(name))) {
      throw new Error(`Expired periodic refresh misreports authentication loss as an operations outage: ${JSON.stringify(authenticationUIContract)}`);
    }
    if (!authenticationUIContract.dialogsNamed) {
      throw new Error(`Editor dialogs must expose accessible names: ${JSON.stringify(authenticationUIContract)}`);
    }
  }

  let themeContract = null;
  if (fixtureRoot) {
    themeContract = await cdp.evaluate(`(async () => {
      const root = document.documentElement;
      const variable = name => getComputedStyle(root).getPropertyValue(name).trim();
      const parse = value => {
        const match = String(value).match(/^#([0-9a-f]{6})$/i);
        if (!match) return null;
        const hex = match[1];
        return [0,2,4].map(index => parseInt(hex.slice(index,index+2),16) / 255);
      };
      const luminance = value => {
        const rgb = parse(value);
        if (!rgb) return 0;
        const linear = rgb.map(channel => channel <= .04045 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4));
        return .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
      };
      const contrast = (foreground, background) => {
        const first = luminance(foreground), second = luminance(background);
        return (Math.max(first, second) + .05) / (Math.min(first, second) + .05);
      };
      const snapshot = () => ({
        theme:root.dataset.theme,
        text:variable('--text'), panel:variable('--panel'), muted:variable('--muted'),
        accent:variable('--accent'), danger:variable('--danger'), warn:variable('--warn'),
        themeColor:document.querySelector('meta[name="theme-color"]')?.content || '',
        textContrast:contrast(variable('--text'), variable('--panel')),
        mutedContrast:contrast(variable('--muted'), variable('--panel')),
        accentContrast:contrast(variable('--accent'), variable('--panel')),
        dangerContrast:contrast(variable('--danger'), variable('--panel')),
        warnContrast:contrast(variable('--warn'), variable('--panel'))
      });
      const initial = snapshot();
      const loginToggle = document.querySelector('#login [data-theme-toggle]');
      const initialLabel = loginToggle?.getAttribute('aria-label') || '';
      loginToggle?.click();
      const toggled = snapshot();
      let persisted = '';
      try { persisted = localStorage.getItem(window.SecurityEdgeTheme.storageKey) || ''; } catch {}

      // Exercise a fresh document bootstrap with a saved user preference while
      // the emulated operating-system preference remains light. This verifies
      // that persistence is read on initialization rather than merely written.
      const frame = document.createElement('iframe');
      frame.hidden = true;
      document.body.appendChild(frame);
      await new Promise(resolve => requestAnimationFrame(resolve));
      const frameValues = new Map([[window.SecurityEdgeTheme.storageKey, persisted]]);
      Object.defineProperty(frame.contentWindow, 'localStorage', {configurable:true, value:{
        getItem:key => frameValues.has(String(key)) ? frameValues.get(String(key)) : null,
        setItem:(key,value) => frameValues.set(String(key), String(value)),
        removeItem:key => frameValues.delete(String(key)),
        clear:() => frameValues.clear()
      }});
      Object.defineProperty(frame.contentWindow, 'matchMedia', {configurable:true, value:() => ({
        matches:false,
        addEventListener:() => {},
        removeEventListener:() => {},
        addListener:() => {},
        removeListener:() => {}
      })});
      const freshScript = frame.contentDocument.createElement('script');
      freshScript.textContent = window.__fixtureThemeSource;
      frame.contentDocument.head.appendChild(freshScript);
      const freshPersistedTheme = frame.contentDocument.documentElement.dataset.theme || '';
      frame.remove();

      loginToggle?.click();
      const restored = snapshot();

      // A storage event represents a same-origin tab changing the preference.
      window.dispatchEvent(new StorageEvent('storage', {key:window.SecurityEdgeTheme.storageKey, newValue:'dark'}));
      const storageSynced = snapshot();
      try { localStorage.removeItem(window.SecurityEdgeTheme.storageKey); } catch {}
      window.dispatchEvent(new StorageEvent('storage', {key:window.SecurityEdgeTheme.storageKey, newValue:null}));
      const storageCleared = snapshot();

      const topToggle = document.querySelector('.topbar [data-theme-toggle]');
      return {
        initial, toggled, restored, storageSynced, storageCleared,
        freshPersistedTheme, persisted, initialLabel,
        loginToggleVisible:Boolean(loginToggle && loginToggle.getBoundingClientRect().width > 0),
        topTogglePresent:Boolean(topToggle),
        synchronizedLabel:topToggle?.getAttribute('aria-label') || ''
      };
    })()`, true);
    if (themeContract.initial.theme !== 'light' || themeContract.toggled.theme !== 'dark' || themeContract.restored.theme !== 'light' ||
        themeContract.freshPersistedTheme !== 'dark' || themeContract.storageSynced.theme !== 'dark' || themeContract.storageCleared.theme !== 'light') {
      throw new Error(`System-default, persistence, storage-sync, or toggle theme behavior failed: ${JSON.stringify(themeContract)}`);
    }
    for (const palette of [themeContract.initial, themeContract.toggled]) {
      if (palette.textContrast < 7 || palette.mutedContrast < 4.5 || palette.accentContrast < 4.5 ||
          palette.dangerContrast < 4.5 || palette.warnContrast < 4.5) {
        throw new Error(`Theme palette contrast contract failed: ${JSON.stringify(palette)}`);
      }
    }
    if (themeContract.initial.themeColor.toLowerCase() !== '#f2f6fb' || themeContract.toggled.themeColor.toLowerCase() !== '#0b1020') {
      throw new Error(`Browser theme-color metadata does not match the active palette: ${JSON.stringify(themeContract)}`);
    }
    if (!themeContract.loginToggleVisible || !themeContract.topTogglePresent || !themeContract.initialLabel.includes('dark') ||
        !themeContract.synchronizedLabel.includes('dark')) {
      throw new Error(`Theme toggle accessibility/synchronization contract failed: ${JSON.stringify(themeContract)}`);
    }
    if (themeContract.persisted !== 'dark') {
      throw new Error(`Theme preference was not persisted through localStorage: ${JSON.stringify(themeContract)}`);
    }
  }

  let loginBrandLayout = null;
  if (fixtureRoot) {
    loginBrandLayout = await cdp.evaluate(`(() => {
      const card = document.querySelector('#login .login-card');
      const lockup = document.querySelector('#login .login-brand');
      const mark = lockup?.querySelector('.brand-mark');
      const shield = mark?.querySelector('svg.brand-shield');
      const title = document.getElementById('login-title');
      if (!card || !lockup || !mark || !shield || !title) return null;
      const cardRect = card.getBoundingClientRect();
      const lockupRect = lockup.getBoundingClientRect();
      const markRect = mark.getBoundingClientRect();
      const titleRect = title.getBoundingClientRect();
      return {
        hasShield:true,
        markText:mark.textContent.trim(),
        centerDelta:Math.abs((markRect.top + markRect.height / 2) - (titleRect.top + titleRect.height / 2)),
        lockupCenterDelta:Math.abs((lockupRect.left + lockupRect.width / 2) - (cardRect.left + cardRect.width / 2)),
        titleHeight:titleRect.height,
        titleWhiteSpace:getComputedStyle(title).whiteSpace,
        markWidth:markRect.width,
        markHeight:markRect.height,
        leftOverflow:Math.max(0, lockupRect.left - markRect.left),
        rightOverflow:Math.max(0, titleRect.right - lockupRect.right)
      };
    })()`);
    if (!loginBrandLayout || !loginBrandLayout.hasShield || loginBrandLayout.markText !== '' ||
        loginBrandLayout.centerDelta > 1.5 || loginBrandLayout.lockupCenterDelta > 1.5 ||
        loginBrandLayout.titleHeight > 42 || loginBrandLayout.titleWhiteSpace !== 'nowrap' ||
        loginBrandLayout.leftOverflow > 1 || loginBrandLayout.rightOverflow > 1) {
      throw new Error(`Login brand lockup is not centered, shield-only, and single-line on desktop: ${JSON.stringify(loginBrandLayout)}`);
    }
  }

  await cdp.evaluate(`login(${JSON.stringify(token)})`, true);
  await eventually(async () => await cdp.evaluate(`!document.getElementById('login').classList.contains('visible') && !!state.edgeConfig`), 'Authenticated Dashboard data');
  if (fixtureRoot) {
    const authenticatedUI = await cdp.evaluate(`(() => ({
      shellInert:document.getElementById('app-shell').inert,
      loginVisible:document.getElementById('login').classList.contains('visible'),
      inputValue:document.getElementById('token').value,
      activeIsNav:document.activeElement?.classList?.contains('nav-item') || false
    }))()`);
    if (authenticatedUI.shellInert || authenticatedUI.loginVisible || authenticatedUI.inputValue) {
      throw new Error(`Authenticated Dashboard did not release modal isolation or clear the credential input: ${JSON.stringify(authenticatedUI)}`);
    }
    authenticationUIContract.authenticated = authenticatedUI;
  }

  let telemetryAvailabilityContract = null;
  if (fixtureRoot) {
    telemetryAvailabilityContract = await cdp.evaluate(`(() => {
      const previous = state.overview;
      const overviewKpis = () => ({
        requests:document.getElementById('kpi-requests').textContent,
        rps:document.getElementById('kpi-rps').textContent,
        cache:document.getElementById('kpi-cache').textContent,
        cacheCounts:document.getElementById('kpi-cache-counts').textContent,
        upstream:document.getElementById('kpi-upstream').textContent,
        origins:document.getElementById('kpi-origins').textContent,
        routes:document.getElementById('kpi-routes').textContent
      });
      const unavailable = structuredClone(previous);
      unavailable.edgeproxy_metrics = null;
      unavailable.edgeproxy_status = null;
      unavailable.edgeproxy_status_code = 0;
      unavailable.edgeproxy_metrics_status_code = 0;
      unavailable.connectivity = {...unavailable.connectivity, edgeproxy_connection_status:'down'};
      state.overview = unavailable;
      renderOverview();
      renderRoutes();
      renderSystem();
      const metricValue = (id, label) => {
        const row = [...document.querySelectorAll('#' + id + ' .metric-row')].find(item => item.querySelector('span')?.textContent === label);
        return row?.querySelector('strong')?.textContent || '';
      };
      const snapshot = {
        ...overviewKpis(),
        routeState:document.querySelector('#route-cards .route-head .badge')?.textContent || '',
        originState:document.querySelector('#route-cards .origin-badges .badge')?.textContent || '',
        routeSummary:document.querySelector('#route-cards .scheduler-banner small')?.textContent || '',
        routeTelemetry:document.getElementById('route-telemetry-table').textContent,
        originTelemetry:document.getElementById('origin-telemetry-table').textContent,
        edgeUptime:metricValue('edge-system','Uptime'),
        edgeInflight:metricValue('edge-system','In flight'),
        edgeReadyRoutes:metricValue('edge-system','Ready routes')
      };

      const metricsOnly = structuredClone(previous);
      metricsOnly.edgeproxy_status = null;
      metricsOnly.edgeproxy_status_code = 0;
      metricsOnly.connectivity = {...metricsOnly.connectivity, edgeproxy_connection_status:'down'};
      state.overview = metricsOnly;
      renderOverview();
      const metricsOnlyKpis = overviewKpis();

      const statusOnly = structuredClone(previous);
      statusOnly.edgeproxy_metrics = null;
      statusOnly.edgeproxy_metrics_status_code = 0;
      statusOnly.connectivity = {...statusOnly.connectivity, edgeproxy_connection_status:'down'};
      state.overview = statusOnly;
      renderOverview();
      const statusOnlyKpis = overviewKpis();

      state.overview = previous;
      renderAll();
      return {unavailable:snapshot, metricsOnly:metricsOnlyKpis, statusOnly:statusOnlyKpis};
    })()`);
    const unavailable = telemetryAvailabilityContract.unavailable;
    if (unavailable.requests !== '—' || unavailable.rps !== 'EdgeProxy metrics unavailable' ||
        unavailable.cache !== '—' || unavailable.cacheCounts !== 'No cache telemetry' ||
        unavailable.upstream !== 'EdgeProxy metrics unavailable' || unavailable.origins !== '—' ||
        unavailable.routes !== 'EdgeProxy status unavailable' || unavailable.routeState !== 'UNKNOWN' ||
        unavailable.originState !== 'unknown' || unavailable.routeSummary !== 'Telemetry unavailable' ||
        !unavailable.routeTelemetry.includes('EdgeProxy telemetry unavailable.') ||
        !unavailable.originTelemetry.includes('EdgeProxy telemetry unavailable.') ||
        !unavailable.originTelemetry.includes('Runtime health unavailable.') ||
        unavailable.edgeUptime !== '—' || unavailable.edgeInflight !== '—' ||
        unavailable.edgeReadyRoutes !== '—') {
      throw new Error(`Unavailable EdgeProxy telemetry is rendered as real zero-valued or unhealthy data: ${JSON.stringify(telemetryAvailabilityContract)}`);
    }
    const metricsOnly = telemetryAvailabilityContract.metricsOnly;
    if (metricsOnly.requests === '—' || metricsOnly.rps === 'EdgeProxy metrics unavailable' || metricsOnly.cache === '—' ||
        metricsOnly.upstream === 'EdgeProxy metrics unavailable' || metricsOnly.origins !== '—' || metricsOnly.routes !== 'EdgeProxy status unavailable') {
      throw new Error(`Independent EdgeProxy metrics availability is coupled incorrectly to runtime status/connectivity: ${JSON.stringify(telemetryAvailabilityContract)}`);
    }
    const statusOnly = telemetryAvailabilityContract.statusOnly;
    if (statusOnly.requests !== '—' || statusOnly.rps !== 'EdgeProxy metrics unavailable' || statusOnly.cache !== '—' ||
        statusOnly.upstream !== 'EdgeProxy metrics unavailable' || statusOnly.origins !== '1/1' || statusOnly.routes !== '1/1 routes ready') {
      throw new Error(`Independent EdgeProxy runtime status availability is coupled incorrectly to metrics availability: ${JSON.stringify(telemetryAvailabilityContract)}`);
    }
  }

  let clientFacingErrorContract = null;
  if (fixtureRoot) {
    clientFacingErrorContract = await cdp.evaluate(`(() => {
      const previous = state.overview;
      const candidate = structuredClone(previous);
      const routeName = Object.keys(candidate.edgeproxy_metrics?.routes || {})[0];
      if (!routeName) return {routeName:'', text:''};
      const metric = candidate.edgeproxy_metrics.routes[routeName];
      metric.client_errors = 1;
      metric.server_errors = 2;
      metric.proxy_errors = 2;
      state.overview = candidate;
      renderRoutes();
      const text = document.getElementById('route-telemetry-table').textContent;
      state.overview = previous;
      renderAll();
      return {routeName, text};
    })()`);
    if (!clientFacingErrorContract.routeName ||
        !clientFacingErrorContract.text.includes('3 client-facing errors') ||
        clientFacingErrorContract.text.includes('5 client-facing errors')) {
      throw new Error(`Dashboard double-counted proxy-error causes as additional client-facing requests: ${JSON.stringify(clientFacingErrorContract)}`);
    }
  }

  let clientCanceledRequestContract = null;
  if (fixtureRoot) {
    clientCanceledRequestContract = await cdp.evaluate(`(() => {
      const previous = state.overview;
      const candidate = structuredClone(previous);
      const routeName = Object.keys(candidate.edgeproxy_metrics?.routes || {})[0];
      if (!routeName) return {routeName:'', text:''};
      const metric = candidate.edgeproxy_metrics.routes[routeName];
      metric.requests = 1;
      metric.canceled_requests = 1;
      metric.success = 0;
      metric.client_errors = 0;
      metric.server_errors = 0;
      metric.proxy_errors = 0;
      metric.success_rate = 0.75;
      metric.error_rate = 0.25;
      metric.response_latency_ms = {count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]};
      state.overview = candidate;
      renderRoutes();
      const text = document.getElementById('route-telemetry-table').textContent.replace(/\\s+/g,' ').trim();
      state.overview = previous;
      renderAll();
      return {routeName, text};
    })()`);
    if (!clientCanceledRequestContract.routeName ||
        !clientCanceledRequestContract.text.includes('1 canceled · no completed responses') ||
        !clientCanceledRequestContract.text.includes('— / —') ||
        clientCanceledRequestContract.text.includes('75.0%') ||
        clientCanceledRequestContract.text.includes('25.0%') ||
        clientCanceledRequestContract.text.includes('99.00 ms')) {
      throw new Error(`Client-canceled requests polluted completed-outcome telemetry rendering: ${JSON.stringify(clientCanceledRequestContract)}`);
    }
  }

  let telemetryTrendGapContract = null;
  if (fixtureRoot) {
    telemetryTrendGapContract = await cdp.evaluate(`(() => {
      const previous = state.overview;
      const baseTime = Date.now() - 40000;
      const sample = (offset, available, rateAvailable, rate, rejectedRateAvailable, rejectedRate) => ({
        generated_at:new Date(baseTime + offset).toISOString(),
        security:{rejected_rate_available:rejectedRateAvailable, rejected_per_second:rejectedRate},
        edgeproxy:{available, request_rate_available:rateAvailable, requests_per_second:rate}
      });
      const candidate = structuredClone(previous);
      candidate.telemetry_history = {samples:[
        sample(0,true,true,1.5,true,0.25),
        sample(10000,false,false,0,true,0.30),
        sample(20000,true,false,99,false,99),
        sample(30000,true,true,2.5,true,0.40),
        sample(40000,true,true,3.5,true,0.50)
      ]};
      state.overview = candidate;
      renderOverview();
      const mapped = state.trend.map(point => point.requests);
      const blockedMapped = state.trend.map(point => point.blocked);

      const canvas = document.getElementById('trend-chart');
      const originalGetContext = canvas.getContext;
      const operations = [];
      const context = {
        _strokeStyle:'', lineWidth:1,
        set strokeStyle(value) { this._strokeStyle = value; },
        get strokeStyle() { return this._strokeStyle; },
        scale(){}, clearRect(){}, beginPath(){}, stroke(){},
        moveTo(x,y){ operations.push({type:'move', color:this._strokeStyle, x, y}); },
        lineTo(x,y){ operations.push({type:'line', color:this._strokeStyle, x, y}); }
      };
      canvas.getContext = () => context;
      try { drawTrend(); } finally { canvas.getContext = originalGetContext; }
      const requestColor = cssColor('--chart-requests', '#67a6ff');
      const blockedColor = cssColor('--chart-blocked', '#ff6b84');
      const requestOps = operations.filter(operation => operation.color === requestColor).map(operation => operation.type);
      const blockedOps = operations.filter(operation => operation.color === blockedColor).map(operation => operation.type);

      state.overview = previous;
      renderAll();
      return {mapped, blockedMapped, requestOps, blockedOps};
    })()`);
    if (telemetryTrendGapContract.mapped.length !== 5 ||
        telemetryTrendGapContract.mapped[0] !== 1.5 ||
        telemetryTrendGapContract.mapped[1] !== null ||
        telemetryTrendGapContract.mapped[2] !== null ||
        telemetryTrendGapContract.mapped[3] !== 2.5 ||
        telemetryTrendGapContract.mapped[4] !== 3.5) {
      throw new Error(`Telemetry history did not preserve unavailable request-rate gaps: ${JSON.stringify(telemetryTrendGapContract)}`);
    }
    const expectedRequestOps = ['move','move','line'];
    if (JSON.stringify(telemetryTrendGapContract.requestOps) !== JSON.stringify(expectedRequestOps)) {
      throw new Error(`Trend chart connected EdgeProxy request-rate segments across a telemetry gap: ${JSON.stringify(telemetryTrendGapContract)}`);
    }
    if (telemetryTrendGapContract.blockedMapped.length !== 5 ||
        telemetryTrendGapContract.blockedMapped[0] !== 0.25 ||
        telemetryTrendGapContract.blockedMapped[1] !== 0.30 ||
        telemetryTrendGapContract.blockedMapped[2] !== null ||
        telemetryTrendGapContract.blockedMapped[3] !== 0.40 ||
        telemetryTrendGapContract.blockedMapped[4] !== 0.50) {
      throw new Error(`Telemetry history did not preserve SecurityEdge rejection-rate gaps: ${JSON.stringify(telemetryTrendGapContract)}`);
    }
    const expectedBlockedOps = ['move','line','move','line'];
    if (JSON.stringify(telemetryTrendGapContract.blockedOps) !== JSON.stringify(expectedBlockedOps)) {
      throw new Error(`Trend chart connected SecurityEdge rejection-rate segments across a telemetry gap: ${JSON.stringify(telemetryTrendGapContract)}`);
    }
  }

  let undefinedMetricRenderingContract = null;
  if (fixtureRoot) {
    undefinedMetricRenderingContract = await cdp.evaluate(`(() => {
      const previous = state.overview;
      const candidate = structuredClone(previous);
      const securityTotal = candidate.security_metrics.total;
      securityTotal.requests = 0;
      securityTotal.block_rate = 0.75;
      securityTotal.detection_rate = 0.50;
      securityTotal.latency = {average_ms:99, maximum_ms:99, p50_ms:99, p95_ms:99, p99_ms:99};

      const edgeMetrics = candidate.edgeproxy_metrics;
      edgeMetrics.requests_per_second = 0;
      const edgeTotal = edgeMetrics.total;
      edgeTotal.requests = 0;
      edgeTotal.cache_hits = 0;
      edgeTotal.cache_misses = 0;
      edgeTotal.cache_hit_ratio = 0.99;
      edgeTotal.response_latency_ms = {count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]};
      edgeTotal.upstream = {...(edgeTotal.upstream || {}), calls:0, latency_ms:{count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]}};

      for (const metric of Object.values(edgeMetrics.routes || {})) {
        metric.requests = 0;
        metric.canceled_requests = 0;
        metric.success = 0;
        metric.success_rate = 1;
        metric.error_rate = 1;
        metric.client_errors = 0;
        metric.server_errors = 0;
        metric.cache_hits = 0;
        metric.cache_misses = 0;
        metric.cache_hit_ratio = 1;
        metric.response_latency_ms = {count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]};
        metric.upstream = {...(metric.upstream || {}), calls:0, latency_ms:{count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]}};
        for (const originMetric of Object.values(metric.upstreams || {})) {
          originMetric.calls = 0;
          originMetric.success_rate = 1;
          originMetric.error_rate = 1;
          originMetric.latency_ms = {count:0, average:99, minimum:99, maximum:99, p50:99, p95:99, p99:99, distribution:[]};
        }
      }
      for (const route of candidate.edgeproxy_status?.routes || []) {
        for (const origin of route.upstreams || []) {
          origin.scheduler_selections = 0;
          origin.ewma_latency_ms = 99;
        }
      }

      state.overview = candidate;
      renderAll();
      const result = {
        blockRate:document.getElementById('kpi-block-rate').textContent.trim(),
        detectionRate:document.getElementById('kpi-detection-rate').textContent.trim(),
        cacheRatio:document.getElementById('kpi-cache').textContent.trim(),
        cacheCounts:document.getElementById('kpi-cache-counts').textContent.trim(),
        securityP95:document.getElementById('kpi-p95').textContent.trim(),
        upstreamAverage:document.getElementById('kpi-upstream').textContent.trim(),
        requestRateLabel:document.getElementById('kpi-rps').textContent.trim(),
        cacheStats:document.getElementById('cache-stats').textContent.replace(/\\s+/g,' ').trim(),
        edgeLatency:document.getElementById('latency-stats').textContent.replace(/\\s+/g,' ').trim(),
        securityLatency:document.getElementById('security-latency').textContent.replace(/\\s+/g,' ').trim(),
        routeTelemetry:document.getElementById('route-telemetry-table').textContent.replace(/\\s+/g,' ').trim(),
        originTelemetry:document.getElementById('origin-telemetry-table').textContent.replace(/\\s+/g,' ').trim()
      };
      state.overview = previous;
      renderAll();
      return result;
    })()`);
    if (undefinedMetricRenderingContract.blockRate !== 'No requests yet' ||
        undefinedMetricRenderingContract.detectionRate !== 'No requests yet' ||
        undefinedMetricRenderingContract.cacheRatio !== '—' ||
        !undefinedMetricRenderingContract.cacheCounts.includes('no cache lookups') ||
        undefinedMetricRenderingContract.securityP95 !== '—' ||
        undefinedMetricRenderingContract.upstreamAverage !== 'No upstream samples' ||
        !undefinedMetricRenderingContract.requestRateLabel.includes('avg since start') ||
        !undefinedMetricRenderingContract.cacheStats.includes('Hit ratio—') ||
        undefinedMetricRenderingContract.cacheStats.includes('99.0%') ||
        undefinedMetricRenderingContract.edgeLatency.includes('99.00 ms') ||
        undefinedMetricRenderingContract.securityLatency.includes('99.00 ms') ||
        !undefinedMetricRenderingContract.routeTelemetry.includes('No requests yet') ||
        !undefinedMetricRenderingContract.routeTelemetry.includes('— / —') ||
        undefinedMetricRenderingContract.routeTelemetry.includes('99.00 ms') ||
        undefinedMetricRenderingContract.originTelemetry.includes('99.00 ms')) {
      throw new Error(`Dashboard rendered undefined zero-denominator/sample metrics as measured values: ${JSON.stringify(undefinedMetricRenderingContract)}`);
    }
  }

  let mobileNavLayouts = [];
  if (fixtureRoot) {
    const views = ['overview','security','protection','traffic','routes','policies','system'];
    for (const width of [700,390,320]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:width <= 520});
      await sleep(60);
      for (const view of views) {
        await cdp.evaluate(`setView(${JSON.stringify(view)}); ensureActiveNavVisible()`);
        await sleep(25);
        const layout = await cdp.evaluate(`(() => {
          const nav=document.getElementById('nav');
          const active=nav?.querySelector('.nav-item.active');
          if (!nav || !active) return null;
          const navRect=nav.getBoundingClientRect();
          const activeRect=active.getBoundingClientRect();
          const items=[...nav.querySelectorAll('.nav-item')].map(item => {
            const rect=item.getBoundingClientRect();
            return {label:item.textContent.trim(),left:rect.left,right:rect.right};
          });
          const partialLeft=items.filter(item => item.left < navRect.left - 1 && item.right > navRect.left + 1).map(item => item.label);
          const root=document.documentElement;
          const activeView=document.querySelector('.view.active');
          const escaped=activeView ? [...activeView.querySelectorAll('*')].filter(node => {
            const style=getComputedStyle(node);
            if (style.display === 'none' || style.visibility === 'hidden') return false;
            const rect=node.getBoundingClientRect();
            if (rect.width <= 0 || rect.height <= 0) return false;
            const scrollContainer=node.closest('.table-wrap,.connectivity-topology');
            if (scrollContainer && scrollContainer !== node) return false;
            return rect.left < -1 || rect.right > root.clientWidth + 1;
          }).map(node => ({
            tag:node.tagName.toLowerCase(),
            id:node.id || '',
            className:typeof node.className === 'string' ? node.className : '',
            left:Math.round(node.getBoundingClientRect().left * 10) / 10,
            right:Math.round(node.getBoundingClientRect().right * 10) / 10
          })).slice(0,8) : [];
          const clipped=activeView ? [...activeView.querySelectorAll('*')].filter(node => {
            if (node.closest('.table-wrap,.connectivity-topology,.component-list,.transition-list,.raw-details')) return false;
            const style=getComputedStyle(node);
            const rect=node.getBoundingClientRect();
            if (style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return false;
            if (!(node.textContent || '').trim()) return false;
            if (['auto','scroll'].includes(style.overflowX)) return false;
            return node.scrollWidth > node.clientWidth + 1;
          }).map(node => ({
            tag:node.tagName.toLowerCase(),
            id:node.id || '',
            className:typeof node.className === 'string' ? node.className : '',
            scrollWidth:node.scrollWidth,
            clientWidth:node.clientWidth
          })).slice(0,8) : [];
          return {
            navLeft:navRect.left, navRight:navRect.right, scrollLeft:nav.scrollLeft,
            scrollWidth:nav.scrollWidth, clientWidth:nav.clientWidth,
            active:active.textContent.trim(), activeLeft:activeRect.left, activeRight:activeRect.right,
            activeVisible:activeRect.left >= navRect.left - 1 && activeRect.right <= navRect.right + 1,
            viewportWidth:root.clientWidth, bodyScrollWidth:document.body.scrollWidth,
            partialLeft, escaped, clipped
          };
        })()`);
        if (!layout) throw new Error(`Compact navigation layout is missing at ${width}px for ${view}`);
        layout.width=width;
        layout.view=view;
        mobileNavLayouts.push(layout);
        if (!layout.activeVisible || layout.partialLeft.length ||
            layout.bodyScrollWidth > layout.viewportWidth + 1 ||
            layout.escaped.length || layout.clipped.length) {
          throw new Error(`Compact navigation or page layout escapes the viewport at ${width}px for ${view}: ${JSON.stringify(layout)}`);
        }
      }
    }
    await cdp.evaluate(`setView('overview')`);
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(80);
  }

  let topbarLayouts = [];
  if (fixtureRoot) {
    for (const width of [1365,960,700,520,390,360,320]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:width <= 520});
      await sleep(80);
      const layout = await cdp.evaluate(`(() => {
        const root=document.documentElement;
        const topbar=document.querySelector('.topbar');
        const eyebrow=document.querySelector('.topbar-eyebrow');
        const row=document.querySelector('.topbar-row');
        const titleGroup=document.querySelector('.topbar-title-group');
        const title=document.getElementById('page-title');
        const updated=document.getElementById('last-updated');
        const actions=document.querySelector('.topbar-actions');
        const toggle=actions?.querySelector('[data-theme-toggle]');
        const refresh=document.getElementById('refresh');
        if (!topbar || !eyebrow || !row || !titleGroup || !title || !updated || !actions || !toggle || !refresh) return null;
        const rect = node => { const value=node.getBoundingClientRect(); return {left:value.left,right:value.right,top:value.top,bottom:value.bottom,width:value.width,height:value.height}; };
        const topbarRect=rect(topbar), eyebrowRect=rect(eyebrow), rowRect=rect(row), titleRect=rect(title), updatedRect=rect(updated), actionsRect=rect(actions), toggleRect=rect(toggle), refreshRect=rect(refresh);
        return {
          viewportWidth:root.clientWidth, bodyScrollWidth:document.body.scrollWidth,
          topbar:topbarRect, eyebrow:eyebrowRect, row:rowRect, title:titleRect, updated:updatedRect, actions:actionsRect, toggle:toggleRect, refresh:refreshRect,
          titleDirection:getComputedStyle(titleGroup).flexDirection,
          actionDirection:getComputedStyle(actions).flexDirection,
          actionWrap:getComputedStyle(actions).flexWrap,
          actionGap:parseFloat(getComputedStyle(actions).columnGap || getComputedStyle(actions).gap || '0'),
          eyebrowRowGap:rowRect.top-eyebrowRect.bottom,
          titleUpdatedGap:updatedRect.top-titleRect.bottom,
          buttonCenterDelta:Math.abs((toggleRect.top+toggleRect.height/2)-(refreshRect.top+refreshRect.height/2)),
          titleActionCenterDelta:Math.abs((titleRect.top+titleRect.height/2)-(actionsRect.top+actionsRect.height/2))
        };
      })()`);
      if (!layout) throw new Error(`Topbar layout nodes are missing at ${width}px`);
      layout.width=width;
      topbarLayouts.push(layout);
      const outOfBounds = layout.row.left < layout.topbar.left - 1 || layout.row.right > layout.topbar.right + 1 ||
        layout.actions.right > layout.row.right + 1 || layout.title.left < layout.row.left - 1;
      const buttonsNotInline = layout.actionDirection !== 'row' || layout.actionWrap !== 'nowrap' ||
        layout.toggle.right > layout.refresh.left + 1 || layout.buttonCenterDelta > 1.5 ||
        layout.actionGap < 6 || layout.actionGap > 12;
      if (layout.bodyScrollWidth > layout.viewportWidth + 1 || outOfBounds || buttonsNotInline) {
        throw new Error(`Topbar action layout failed at ${width}px: ${JSON.stringify(layout)}`);
      }
      if (width <= 520) {
        const compactMismatch = layout.titleDirection !== 'column' ||
          layout.updated.top < layout.title.bottom - 1 ||
          layout.title.right > layout.actions.left - 4 ||
          layout.titleActionCenterDelta > 4 ||
          layout.eyebrowRowGap < 9 || layout.eyebrowRowGap > 13 ||
          layout.titleUpdatedGap < 8 || layout.titleUpdatedGap > 12 ||
          layout.topbar.height > 112;
        if (compactMismatch) throw new Error(`Compact Overview header is not balanced at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(80);
  }

  let securityExplorerLayouts = [];
  if (fixtureRoot) {
    for (const width of [700,520,390,320]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:width <= 520});
      await sleep(60);
      await cdp.evaluate(`setView('security')`);
      const layout = await cdp.evaluate(`(() => {
        const root=document.documentElement;
        const panel=document.querySelector('#view-security > .panel');
        const head=panel?.querySelector('.panel-head');
        const intro=head?.querySelector(':scope > div:first-child');
        const actions=head?.querySelector('.top-actions');
        const ndjson=document.getElementById('export-ndjson');
        const csv=document.getElementById('export-csv');
        const clear=document.getElementById('clear-security');
        const filters=document.getElementById('security-filters');
        if (!panel || !head || !intro || !actions || !ndjson || !csv || !clear || !filters) return null;
        const rect=node=>{const r=node.getBoundingClientRect(); return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};
        const actionRects=[ndjson,csv,clear].map(rect);
        const filterRect=rect(filters);
        const filterControls=[...filters.querySelectorAll('input,select,button')].map(node=>({id:node.id||'',name:node.getAttribute('name')||'',...rect(node)}));
        return {
          viewportWidth:root.clientWidth,bodyScrollWidth:document.body.scrollWidth,
          panel:rect(panel),head:rect(head),intro:rect(intro),actions:rect(actions),filters:filterRect,
          headDirection:getComputedStyle(head).flexDirection,
          actionsDisplay:getComputedStyle(actions).display,
          actionsDirection:getComputedStyle(actions).flexDirection,
          actionsGap:parseFloat(getComputedStyle(actions).gap || '0'),
          introActionGap:rect(actions).top-rect(intro).bottom,
          actionRects,filterControls,
          filtersDisplay:getComputedStyle(filters).display,
          actionsScrollWidth:actions.scrollWidth,actionsClientWidth:actions.clientWidth
        };
      })()`);
      if (!layout) throw new Error(`Security Explorer responsive controls are missing at ${width}px`);
      layout.width=width;
      securityExplorerLayouts.push(layout);
      const actionsEscape=layout.actions.left < layout.panel.left - 1 || layout.actions.right > layout.panel.right + 1 ||
        layout.actionsScrollWidth > layout.actionsClientWidth + 1;
      if (layout.bodyScrollWidth > layout.viewportWidth + 1 || layout.headDirection !== 'column' || actionsEscape ||
          layout.introActionGap < 12 || layout.introActionGap > 18) {
        throw new Error(`Security Explorer header actions are not balanced at ${width}px: ${JSON.stringify(layout)}`);
      }
      const [ndjson,csv,clear]=layout.actionRects;
      if (width > 520) {
        const centers=[ndjson,csv,clear].map(r=>r.top+r.height/2);
        if (layout.actionsDisplay !== 'flex' || layout.actionsDirection !== 'row' ||
            Math.max(...centers)-Math.min(...centers) > 1.5) {
          throw new Error(`Tablet Security Explorer actions are not kept on one row at ${width}px: ${JSON.stringify(layout)}`);
        }
      } else {
        const exportsAligned=Math.abs(ndjson.top-csv.top) <= 1.5 && Math.abs(ndjson.height-csv.height) <= 1.5;
        const clearBelow=clear.top >= Math.max(ndjson.bottom,csv.bottom) + 6;
        const clearSpans=Math.abs(clear.left-layout.actions.left) <= 1.5 && Math.abs(clear.right-layout.actions.right) <= 1.5;
        const controlsFullWidth=layout.filterControls.every(control =>
          Math.abs(control.left-layout.filters.left) <= 1.5 && Math.abs(control.right-layout.filters.right) <= 1.5);
        if (layout.actionsDisplay !== 'grid' || !exportsAligned || !clearBelow || !clearSpans ||
            layout.filtersDisplay !== 'grid' || !controlsFullWidth) {
          throw new Error(`Mobile Security Explorer controls are not cleanly stacked at ${width}px: ${JSON.stringify(layout)}`);
        }
      }
    }
    await cdp.evaluate(`setView('overview')`);
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(80);
  }

  let semanticColorContract = null;
  let connectivityActionLayout = null;
  let connectivityResponsiveLayouts = [];
  if (fixtureRoot) {
    // Prevent Light Mode from silently flattening semantic status colors. These
    // probes cover every status-bearing visual family used by the Dashboard.
    semanticColorContract = await cdp.evaluate(`(() => {
      window.SecurityEdgeTheme.apply('light');
      const normalize = value => String(value || '').replaceAll(' ', '').toLowerCase();
      const resolveColor = value => {
        const node = document.createElement('span');
        node.style.color = value;
        document.body.appendChild(node);
        const resolved = getComputedStyle(node).color;
        node.remove();
        return normalize(resolved);
      };
      const rgb = value => {
        const values = String(value || '').match(/[0-9.]+/g);
        return values && values.length >= 3 ? values.slice(0,3).map(Number) : null;
      };
      const luminance = value => {
        const channels = rgb(value);
        if (!channels) return 0;
        const linear = channels.map(channel => {
          const c = channel / 255;
          return c <= .04045 ? c / 12.92 : Math.pow((c + .055) / 1.055, 2.4);
        });
        return .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
      };
      const contrast = (a,b) => {
        const first=luminance(a), second=luminance(b);
        return (Math.max(first,second)+.05)/(Math.min(first,second)+.05);
      };
      const expected = {
        healthy:resolveColor('var(--accent)'),
        degraded:resolveColor('var(--warn)'),
        down:resolveColor('var(--danger)')
      };
      const host = document.createElement('div');
      host.style.cssText = 'position:fixed;left:-10000px;top:0;width:600px;pointer-events:none';
      document.body.appendChild(host);
      const states = {};
      for (const status of ['healthy','degraded','down']) {
        const dotClass = status === 'healthy' ? 'live' : status;
        const badgeClass = status === 'healthy' ? 'ready' : status === 'degraded' ? 'warn' : 'error';
        host.innerHTML =
          '<article class="panel connectivity-panel status-' + status + '"><div class="connectivity-hero"><div class="status-orb"><span></span></div></div></article>' +
          '<span class="dot ' + dotClass + '"></span>' +
          '<div class="topology-node ' + status + '"><span class="node-dot"></span></div>' +
          '<span class="legend-dot ' + status + '"></span>' +
          '<article class="component-check ' + status + '"><span class="node-dot"></span></article>' +
          '<span class="status-pill ' + status + '">' + status + '</span>' +
          '<span class="badge ' + badgeClass + '">state</span>' +
          (status === 'healthy' ? '<div class="traffic-active"><span class="activity-dot"></span></div>' : '');
        const panel = host.querySelector('.connectivity-panel');
        const orb = host.querySelector('.status-orb span');
        const dot = host.querySelector('.dot');
        const topologyDot = host.querySelector('.topology-node .node-dot');
        const legendDot = host.querySelector('.legend-dot');
        const component = host.querySelector('.component-check');
        const componentDot = component.querySelector('.node-dot');
        const pill = host.querySelector('.status-pill');
        const badge = host.querySelector('.badge');
        const pillStyle = getComputedStyle(pill);
        const badgeStyle = getComputedStyle(badge);
        states[status] = {
          expected:expected[status],
          barGradient:getComputedStyle(panel,'::before').backgroundImage,
          heroGradient:getComputedStyle(panel.querySelector('.connectivity-hero')).backgroundImage,
          orb:normalize(getComputedStyle(orb).backgroundColor),
          dot:normalize(getComputedStyle(dot).backgroundColor),
          topologyDot:normalize(getComputedStyle(topologyDot).backgroundColor),
          legendDot:normalize(getComputedStyle(legendDot).backgroundColor),
          componentDot:normalize(getComputedStyle(componentDot).backgroundColor),
          componentBorder:normalize(getComputedStyle(component).borderLeftColor),
          pillTextContrast:contrast(pillStyle.color,pillStyle.backgroundColor),
          badgeTextContrast:contrast(badgeStyle.color,badgeStyle.backgroundColor),
          activityDot:status === 'healthy' ? normalize(getComputedStyle(host.querySelector('.activity-dot')).backgroundColor) : ''
        };
      }
      host.remove();
      return states;
    })()`);
    for (const [status, values] of Object.entries(semanticColorContract)) {
      for (const field of ['orb','dot','topologyDot','legendDot','componentDot','componentBorder']) {
        if (values[field] !== values.expected) {
          throw new Error(`Light-theme semantic ${status} color was flattened for ${field}: ${JSON.stringify(values)}`);
        }
      }
      if (!String(values.barGradient).includes('linear-gradient') || !String(values.heroGradient).includes('linear-gradient')) {
        throw new Error(`Light-theme semantic ${status} panel treatment is missing: ${JSON.stringify(values)}`);
      }
      if (values.pillTextContrast < 4.5 || values.badgeTextContrast < 4.5) {
        throw new Error(`Light-theme semantic ${status} badge/pill contrast is too weak: ${JSON.stringify(values)}`);
      }
      if (status === 'healthy' && values.activityDot !== values.expected) {
        throw new Error(`Light-theme live activity indicator lost its semantic color: ${JSON.stringify(values)}`);
      }
    }

    connectivityActionLayout = await cdp.evaluate(`(() => {
      const actions=document.querySelector('.connectivity-actions');
      const pill=document.getElementById('connectivity-overall');
      const updated=document.getElementById('connectivity-updated');
      const button=document.getElementById('check-connectivity');
      // Use the longest normal status label and the timestamp shape shown in
      // production so this guards the exact desktop wrapping regression.
      const original={pillText:pill.textContent,pillClass:pill.className,updatedText:updated.textContent};
      pill.textContent='DEGRADED';
      pill.className='status-pill degraded';
      updated.textContent='Checked 8/12/2026, 9:21:51 PM';
      const rects=[pill,updated,button].map(node => node.getBoundingClientRect());
      const centers=rects.map(rect => rect.top + rect.height/2);
      const result={
        flexWrap:getComputedStyle(actions).flexWrap,
        centerSpread:Math.max(...centers)-Math.min(...centers),
        actionTop:actions.getBoundingClientRect().top,
        actionBottom:actions.getBoundingClientRect().bottom,
        buttonTop:rects[2].top,
        updatedTop:rects[1].top
      };
      pill.textContent=original.pillText;
      pill.className=original.pillClass;
      updated.textContent=original.updatedText;
      return result;
    })()`);
    if (connectivityActionLayout.flexWrap !== 'nowrap' || connectivityActionLayout.centerSpread > 1.5) {
      throw new Error(`Desktop connectivity actions are no longer kept on one aligned row: ${JSON.stringify(connectivityActionLayout)}`);
    }

    for (const width of [1365,1100,961,901,701,700,520,390,320]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:width <= 520});
      await sleep(80);
      const layout = await cdp.evaluate(`(() => {
        const hero=document.querySelector('.connectivity-hero');
        const heading=document.querySelector('.connectivity-heading');
        const actions=document.querySelector('.connectivity-actions');
        const pill=document.getElementById('connectivity-overall');
        const updated=document.getElementById('connectivity-updated');
        const button=document.getElementById('check-connectivity');
        const heroRect=hero.getBoundingClientRect();
        const headingRect=heading.getBoundingClientRect();
        const actionsRect=actions.getBoundingClientRect();
        const pillRect=pill.getBoundingClientRect();
        const updatedRect=updated.getBoundingClientRect();
        const buttonRect=button.getBoundingClientRect();
        const style=getComputedStyle(hero);
        const actionStyle=getComputedStyle(actions);
        return {
          viewport:document.documentElement.clientWidth,
          bodyScrollWidth:document.body.scrollWidth,
          flexDirection:style.flexDirection,
          actionsDisplay:actionStyle.display,
          actionsWrap:actionStyle.flexWrap,
          actionsScrollWidth:actions.scrollWidth,actionsClientWidth:actions.clientWidth,
          updatedWhiteSpace:getComputedStyle(updated).whiteSpace,
          heroLeft:heroRect.left,heroRight:heroRect.right,
          headingLeft:headingRect.left,headingRight:headingRect.right,headingWidth:headingRect.width,
          actionsLeft:actionsRect.left,actionsRight:actionsRect.right,actionsWidth:actionsRect.width,
          pillTop:pillRect.top,pillBottom:pillRect.bottom,
          updatedTop:updatedRect.top,updatedBottom:updatedRect.bottom,
          buttonTop:buttonRect.top,buttonBottom:buttonRect.bottom
        };
      })()`);
      layout.width=width;
      connectivityResponsiveLayouts.push(layout);
      const childOverflow = layout.headingLeft < layout.heroLeft - 1 || layout.headingRight > layout.heroRight + 1 ||
        layout.actionsLeft < layout.heroLeft - 1 || layout.actionsRight > layout.heroRight + 1;
      const compactActionMismatch = width <= 520 ?
        (layout.actionsDisplay !== 'grid' || layout.actionsScrollWidth > layout.actionsClientWidth + 1 ||
          layout.updatedWhiteSpace === 'nowrap' || layout.buttonTop < Math.max(layout.pillBottom,layout.updatedBottom) + 6) :
        (width <= 700 ? layout.actionsWrap !== 'wrap' : layout.actionsWrap !== 'nowrap');
      if (layout.bodyScrollWidth > layout.viewport + 1 || childOverflow ||
          (width > 1180 && layout.flexDirection !== 'row') ||
          (width <= 1180 && layout.flexDirection !== 'column') || compactActionMismatch) {
        throw new Error(`Connectivity hero responsive layout failed at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(80);
  }

  let sidebarBrandLayout = null;
  if (fixtureRoot) {
    sidebarBrandLayout = await cdp.evaluate(`(() => {
      const brand = document.querySelector('.sidebar .brand');
      const mark = brand?.querySelector('.brand-mark.small');
      const shield = mark?.querySelector('svg.brand-shield');
      const copy = brand?.querySelector('.brand-copy');
      if (!brand || !mark || !shield || !copy) return null;
      const brandRect = brand.getBoundingClientRect();
      const markRect = mark.getBoundingClientRect();
      const copyRect = copy.getBoundingClientRect();
      return {
        hasShield:true, markText:mark.textContent.trim(),
        markWidth:markRect.width, markHeight:markRect.height,
        centerDelta:Math.abs((markRect.top + markRect.height / 2) - (copyRect.top + copyRect.height / 2)),
        brandWidth:brandRect.width
      };
    })()`);
    if (!sidebarBrandLayout || !sidebarBrandLayout.hasShield || sidebarBrandLayout.markText !== '' ||
        sidebarBrandLayout.markWidth < 36 || sidebarBrandLayout.markWidth > 44 ||
        Math.abs(sidebarBrandLayout.markWidth - sidebarBrandLayout.markHeight) > 1 ||
        sidebarBrandLayout.centerDelta > 2) {
      throw new Error(`Sidebar brand mark is not a balanced shield lockup: ${JSON.stringify(sidebarBrandLayout)}`);
    }
  }

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
      // The production dashboard has a 5-second periodic refresh. Stop fixture
      // intervals before this timing-sensitive contract so an unrelated timer
      // cannot start a third generation after the manual refresh promise settles.
      // This isolates the behavior under test: three concurrent triggers must
      // serialize into the active generation plus one queued generation.
      (window.__fixtureIntervals || []).forEach(id => clearInterval(id));
      window.__fixtureIntervals = [];
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

  let originDialogLayout = null;
  let telemetryDetailLayout = null;
  if (fixtureRoot) {
    await cdp.evaluate(`document.querySelector('[data-origin-edit]').click()`);
    await eventually(async () => await cdp.evaluate(`document.getElementById('origin-dialog').open`), 'Origin editor');
    originDialogLayout = await cdp.evaluate(`(() => {
      const dialog = document.getElementById('origin-dialog');
      const fields = dialog.querySelector('.form-grid').getBoundingClientRect();
      const tlsSwitch = dialog.querySelector('.switch-row').getBoundingClientRect();
      return {switchGap:tlsSwitch.top-fields.bottom};
    })()`);
    if (originDialogLayout.switchGap < 12 || originDialogLayout.switchGap > 20) {
      throw new Error(`Origin TLS verification control spacing is inconsistent: ${JSON.stringify(originDialogLayout)}`);
    }
    await cdp.evaluate(`document.getElementById('origin-dialog').close()`);

    await cdp.evaluate(`document.querySelector('[data-origin-telemetry]').click()`);
    await eventually(async () => await cdp.evaluate(`document.getElementById('telemetry-dialog').open`), 'Origin telemetry dialog');
    telemetryDetailLayout = await cdp.evaluate(`(() => {
      const dialog = document.getElementById('telemetry-dialog');
      const statusPanel = dialog.querySelector('.telemetry-detail-grid + .subsection').getBoundingClientRect();
      const rawPanel = dialog.querySelector('.raw-details').getBoundingClientRect();
      const barList = dialog.querySelector('.bar-list').getBoundingClientRect();
      const barRowWidths = [...dialog.querySelectorAll('.bar-row')].map(row => row.getBoundingClientRect().width);
      return {
        leftDelta:Math.abs(statusPanel.left-rawPanel.left),
        rightDelta:Math.abs(statusPanel.right-rawPanel.right),
        barListWidth:barList.width,
        barRowWidths
      };
    })()`);
    if (telemetryDetailLayout.leftDelta > 1 || telemetryDetailLayout.rightDelta > 1 ||
        telemetryDetailLayout.barRowWidths.length < 1 ||
        telemetryDetailLayout.barRowWidths.some(width => Math.abs(width-telemetryDetailLayout.barListWidth) > 1)) {
      throw new Error(`Telemetry status distribution is not aligned with the raw telemetry panel: ${JSON.stringify(telemetryDetailLayout)}`);
    }
    await cdp.evaluate(`document.getElementById('telemetry-dialog').close()`);
  }

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
    for (const width of [901, 680, 390, 320]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:false});
      await sleep(100);
      await cdp.evaluate(`ensureActiveNavVisible()`);
      await sleep(20);
      const navState = await cdp.evaluate(`(() => {
        const nav = document.getElementById('nav');
        const active = nav?.querySelector('.nav-item.active');
        const navRect = nav?.getBoundingClientRect();
        const activeRect = active?.getBoundingClientRect();
        return {
          scrollbarWidth: nav ? getComputedStyle(nav).scrollbarWidth : '',
          activeVisible: !navRect || !activeRect || (activeRect.left >= navRect.left - 1 && activeRect.right <= navRect.right + 1),
          scrollLeft: nav?.scrollLeft, scrollWidth: nav?.scrollWidth, clientWidth: nav?.clientWidth,
          navLeft: navRect?.left, navRight: navRect?.right,
          activeLeft: activeRect?.left, activeRight: activeRect?.right,
          activeOffsetLeft: active?.offsetLeft, activeOffsetWidth: active?.offsetWidth
        };
      })()`);
      if (width <= 960 && (navState.scrollbarWidth !== 'none' || !navState.activeVisible)) {
        throw new Error(`Compact navigation is not clean and active-visible at ${width}px: ${JSON.stringify(navState)}`);
      }
      await cdp.evaluate(`document.querySelector('[data-route-edit]').click()`);
      await eventually(async () => await cdp.evaluate(`document.getElementById('route-dialog').open`), `Route dialog at ${width}px`);
      const layout = await cdp.evaluate(`(() => {
        const root = document.documentElement;
        const wraps = [...document.querySelectorAll('#view-routes .table-wrap')];
        const scrollableTables = wraps.filter(node => node.scrollWidth > node.clientWidth + 1).length;
        const originActions = document.querySelector('.origin-actions');
        const tableAction = document.querySelector('.table-actions-cell');
        const footer = document.querySelector('.sidebar-foot');
        const lock = document.getElementById('logout');
        const footerRect = footer.getBoundingClientRect();
        const lockRect = lock.getBoundingClientRect();
        const dialog = document.getElementById('route-dialog').getBoundingClientRect();
        return {
          horizontalScrollbarPx: window.innerHeight - root.clientHeight,
          bodyScrollWidth: document.body.scrollWidth,
          pageOverflowX: getComputedStyle(root).overflowX,
          bodyOverflowX: getComputedStyle(document.body).overflowX,
          scrollableTables,
          originActionGap: originActions ? getComputedStyle(originActions).gap : '',
          tableActionAlign: tableAction ? getComputedStyle(tableAction).textAlign : '',
          compactFooterDisplay: getComputedStyle(footer).display,
          compactFooterWidth: footerRect.width,
          compactLockVisible: lockRect.width > 0 && lockRect.height > 0,
          compactLockLeft: lockRect.left,
          compactLockRight: lockRect.right,
          dialogLeft: dialog.left,
          dialogRight: dialog.right,
          dialogWidth: dialog.width,
          viewportWidth: root.clientWidth
        };
      })()`);
      await cdp.evaluate(`document.getElementById('route-dialog').close()`);
      layout.width = width;
      responsiveLayouts.push(layout);
      if (layout.horizontalScrollbarPx > 1 || layout.bodyScrollWidth > layout.viewportWidth + 1 ||
          layout.pageOverflowX !== 'hidden' || layout.bodyOverflowX !== 'hidden') {
        throw new Error(`Dashboard exposes page-level horizontal overflow at ${width}px: ${JSON.stringify(layout)}`);
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
      if (layout.compactFooterDisplay === 'none' || !layout.compactLockVisible ||
          layout.compactLockLeft < -1 || layout.compactLockRight > layout.viewportWidth + 1 ||
          layout.compactFooterWidth > layout.viewportWidth + 1) {
        throw new Error(`Compact connection status or Lock action is unavailable at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    for (const width of [680, 390, 320]) {
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
    const breakpointLayouts = [];
    for (const width of [961, 901]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:false});
      await sleep(100);
      await cdp.evaluate(`document.querySelector('[data-view="policies"]').click()`);
      const layout = await cdp.evaluate(`(() => {
        const root = document.documentElement;
        const sidebar = document.querySelector('.sidebar');
        const footer = document.querySelector('.sidebar-foot');
        const lock = document.getElementById('logout');
        const main = document.querySelector('main').getBoundingClientRect();
        const controls = [...document.querySelectorAll('#view-policies input,#view-policies select,#view-policies button')]
          .filter(node => { const rect=node.getBoundingClientRect(), style=getComputedStyle(node); return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0; });
        const outOfBounds = controls.filter(node => { const rect=node.getBoundingClientRect(); return rect.left < main.left - 1 || rect.right > main.right + 1; }).length;
        return {
          viewportWidth: root.clientWidth,
          bodyScrollWidth: document.body.scrollWidth,
          sidebarPosition: getComputedStyle(sidebar).position,
          footerDisplay: getComputedStyle(footer).display,
          lockVisible: lock.getBoundingClientRect().width > 0 && lock.getBoundingClientRect().height > 0,
          mainLeft: main.left,
          outOfBounds
        };
      })()`);
      layout.width = width;
      breakpointLayouts.push(layout);
      const shouldBeDesktop = width > 960;
      if (layout.bodyScrollWidth > layout.viewportWidth + 1 || layout.outOfBounds !== 0 ||
          layout.footerDisplay === 'none' || !layout.lockVisible ||
          (shouldBeDesktop && (layout.sidebarPosition !== 'fixed' || Math.abs(layout.mainLeft - 250) > 1)) ||
          (!shouldBeDesktop && (layout.sidebarPosition !== 'static' || Math.abs(layout.mainLeft) > 1))) {
        throw new Error(`Responsive breakpoint layout contract failed at ${width}px: ${JSON.stringify(layout)}`);
      }
    }
    responsiveLayouts.push({breakpointLayouts});
    await cdp.send('Emulation.setDeviceMetricsOverride', {width:1365,height:900,deviceScaleFactor:1,mobile:false});
    await sleep(100);
  }

  await cdp.evaluate(`document.querySelector('[data-view="traffic"]').click()`);
  await eventually(async () => await cdp.evaluate(`document.getElementById('view-traffic').classList.contains('active')`), 'Traffic and cache view');
  const cacheOptions = await cdp.evaluate(`document.getElementById('cache-route-select').options.length`);
  if (cacheOptions < 1) throw new Error('Per-route cache editor has no Route options.');

  let editorStateContract = null;
  if (fixtureRoot) {
    editorStateContract = await cdp.evaluate(`(() => {
      const originalEdgeConfig = structuredClone(state.edgeConfig);
      const originalPolicies = structuredClone(state.policies);
      const originalSelectedPolicy = state.selectedPolicy;
      const originalPolicyDirty = state.policyDirty;
      const originalCacheDirty = state.cacheEditorDirty;
      const routeName = ${JSON.stringify(expectedRoute)};
      try {
        state.selectedPolicy = routeName;
        state.policyDirty = false;
        renderPolicies();
        const policyField = document.querySelector('#policy-form [name="anomaly_threshold"]');
        policyField.value = '17';
        policyField.dispatchEvent(new Event('input', {bubbles:true}));
        renderPolicies();
        const policyPreserved = {
          selected:state.selectedPolicy, dirty:state.policyDirty, value:policyField.value
        };

        state.policies = {...structuredClone(originalPolicies), routes:[], route_policies:{}, effective_policies:{}};
        renderPolicies();
        const policyResynchronized = {
          selected:state.selectedPolicy, dirty:state.policyDirty, title:document.getElementById('policy-title').textContent, value:policyField.value
        };

        state.policies = structuredClone(originalPolicies);
        const firstRoute = structuredClone(originalEdgeConfig.routes.find(route => route.name === routeName) || originalEdgeConfig.routes[0]);
        const backupRoute = structuredClone(firstRoute);
        backupRoute.name = 'backup-app';
        backupRoute.cache = {...(backupRoute.cache || {}), default_ttl:'77s'};
        state.edgeConfig = {...structuredClone(originalEdgeConfig), routes:[firstRoute, backupRoute]};
        state.cacheEditorDirty = false;
        renderRoutes();
        loadCacheEditor(firstRoute.name);
        const cacheSelect = document.getElementById('cache-route-select');
        const cacheTTL = document.getElementById('cache-editor-ttl');
        cacheSelect.value = backupRoute.name;
        cacheSelect.dispatchEvent(new Event('change', {bubbles:true}));
        const cacheRouteSwitch = {
          selected:cacheSelect.value, loaded:cacheSelect.dataset.loaded || '', dirty:state.cacheEditorDirty, ttl:cacheTTL.value
        };
        cacheSelect.value = firstRoute.name;
        cacheSelect.dispatchEvent(new Event('change', {bubbles:true}));
        cacheTTL.value = '999s';
        cacheTTL.dispatchEvent(new Event('input', {bubbles:true}));
        renderRoutes();
        const cachePreserved = {
          selected:document.getElementById('cache-route-select').value,
          loaded:document.getElementById('cache-route-select').dataset.loaded || '',
          dirty:state.cacheEditorDirty,
          ttl:cacheTTL.value
        };

        state.edgeConfig = {...structuredClone(originalEdgeConfig), routes:[backupRoute]};
        renderRoutes();
        const cacheResynchronized = {
          selected:document.getElementById('cache-route-select').value,
          loaded:document.getElementById('cache-route-select').dataset.loaded || '',
          dirty:state.cacheEditorDirty,
          ttl:cacheTTL.value
        };

        state.edgeConfig = {...structuredClone(originalEdgeConfig), routes:[]};
        renderRoutes();
        const emptyRoutes = {
          loaded:document.getElementById('cache-route-select').dataset.loaded || '',
          editorDisabled:[...document.querySelectorAll('#cache-config-form input, #cache-config-form select')].every(control => control.disabled),
          saveDisabled:document.getElementById('save-cache-config').disabled,
          purgeDisabled:document.querySelector('#purge-form button[type="submit"]').disabled,
          message:document.getElementById('cache-config-result').textContent
        };
        return {policyPreserved, policyResynchronized, cacheRouteSwitch, cachePreserved, cacheResynchronized, emptyRoutes};
      } finally {
        state.edgeConfig = originalEdgeConfig;
        state.policies = originalPolicies;
        state.selectedPolicy = originalSelectedPolicy;
        state.policyDirty = originalPolicyDirty;
        state.cacheEditorDirty = originalCacheDirty;
        renderRoutes();
        renderPolicies();
      }
    })()`);
    if (editorStateContract.policyPreserved.selected !== expectedRoute || !editorStateContract.policyPreserved.dirty ||
        editorStateContract.policyPreserved.value !== '17') {
      throw new Error(`Unsaved Policy edits are not preserved across dashboard renders: ${JSON.stringify(editorStateContract)}`);
    }
    if (editorStateContract.policyResynchronized.selected !== 'default' || editorStateContract.policyResynchronized.dirty ||
        editorStateContract.policyResynchronized.title !== 'Default policy') {
      throw new Error(`Policy editor does not safely resynchronize when its Route disappears: ${JSON.stringify(editorStateContract)}`);
    }
    if (editorStateContract.cacheRouteSwitch.selected !== 'backup-app' || editorStateContract.cacheRouteSwitch.loaded !== 'backup-app' ||
        editorStateContract.cacheRouteSwitch.dirty || editorStateContract.cacheRouteSwitch.ttl !== '77s') {
      throw new Error(`Changing the cache Route must load a clean editor state: ${JSON.stringify(editorStateContract)}`);
    }
    if (editorStateContract.cachePreserved.selected !== expectedRoute || editorStateContract.cachePreserved.loaded !== expectedRoute ||
        !editorStateContract.cachePreserved.dirty || editorStateContract.cachePreserved.ttl !== '999s') {
      throw new Error(`Unsaved cache edits are not preserved for the active Route: ${JSON.stringify(editorStateContract)}`);
    }
    if (editorStateContract.cacheResynchronized.selected !== 'backup-app' || editorStateContract.cacheResynchronized.loaded !== 'backup-app' ||
        editorStateContract.cacheResynchronized.dirty || editorStateContract.cacheResynchronized.ttl !== '77s') {
      throw new Error(`Cache editor does not resynchronize after its selected Route is removed: ${JSON.stringify(editorStateContract)}`);
    }
    if (editorStateContract.emptyRoutes.loaded || !editorStateContract.emptyRoutes.editorDisabled ||
        !editorStateContract.emptyRoutes.saveDisabled || !editorStateContract.emptyRoutes.purgeDisabled ||
        editorStateContract.emptyRoutes.message !== 'No routes are configured.') {
      throw new Error(`Route-dependent cache controls are not safely disabled without Routes: ${JSON.stringify(editorStateContract)}`);
    }
  }

  let actionErrorContract = null;
  if (fixtureRoot) {
    actionErrorContract = await cdp.evaluate(`(async () => {
      const originalFetch = window.fetch;
      const originalPolicies = state.policies;
      const originalSelectedPolicy = state.selectedPolicy;
      const originalBans = state.bans;
      const failureMessage = 'fixture action failure';
      const waitForToast = async () => {
        const deadline = performance.now() + 1000;
        while (performance.now() < deadline) {
          if (document.getElementById('toast').textContent === failureMessage) return failureMessage;
          await new Promise(resolve => setTimeout(resolve, 10));
        }
        return document.getElementById('toast').textContent;
      };
      const resetToast = () => { document.getElementById('toast').textContent = ''; };
      const results = {};
      window.fetch = async () => new Response(JSON.stringify({error:{message:failureMessage}}), {status:500,headers:{'Content-Type':'application/json'}});
      try {
        state.bans = [{client:'203.0.113.7', banned_until:new Date(Date.now()+60000).toISOString(), violations:3}];
        renderBans();
        resetToast(); document.querySelector('[data-unban]').click(); results.unban = await waitForToast();

        resetToast(); document.getElementById('clear-security').click(); results.clearSecurity = await waitForToast();
        resetToast(); document.getElementById('clear-bans').click(); results.clearBans = await waitForToast();

        state.policies = structuredClone(originalPolicies);
        state.selectedPolicy = ${JSON.stringify(expectedRoute)};
        state.policyDirty = false;
        renderPolicies();
        resetToast(); document.getElementById('delete-override').click(); results.deletePolicy = await waitForToast();

        resetToast(); document.getElementById('reload-config').click(); results.reloadConfig = await waitForToast();
        resetToast(); document.getElementById('refresh-control').click(); results.refreshControl = await waitForToast();

        state.policies = null;
        resetToast(); setView('policies'); results.loadPolicies = await waitForToast();
        return results;
      } finally {
        window.fetch = originalFetch;
        state.policies = originalPolicies;
        state.selectedPolicy = originalSelectedPolicy;
        state.policyDirty = false;
        state.bans = originalBans;
        renderPolicies();
        renderBans();
      }
    })()`, true);
    const failedActions = Object.entries(actionErrorContract).filter(([, message]) => message !== 'fixture action failure');
    if (failedActions.length) {
      throw new Error(`Control-plane action failures are not consistently surfaced to the operator: ${JSON.stringify(actionErrorContract)}`);
    }
  }

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
  let accessibilityContract = null;
  if (fixtureRoot) {
    accessibilityContract = await cdp.evaluate(`(() => {
      const selectors='button,input:not([type="hidden"]),select,textarea,a[href]';
      const controls=[...document.querySelectorAll(selectors)];
      const visibleControls=controls.filter(node => {
        const style=getComputedStyle(node);
        const rect=node.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
      });
      const missing=controls.filter(node => {
        const aria=(node.getAttribute('aria-label') || '').trim();
        if (aria) return false;
        const labelledBy=(node.getAttribute('aria-labelledby') || '').trim();
        if (labelledBy) {
          const text=labelledBy.split(/\s+/).map(id => document.getElementById(id)?.textContent?.trim() || '').join(' ').trim();
          if (text) return false;
        }
        const labels=node.labels ? [...node.labels].map(label => label.textContent.trim()).join(' ').trim() : '';
        if (labels) return false;
        const title=(node.getAttribute('title') || '').trim();
        if (title) return false;
        if (node.matches('button,a[href]') && node.textContent.trim()) return false;
        if (node.matches('input[type="button"],input[type="submit"],input[type="reset"]') && node.value.trim()) return false;
        return true;
      }).map(node => ({
        tag:node.tagName.toLowerCase(), id:node.id || '', type:node.getAttribute('type') || '',
        name:node.getAttribute('name') || '', className:typeof node.className === 'string' ? node.className : ''
      }));
      return {total:controls.length, visible:visibleControls.length, missing};
    })()`);
    if (accessibilityContract.missing.length) {
      throw new Error(`Interactive controls without accessible names: ${JSON.stringify(accessibilityContract)}`);
    }
  }

  await sleep(500);
  if (exceptions.length) throw new Error(`Browser console/runtime errors: ${exceptions.join(' | ')}`);

  console.log(JSON.stringify({
    ok:true, mode, browser, url:fixtureRoot ? 'fixture://dashboard' : url,
    title:contract.title, route:routeEditor.name, algorithm:routeEditor.algorithm,
    cache_route_options:cacheOptions, system_forms_populated:true, system_form_submission:systemFormSubmission, live_mutations_skipped:!fixtureRoot,
    refresh_coalescing:refreshCoalescing, mobile_nav_layouts:mobileNavLayouts, responsive_layouts:responsiveLayouts, mobile_dialog_layouts:mobileDialogLayouts,
    route_editor_layout:routeEditorLayout, origin_dialog_layout:originDialogLayout, telemetry_detail_layout:telemetryDetailLayout,
    raw_config_layout:rawConfigLayout, system_header_layout:systemHeaderLayout,
    login_brand_layout:loginBrandLayout, sidebar_brand_layout:sidebarBrandLayout,
    sidebar_layout:sidebarLayout, overview_topology_layout:overviewTopologyLayout, theme_contract:themeContract,
    semantic_color_contract:semanticColorContract, topbar_layouts:topbarLayouts, security_explorer_layouts:securityExplorerLayouts,
    connectivity_action_layout:connectivityActionLayout,
    connectivity_responsive_layouts:connectivityResponsiveLayouts, accessibility_contract:accessibilityContract,
    authentication_ui_contract:authenticationUIContract, telemetry_availability_contract:telemetryAvailabilityContract,
    client_facing_error_contract:clientFacingErrorContract, client_canceled_request_contract:clientCanceledRequestContract, telemetry_trend_gap_contract:telemetryTrendGapContract,
    undefined_metric_rendering_contract:undefinedMetricRenderingContract, editor_state_contract:editorStateContract, action_error_contract:actionErrorContract
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
