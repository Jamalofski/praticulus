#!/usr/bin/env node
// ── Network guard for tool pages ─────────────────────────────────────────────
//
// Checks that no tool page sends what the user types, pastes or uploads into it.
// It backs the claim made on praticulus.com: "nothing leaves your browser,
// verifiable in DevTools → Network". It runs before every deployment of the site;
// a violation cancels the deployment. Published at https://praticulus.com/network-test/
//
// Each page is served from the site folder by a local server, loaded in headless
// Chromium, then EXERCISED: every visible field is filled with a marker, every button
// is clicked (fields filled again before each click), every <input type=file> gets a
// file that carries the marker. The page is finally reloaded, to catch anything kept
// in localStorage and sent on the next load. Nothing leaves the machine: every request
// to another host than the local server is intercepted and answered with a 204.
//
// The rule is not "zero requests": every page loads its own assets and error-reporter.js.
//   1. no request carries the marker (URL or body; raw, URL-encoded or base64);
//   2. no request goes to another origin than the site (error-reporter.js's beacon
//      included: it only fires on a JS error, and there is none on the normal path —
//      if it fires, the page has an error, and its message is shown);
//   3. no request is triggered by the interaction, except the deferred loading of an
//      asset of the site: GET of a file that exists, of type script, stylesheet, font
//      or image, with no parameter other than a ?v= cache key. fetch, XHR, sendBeacon,
//      WebSocket, navigation: always a violation after load;
//   4. no request other than GET, at any time.
//
// Pages: the `type: "tool"` entries of the registry.json next to network-guard.json
// (or the `pages` list of the latter). Its `inputs` set, per page, the value of a field
// that a bare marker cannot make work (a JWT, a certificate); a selector that cannot be
// found is an error, not a skipped field.
//
// Exit codes: 0 = compliant, 1 = violation (the deployment is cancelled), 2 = the guard
// could NOT check (playwright-core or Chromium missing, page that does not load, page
// where nothing could be exercised, wrong configuration). A 2 does not block a
// deployment, but it says so: a page that was not exercised is not a compliant page.
// Console output is in French: "conformes" = compliant, "INEXPLOITABLE" = not checked.
//
// Usage:
//   node network-guard.mjs <served folder> [--config <network-guard.json>] [--only /a/,/b/]
// Browser: the one installed by playwright-core (~/.cache/ms-playwright), or an installed
// browser with NETWORK_GUARD_CHANNEL=chrome (or msedge).

import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, resolve, dirname, extname, sep } from 'node:path';

// Dynamic import: without playwright-core, exit with 2, distinct from a violation.
let chromium;
try {
  ({ chromium } = await import('playwright-core'));
} catch {
  console.error('  network-guard: playwright-core introuvable — controle IMPOSSIBLE (npm install manquant ?)');
  process.exit(2);
}

const CANARY = 'QZNETGUARDCANARY';          // letters only: valid in base32 (TOTP), in text, in an identifier
const PAGE_TIMEOUT = 15000;
// Budget for the whole run: past it, the guard stops with 2 rather than letting a
// caller with its own time limit kill it.
const GLOBAL_TIMEOUT = Number(process.env.NETWORK_GUARD_BUDGET_MS) || 75000;
const JOBS = Number(process.env.NETWORK_GUARD_JOBS) || 4;     // pages checked in parallel
const MAX_CLICKS = 60;
// Quiet network: no request in flight for QUIET_MS. After the exercise, wait SETTLE_MS
// more, for a send delayed by a setTimeout or a debounce.
const QUIET_MS = 150;
const SETTLE_MS = 1000;
const ASSET_TYPES = new Set(['script', 'stylesheet', 'font', 'image']);
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.mjs': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.txt': 'text/plain', '.xml': 'application/xml',
};

function fail(msg) {
  console.error(`  network-guard: ${msg} — controle IMPOSSIBLE`);
  process.exit(2);
}
// An unexpected exception would exit with 1, read by the caller as a violation: it is
// a failure of the guard, so it exits with 2.
process.on('uncaughtException', (e) => fail(`erreur interne : ${e.stack || e}`));
process.on('unhandledRejection', (e) => fail(`erreur interne : ${(e && e.stack) || e}`));

// ── Arguments and configuration ──────────────────────────────
const argv = process.argv.slice(2);
let root = null, configPath = null, only = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--config') configPath = argv[++i];
  else if (argv[i] === '--only') only = argv[++i].split(',').filter(Boolean);
  else if (!root) root = argv[i];
  else fail(`argument inattendu : ${argv[i]}`);
}
if (!root) fail('usage : node network-guard.mjs <dossier servi> [--config <fichier>] [--only /a/,/b/]');
root = resolve(root);
if (!existsSync(root) || !statSync(root).isDirectory()) fail(`dossier introuvable : ${root}`);
configPath = resolve(configPath || join(dirname(root), 'network-guard.json'));

let config;
try {
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (e) {
  fail(`configuration illisible (${configPath}) : ${e.message}`);
}

let pages = config.pages;
if (pages === undefined || pages === 'registry') {
  const registryPath = join(dirname(configPath), 'registry.json');
  try {
    pages = JSON.parse(readFileSync(registryPath, 'utf8')).tools
      .filter((t) => t.type === 'tool').map((t) => t.url);
  } catch (e) {
    fail(`liste des pages illisible (${registryPath}) : ${e.message}`);
  }
}
if (!Array.isArray(pages) || pages.length === 0) fail('aucune page outil a controler');
const inputs = config.inputs || {};
for (const p of Object.keys(inputs)) {
  if (!pages.includes(p)) fail(`inputs["${p}"] ne correspond a aucune page controlee`);
}
if (only) {
  for (const p of only) if (!pages.includes(p)) fail(`--only : ${p} n'est pas une page controlee`);
  pages = pages.filter((p) => only.includes(p));
}

// ── Marker detection ─────────────────────────────────────────
// Raw and URL-encoded forms are searched in the decoded text, case-insensitive (a case
// tool transforms it). In base64 (and base64url), the encoding depends on the marker's
// offset in the encoded text: the three alignments are searched, edges trimmed.
const needles = [CANARY.toLowerCase()];
for (let shift = 0; shift < 3; shift++) {
  for (const word of [CANARY, CANARY.toLowerCase()]) {
    const b64 = Buffer.from('\0'.repeat(shift) + word).toString('base64');
    const start = Math.ceil((shift * 4) / 3) + 1;
    const core = b64.slice(start, b64.length - 4);
    needles.push(core, core.replace(/\+/g, '-').replace(/\//g, '_'));
  }
}

function carriesCanary(text) {
  if (!text) return false;
  let decoded = text;
  try { decoded = decodeURIComponent(text.replace(/\+/g, ' ')); } catch { /* raw text */ }
  const lower = decoded.toLowerCase();
  if (lower.includes(needles[0])) return true;
  return needles.slice(1).some((n) => text.includes(n) || decoded.includes(n));
}

// ── Files for <input type=file> ──────────────────────────────
// Valid 1x1 PNG carrying the marker in a tEXt chunk: an image tool reads it, and if
// its bytes are sent, the marker goes with them.
function pngWithCanary() {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
  const idat = Buffer.from('78da63f8cf000003010100c9fe92ef', 'hex'); // one RGBA pixel, zlib
  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    chunk('IHDR', ihdr), chunk('tEXt', Buffer.from(`Comment\0${CANARY}`, 'latin1')),
    chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0)),
  ]);
}
function crc32(buf) {
  let c = ~0;
  for (const b of buf) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return ~c >>> 0;
}
const PNG = pngWithCanary();

function fileFor(accept, pageInputs) {
  const a = (accept || '').toLowerCase();
  if (/image/.test(a) || /\.(png|jpe?g|webp|gif)/.test(a)) {
    return { name: 'canary.png', mimeType: 'image/png', buffer: PNG };
  }
  const ext = (a.match(/\.[a-z0-9]+/) || ['.txt'])[0];
  const body = pageInputs['@file'] || CANARY;
  return { name: `canary${ext}`, mimeType: 'text/plain', buffer: Buffer.from(body.replaceAll('{CANARY}', CANARY)) };
}

// ── Local server for the folder ──────────────────────────────
function serve() {
  return new Promise((ok, ko) => {
    const server = createServer((req, res) => {
      let path;
      try { path = decodeURIComponent(new URL(req.url, 'http://x').pathname); } catch { path = '/'; }
      let file = join(root, path);
      if (!file.startsWith(root + sep) && file !== root) { res.writeHead(400).end(); return; }
      if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
      // An empty 404 makes page.goto() fail in Chrome stable (ERR_HTTP_RESPONSE_CODE_FAILURE):
      // with a body, the page loads and its status can be read.
      if (!existsSync(file) || !statSync(file).isFile()) { res.writeHead(404).end('404'); return; }
      res.writeHead(200, { 'Content-Type': MIME[extname(file).toLowerCase()] || 'application/octet-stream' });
      res.end(readFileSync(file));
    });
    server.on('error', ko);
    server.listen(0, '127.0.0.1', () => ok(server));
  });
}

// ── Judging a request ────────────────────────────────────────
function judge(r, origin) {
  const reasons = [];
  if (carriesCanary(r.url) || carriesCanary(r.body)) reasons.push('porte la saisie');
  let u;
  try { u = new URL(r.url); } catch { u = null; }
  const local = u && u.origin === origin;
  if (!local) {
    reasons.push(r.beacon ? `origine tierce (beacon d'error-reporter : ${r.beacon})` : 'origine tierce');
  }
  if (r.method !== 'GET') reasons.push(`methode ${r.method}`);
  if (r.type === 'websocket') reasons.push('WebSocket');
  if (r.phase === 'interaction' && local) {
    const extra = [...u.searchParams.keys()].filter((k) => k !== 'v');
    const asset = ASSET_TYPES.has(r.type) && r.status === 200 && extra.length === 0;
    // Chromium fetches the tab icon again when the page rewrites its URL (replaceState,
    // share hash): a request from the browser, not the page, carrying nothing typed.
    const favicon = r.type === 'other' && /^\/favicon\.(svg|ico|png)$/.test(u.pathname) && !u.search && r.status === 200;
    if (!asset && !favicon) reasons.push(`declenchee par l'interaction (${r.type})`);
  }
  return reasons;
}

// ── Exercising a page ────────────────────────────────────────
async function fillAll(page, pageInputs) {
  // Values set by the configuration: a missing selector is an error.
  const fixed = Object.entries(pageInputs).filter(([sel]) => !sel.startsWith('@'));
  const done = new Set();
  for (const [sel, value] of fixed) {
    const loc = page.locator(sel);
    if ((await loc.count()) === 0) throw new Error(`inputs : selecteur introuvable ${sel}`);
    if (await loc.first().isVisible()) {
      await loc.first().fill(value.replaceAll('{CANARY}', CANARY), { timeout: 2000 }).catch(() => {});
    }
    done.add(sel);
  }
  // Everything else: every visible, editable field.
  return page.evaluate(({ canary, fixedSel }) => {
    const skip = new Set(fixedSel.flatMap((s) => [...document.querySelectorAll(s)]));
    const set = (el, v) => {
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    let n = 0;
    for (const el of document.querySelectorAll('textarea, input, [contenteditable=""], [contenteditable="true"]')) {
      if (skip.has(el) || el.disabled || el.readOnly) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue;
      if (getComputedStyle(el).visibility === 'hidden') continue;
      if (el.isContentEditable) { el.textContent = canary; el.dispatchEvent(new Event('input', { bubbles: true })); n++; continue; }
      const t = (el.type || 'text').toLowerCase();
      if (['text', 'search', 'url', 'email', 'tel', 'password'].includes(t) || el.tagName === 'TEXTAREA') set(el, canary);
      else if (t === 'number') set(el, '7');
      else if (t === 'color') set(el, '#3a7bd5');
      else continue;
      n++;
    }
    return n;
  }, { canary: CANARY, fixedSel: [...done] }).then((n) => n + done.size);
}

async function exercise(page, pageInputs) {
  let actions = 0;
  // Files: every <input type=file>, hidden ones included, and the chooser opened by a button.
  page.on('filechooser', async (fc) => {
    const accept = await fc.element().getAttribute('accept').catch(() => null);
    await fc.setFiles(fileFor(accept, pageInputs)).catch(() => {});
  });
  const fileInputs = page.locator('input[type=file]');
  for (let i = 0; i < (await fileInputs.count()); i++) {
    const el = fileInputs.nth(i);
    const accept = await el.getAttribute('accept');
    await el.setInputFiles(fileFor(accept, pageInputs)).then(() => actions++).catch(() => {});
  }
  actions += await fillAll(page, pageInputs);
  // @expect: the tool's output must show the marker at least once, proof that the
  // success path ran and not only the error message.
  const expectSel = pageInputs['@expect'];
  let shown = !expectSel;
  const check = async () => {
    if (shown) return;
    shown = await page.locator(expectSel).evaluateAll((els, c) => els.some((el) =>
      ((el.innerText || '') + ' ' + (el.value || '')).toLowerCase().includes(c)), CANARY.toLowerCase()).catch(() => false);
  };
  await check();
  // Dropdowns: the last option of each (another format, another mode).
  const selects = page.locator('select:visible');
  for (let i = 0; i < (await selects.count()); i++) {
    const values = await selects.nth(i).locator('option').evaluateAll((os) => os.map((o) => o.value));
    if (values.length > 1) await selects.nth(i).selectOption(values[values.length - 1], { timeout: 2000 }).then(() => actions++).catch(() => {});
  }
  // Buttons, checkboxes and radios: each one, fields filled again before each click (a
  // "Clear" does not empty the tool for the next ones). Re-read each turn: a click changes the DOM.
  for (let i = 0; i < MAX_CLICKS; i++) {
    const targets = page.locator('main button:visible, main [role=button]:visible, main input[type=checkbox]:visible, main input[type=radio]:visible, main input[type=button]:visible, main input[type=submit]:visible');
    const count = await targets.count();
    if (i >= count) break;
    await fillAll(page, pageInputs);
    await targets.nth(i).click({ timeout: 500, noWaitAfter: true }).then(() => actions++).catch(() => {});
    await page.waitForTimeout(40);
    await check();
  }
  if (!shown) throw new Error(`@expect : ${expectSel} n'a jamais affiche le marqueur, l'outil n'a pas ete exerce (entree a revoir)`);
  return actions;
}

// ── Run ──────────────────────────────────────────────────────
const watchdog = setTimeout(() => fail(`delai de ${GLOBAL_TIMEOUT / 1000} s depasse (NETWORK_GUARD_BUDGET_MS)`), GLOBAL_TIMEOUT);

const server = await serve();
const origin = `http://127.0.0.1:${server.address().port}`;
const channel = process.env.NETWORK_GUARD_CHANNEL || undefined;
let browser;
try {
  browser = await chromium.launch({ channel, args: ['--no-sandbox'] });
} catch (e) {
  server.close();
  fail(`Chromium ne demarre pas (${channel || 'playwright-core'}) : ${e.message.split('\n')[0]}`);
}
console.log(`  network-guard: ${pages.length} pages, ${channel || 'chromium'} ${browser.version()}, marqueur ${CANARY}`);

async function checkPage(path) {
  const pageInputs = inputs[path] || {};
  const context = await browser.newContext({ acceptDownloads: true });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin }).catch(() => {});
  const requests = [];
  const byRequest = new Map();
  let phase = 'chargement';
  let pending = 0, lastActivity = Date.now();

  // Every request is recorded, workers' included; anything not local is never sent and
  // gets a 204.
  await context.route('**/*', (route) => {
    if (route.request().url().startsWith(origin + '/')) return route.continue().catch(() => {});
    return route.fulfill({ status: 204, body: '' }).catch(() => {});   // context already closed: nothing to do
  });
  // WebSockets escape route(): intercepted here, recorded, never connected.
  await context.routeWebSocket(/.*/, (ws) => {
    requests.push({ phase, url: ws.url(), method: 'GET', type: 'websocket', body: '' });
    ws.close().catch(() => {});
  });
  context.on('request', (req) => {
    const body = req.postDataBuffer();
    const r = { phase, url: req.url(), method: req.method(), type: req.resourceType(), body: body ? body.toString('latin1') : '', status: null };
    if (r.type === 'ping' || /\/api\/logs\/client$/.test(r.url)) {
      try { r.beacon = JSON.parse(body.toString('utf8')).m; } catch { r.beacon = '?'; }
    }
    byRequest.set(req, r);
    requests.push(r);
    pending++; lastActivity = Date.now();
  });
  const settle = async (req) => {
    const res = await req.response().catch(() => null);
    if (byRequest.has(req) && res) byRequest.get(req).status = res.status();
    pending--; lastActivity = Date.now();
  };
  context.on('requestfinished', settle);
  context.on('requestfailed', settle);

  const page = await context.newPage();
  page.on('dialog', (d) => d.dismiss().catch(() => {}));
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(e.message));
  const quiet = async (extra = 0) => {
    await page.waitForTimeout(extra);
    const limit = Date.now() + PAGE_TIMEOUT;
    while ((pending > 0 || Date.now() - lastActivity < QUIET_MS) && Date.now() < limit) await page.waitForTimeout(50);
  };

  let actions = 0, problem = null;
  try {
    const res = await page.goto(origin + path, { waitUntil: 'load', timeout: PAGE_TIMEOUT });
    if (!res || res.status() !== 200) throw new Error(`HTTP ${res ? res.status() : '?'}`);
    await quiet();
    phase = 'interaction';
    actions = await exercise(page, pageInputs);
    await quiet(SETTLE_MS);
    // Reload: what was kept (localStorage) and sent again on the next load.
    phase = 'rechargement';
    if (page.url().startsWith(origin + path)) {
      await page.reload({ waitUntil: 'load', timeout: PAGE_TIMEOUT });
      await quiet();
    }
  } catch (e) {
    problem = e.message.split('\n')[0];
  }
  await context.close();

  const lines = [];
  const bad = [];
  for (const r of requests) {
    const why = judge({ ...r, phase: r.phase === 'interaction' ? 'interaction' : 'load' }, origin);
    if (why.length) bad.push(`      [${r.phase}] ${r.method} ${r.url.slice(0, 160)} — ${why.join(', ')}`);
  }
  const loaded = requests.filter((r) => r.phase === 'chargement').length;
  const after = requests.filter((r) => r.phase === 'interaction').length;
  let verdict;
  if (bad.length) {
    verdict = 'violation';
    lines.push(`  VIOLATION ${path} (${bad.length} requete(s))`, ...bad);
    if (problem) lines.push(`      (et la page n'a pas ete exercee jusqu'au bout : ${problem})`);
  } else if (problem || actions === 0) {
    verdict = 'blind';
    lines.push(`  INEXPLOITABLE ${path} : ${problem || 'aucun champ ni bouton exerce'}`);
  } else {
    verdict = 'ok';
    lines.push(`  ok ${path} — ${loaded} requetes au chargement, ${actions} actions, ${after} requete(s) apres interaction`);
  }
  if (pageErrors.length) lines.push(`      erreurs JS : ${[...new Set(pageErrors)].slice(0, 3).join(' | ')}`);
  return { verdict, lines };
}

// Pages in parallel (JOBS isolated tabs), output in list order.
const results = new Array(pages.length);
let next = 0;
await Promise.all(Array.from({ length: Math.min(JOBS, pages.length) }, async () => {
  while (next < pages.length) {
    const i = next++;
    results[i] = await checkPage(pages[i]);
  }
}));
results.forEach((r) => r.lines.forEach((l) => console.log(l)));

await browser.close();
server.close();
clearTimeout(watchdog);

const violations = results.filter((r) => r.verdict === 'violation').length;
const blind = results.filter((r) => r.verdict === 'blind').length;
console.log(`  network-guard: ${pages.length - violations - blind}/${pages.length} conformes, ${violations} en violation, ${blind} inexploitable(s)`);
process.exit(violations ? 1 : blind ? 2 : 0);
