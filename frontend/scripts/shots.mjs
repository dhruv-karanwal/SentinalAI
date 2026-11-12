// Screenshot runner for the per-screen design loop (DESIGN.md section 8). No dependencies:
// it drives a headless Chrome or Edge that is already on the machine over the DevTools protocol.
//
//   node scripts/shots.mjs steps.json [out-dir]
//
// Needs the dev server (npm run dev) and the API. Signs in with SENTINEL_UI_USER (default
// ui-analyst) and SENTINEL_UI_DEV_PASSWORD from the environment; nothing is read from argv.
// A step is one of:
//   {"goto": "#/incidents"}            {"wait": 500}
//   {"key": "j", "times": 3}           {"key": "Enter"}  {"key": "Tab", "shift": true}
//   {"eval": "js expression"}          {"report": "label", "expr": "js expression"}
//   {"theme": "light"}                 {"density": "comfortable"}
//   {"size": [1366, 768]}              {"shot": "incidents-dark"}
//   {"signin": "ui-manager"}           (signs out first if needed)
//   {"signout": true}                 back to the sign-in page
//   {"motion": "reduce"}              emulates prefers-reduced-motion
//   {"tabwalk": 12}                    presses Tab N times; prints each focused element and its outline

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const BROWSERS = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].filter(Boolean);

const stepsFile = process.argv[2];
const outDir = resolve(process.argv[3] ?? 'shots');
if (!stepsFile) {
  console.error('usage: node scripts/shots.mjs steps.json [out-dir]');
  process.exit(2);
}
const steps = JSON.parse(readFileSync(stepsFile, 'utf8'));
const base = process.env.SENTINEL_UI_URL ?? 'http://127.0.0.1:5173/';
const password = process.env.SENTINEL_UI_DEV_PASSWORD ?? '';
if (!password) {
  console.error('set SENTINEL_UI_DEV_PASSWORD in the environment');
  process.exit(2);
}
const exe = BROWSERS.find((p) => existsSync(p));
if (!exe) {
  console.error('no Chrome or Edge found; set CHROME_PATH');
  process.exit(2);
}
mkdirSync(outDir, { recursive: true });

const port = 9300 + Math.floor(Math.random() * 400);
const profile = mkdtempSync(join(tmpdir(), 'sentinel-shots-'));
const chrome = spawn(exe, [
  '--headless=new',
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-extensions',
  '--hide-scrollbars=false',
  '--window-size=1366,768',
  'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pageSocket() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      // not listening yet
    }
    await sleep(200);
  }
  throw new Error('the browser did not open a debugging port');
}

let nextId = 1;
const pending = new Map();
let ws;

function send(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((ok, fail) => pending.set(id, { ok, fail, method }));
}

async function evaluate(expression) {
  const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (res.exceptionDetails) throw new Error(`eval failed: ${res.exceptionDetails.exception?.description ?? res.exceptionDetails.text}`);
  return res.result.value;
}

const KEYS = {
  Enter: { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' },
  Escape: { key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 },
  Tab: { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 },
  ArrowDown: { key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40 },
  ArrowUp: { key: 'ArrowUp', code: 'ArrowUp', windowsVirtualKeyCode: 38 },
  ArrowLeft: { key: 'ArrowLeft', code: 'ArrowLeft', windowsVirtualKeyCode: 37 },
  ArrowRight: { key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 },
  End: { key: 'End', code: 'End', windowsVirtualKeyCode: 35 },
  Home: { key: 'Home', code: 'Home', windowsVirtualKeyCode: 36 },
};

async function press(key, shift = false) {
  const def = KEYS[key] ?? { key, text: key, windowsVirtualKeyCode: key.toUpperCase().charCodeAt(0) };
  const modifiers = shift ? 8 : 0;
  await send('Input.dispatchKeyEvent', { type: def.text ? 'keyDown' : 'rawKeyDown', modifiers, ...def });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', modifiers, key: def.key, code: def.code, windowsVirtualKeyCode: def.windowsVirtualKeyCode });
}

const setInput = (id, value) => `(() => {
  const el = document.getElementById(${JSON.stringify(id)});
  if (!el) return false;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, ${JSON.stringify(value)});
  el.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`;

async function signIn(user) {
  const out = await evaluate(`(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === 'Sign out'); if (b) b.click(); return !!b; })()`);
  if (out) await sleep(200);
  if (!(await evaluate(setInput('si-user', user)))) throw new Error('sign-in form not found');
  await evaluate(setInput('si-pass', password));
  await evaluate(`(document.querySelector('.login-form button[type=submit]') ?? document.querySelector('.signin button[type=submit]')).click()`);
  for (let i = 0; i < 50; i++) {
    if (await evaluate(`!!document.querySelector('.shell')`)) return;
    await sleep(200);
  }
  throw new Error(`sign-in as ${user} failed: ${await evaluate(`document.querySelector('[role=alert]')?.textContent ?? 'no message'`)}`);
}

async function run() {
  ws = new WebSocket(await pageSocket());
  await new Promise((ok, fail) => {
    ws.addEventListener('open', ok);
    ws.addEventListener('error', fail);
  });
  const consoleErrors = [];
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.fail(new Error(`${p.method}: ${msg.error.message}`));
      else p.ok(msg.result);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      consoleErrors.push(msg.params.exceptionDetails.exception?.description ?? msg.params.exceptionDetails.text);
    } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
    }
  });
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 1366, height: 768, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base });
  await sleep(1500);
  await signIn(process.env.SENTINEL_UI_USER ?? 'ui-analyst');

  for (const step of steps) {
    if (step.goto !== undefined) {
      await evaluate(`window.location.hash = ${JSON.stringify(step.goto)}`);
      await sleep(step.wait ?? 600);
    } else if (step.signout) {
      await evaluate(`(() => { const b = [...document.querySelectorAll('button')].find(x => x.textContent.trim() === 'Sign out'); if (b) b.click(); })()`);
      await sleep(step.wait ?? 400);
    } else if (step.signin) {
      await signIn(step.signin);
    } else if (step.key) {
      for (let i = 0; i < (step.times ?? 1); i++) await press(step.key, step.shift === true);
      await sleep(step.wait ?? 150);
    } else if (step.eval) {
      await evaluate(step.eval);
      await sleep(step.wait ?? 150);
    } else if (step.tabwalk) {
      const seen = [];
      for (let i = 0; i < step.tabwalk; i++) {
        await press('Tab');
        await sleep(60);
        seen.push(await evaluate(`(() => { const e = document.activeElement; if (!e || e === document.body) return 'BODY'; const s = getComputedStyle(e); const name = (e.getAttribute('aria-label') || e.textContent || e.id || '').trim().split(' ').filter(Boolean).join(' ').slice(0, 28); return e.tagName.toLowerCase() + '[' + name + '] ' + (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) >= 2 ? 'ring' : 'NO-RING'); })()`));
      }
      console.log(`tabwalk: ${seen.join(' > ')}`);
    } else if (step.report) {
      console.log(`${step.report}: ${JSON.stringify(await evaluate(step.expr))}`);
    } else if (step.theme) {
      await evaluate(`(() => { if (document.documentElement.dataset.theme !== ${JSON.stringify(step.theme)}) document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 't', bubbles: true })); })()`);
      await sleep(200);
    } else if (step.density) {
      await evaluate(`(() => { if (document.documentElement.dataset.density !== ${JSON.stringify(step.density)}) document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'd', bubbles: true })); })()`);
      await sleep(200);
    } else if (step.motion) {
      // {"motion": "reduce"} or {"motion": "no-preference"}: emulates prefers-reduced-motion
      await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: step.motion }] });
      await sleep(200);
    } else if (step.size) {
      await send('Emulation.setDeviceMetricsOverride', { width: step.size[0], height: step.size[1], deviceScaleFactor: 1, mobile: false });
      await sleep(300);
    } else if (step.shot) {
      const { data } = await send('Page.captureScreenshot', { format: 'png' });
      const file = join(outDir, `${step.shot}.png`);
      writeFileSync(file, Buffer.from(data, 'base64'));
      console.log(`shot: ${file}`);
    } else if (step.wait) {
      await sleep(step.wait);
    }
  }
  console.log(`console errors: ${consoleErrors.length}`);
  for (const e of consoleErrors.slice(0, 10)) console.log(`  ${e.slice(0, 300)}`);
}

let code = 0;
try {
  await run();
} catch (err) {
  console.error(String(err));
  code = 1;
} finally {
  try {
    ws?.close();
  } catch {
    // already closed
  }
  chrome.kill();
  await sleep(300);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    // the profile directory can stay locked for a moment on Windows
  }
}
process.exit(code);
