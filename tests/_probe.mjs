import { spawn } from 'node:child_process';
import path from 'node:path';
import { chromium } from 'playwright-core';
const ROOT = '/Users/macmini/WorkBuddy AI/2026-10-25-08-42-00/webssh';
const PORT = 8789;
const dev = spawn(process.execPath, [path.join(ROOT,'node_modules/wrangler/bin/wrangler.js'),'dev','--port',String(PORT),'--ip','127.0.0.1','--persist-to','/tmp/webssh-e2e-state'], {cwd:ROOT, env:{...process.env,NO_COLOR:'1',CI:'1',WRANGLER_SEND_METRICS:'false'}, stdio:['ignore','pipe','pipe']});
await new Promise((res,rej)=>{let b='';const t=setTimeout(()=>rej(new Error(b)),90000);dev.stdout.on('data',c=>{b+=c;if(/Ready on/.test(b)){clearTimeout(t);res();}});});
const browser = await chromium.launch({ executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless:true });
const page = await (await browser.newContext()).newPage();
page.on('pageerror', e=>console.log('PAGEERR', e.message));
page.on('console', m=>console.log('CONSOLE', m.type(), m.text()));
await page.goto('http://127.0.0.1:'+PORT, {waitUntil:'domcontentloaded'});
await page.waitForTimeout(2500);
console.log('state', JSON.stringify(await page.evaluate(()=>fetch('/api/state').then(r=>r.json()))));
console.log('views', JSON.stringify(await page.evaluate(()=>({
  auth: !document.getElementById('view-auth').hidden,
  dash: !document.getElementById('view-dash').hidden,
  term: !document.getElementById('view-term').hidden,
  boot: !!document.getElementById('boot'),
  setupHidden: document.getElementById('form-setup').hidden,
  loginHidden: document.getElementById('form-login').hidden,
  bodyText: document.body.innerText.slice(0,200),
}))));
await browser.close(); dev.kill('SIGTERM');
