// throwaway: screenshot every modal for visual review
import { spawn } from 'node:child_process';
import path from 'node:path';
import { chromium } from 'playwright-core';

const ROOT = '/Users/macmini/WorkBuddy AI/2026-10-25-08-42-00/webssh';
const PORT = 8788;
const BASE = 'http://127.0.0.1:' + PORT;
const STATE = '/tmp/webssh-e2e-state';

const dev = spawn(process.execPath, [path.join(ROOT, 'node_modules/wrangler/bin/wrangler.js'), 'dev', '--port', String(PORT), '--ip', '127.0.0.1', '--persist-to', STATE], {
    cwd: ROOT,
    env: { ...process.env, NO_COLOR: '1', CI: '1', WRANGLER_SEND_METRICS: 'false' },
    stdio: ['ignore', 'pipe', 'pipe'],
});
await new Promise((res, rej) => {
    let buf = '';
    const t = setTimeout(() => rej(new Error('timeout\n' + buf)), 90000);
    dev.stdout.on('data', (c) => {
        buf += c;
        if (/Ready on/.test(buf)) {
            clearTimeout(t);
            res();
        }
    });
});

const browser = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 })).newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(e.message));
page.on('console', (m) => m.type() === 'error' && errs.push(m.text()));

await page.goto(BASE, { waitUntil: 'domcontentloaded' });
await page.waitForSelector('#form-login:not([hidden]), #form-setup:not([hidden]), #view-dash:not([hidden])', { timeout: 15000 });
if (await page.locator('#form-login:not([hidden])').isVisible().catch(() => false)) {
    await page.fill('#form-login input[name="username"]', 'admin');
    await page.fill('#form-login input[name="password"]', 'sup3r-secret');
    await page.click('#form-login button[type="submit"]');
}
await page.waitForSelector('#view-dash:not([hidden])', { timeout: 15000 });

const shot = async (name) => {
    await page.waitForTimeout(450);
    await page.screenshot({ path: '/tmp/shots/' + name + '.png' });
    console.log('shot ' + name);
};
const closeModal = async () => {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
};

// host editor (edit existing)
await page.locator('.host-row', { hasText: 'demo-server' }).locator('.act').nth(1).click();
await shot('modal-host');
await closeModal();

// snippets
await page.click('.rail-item[data-nav="snippets"]');
await shot('modal-snippets');
await page.click('.modal-foot .btn');
await shot('modal-snippet-edit');
await closeModal();
await closeModal();

// quick connect
await page.click('.rail-item[data-nav="quick"]');
await shot('modal-quick');
await closeModal();

// known keys
await page.click('.rail-item[data-nav="known"]');
await shot('modal-known');
await closeModal();

// settings
await page.click('.rail-item[data-nav="settings"]');
await shot('modal-settings');
await closeModal();

// logs (from a host row)
await page.locator('.host-row', { hasText: 'demo-server' }).locator('.act').nth(2).click();
await shot('modal-logs');
await closeModal();

// mobile-ish viewport
await page.setViewportSize({ width: 900, height: 820 });
await shot('dash-900');
await page.setViewportSize({ width: 420, height: 820 });
await shot('dash-420');

console.log('errors:', errs.length ? errs : 'none');
await browser.close();
dev.kill('SIGTERM');
