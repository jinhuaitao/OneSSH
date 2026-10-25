// End-to-end test: real workerd (wrangler dev) + real Chrome + local SSH server.
//   node tests/e2e.mjs            headless
//   node tests/e2e.mjs --headful  watch it run
import { spawn } from 'node:child_process';
import { rm, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { startServer } from './ssh-server.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8787;
const BASE = 'http://127.0.0.1:' + PORT;
const STATE = '/tmp/webssh-e2e-state';
const SHOTS = path.join(ROOT, 'docs');
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const results = [];
function check(name, ok, detail) {
    results.push({ name, ok, detail });
    console.log((ok ? '  ok  ' : '  FAIL') + '  ' + name + (detail && !ok ? '  -> ' + detail : ''));
}

function waitFor(re, stream, label, timeout) {
    return new Promise((resolve, reject) => {
        let buf = '';
        const timer = setTimeout(() => reject(new Error(label + ' 超时\n' + buf.slice(-2000))), timeout || 90000);
        const onData = (chunk) => {
            buf += chunk.toString();
            if (re.test(buf)) {
                clearTimeout(timer);
                stream.off('data', onData);
                resolve(buf);
            }
        };
        stream.on('data', onData);
    });
}

async function main() {
    const headful = process.argv.includes('--headful');
    await rm(STATE, { recursive: true, force: true });
    await mkdir(SHOTS, { recursive: true });

    const ssh = await startServer(2222);
    console.log('· test ssh server on 127.0.0.1:2222');

    const wranglerBin = path.join(ROOT, 'node_modules/wrangler/bin/wrangler.js');
    if (!existsSync(wranglerBin)) throw new Error('wrangler 未安装，先执行 npm install');
    const dev = spawn(process.execPath, [wranglerBin, 'dev', '--port', String(PORT), '--ip', '127.0.0.1', '--persist-to', STATE], {
        cwd: ROOT,
        env: { ...process.env, NO_COLOR: '1', CI: '1', WRANGLER_SEND_METRICS: 'false' },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let devLog = '';
    dev.stdout.on('data', (c) => {
        devLog += c.toString();
    });
    dev.stderr.on('data', (c) => {
        devLog += c.toString();
    });
    try {
        await waitFor(/Ready on/, dev.stdout, 'wrangler dev 启动');
    } catch (e) {
        console.log(devLog.slice(-4000));
        throw e;
    }
    console.log('· wrangler dev ready on ' + BASE);

    const browser = await chromium.launch({ executablePath: CHROME, headless: !headful });
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
    page.on('console', (m) => {
        if (m.type() === 'error') errors.push('console: ' + m.text());
    });

    try {
        /* ------------------------------------------------------------ setup */
        await page.goto(BASE, { waitUntil: 'domcontentloaded' });
        await page.waitForSelector('#form-setup:not([hidden])', { timeout: 15000 });
        check('首次打开显示初始化表单', true);
        await page.waitForSelector('#boot', { state: 'detached', timeout: 5000 });
        await page.screenshot({ path: path.join(SHOTS, 'auth.png') });

        await page.fill('#form-setup input[name="username"]', 'admin');
        await page.fill('#form-setup input[name="password"]', 'sup3r-secret');
        await page.fill('#form-setup input[name="password2"]', 'sup3r-secret');
        await page.click('#form-setup button[type="submit"]');
        await page.waitForSelector('#view-dash:not([hidden])', { timeout: 15000 });
        check('初始化后进入总览页', true);
        check('空状态提示可见', await page.locator('.empty h3').isVisible());
        await page.screenshot({ path: path.join(SHOTS, 'dash-empty.png') });

        /* --------------------------------------------------------- add host */
        await page.click('#btn-add-host');
        await page.waitForSelector('.modal');
        await page.fill('.modal input[placeholder="例如 香港生产机"]', 'demo-server');
        await page.fill('.modal input[placeholder="例如 生产环境"]', '生产环境');
        await page.fill('.modal input[placeholder="192.0.2.10 或 example.com"]', '127.0.0.1');
        await page.fill('.modal input[type="number"]', '2222');
        await page.fill('.modal input[placeholder="root"]', 'demo');
        await page.locator('.modal input[type="password"]').first().fill('demo1234');
        await page.click('.country-pick button[data-code="HK"]');
        await page.click('.modal-foot .btn.primary');
        await page.waitForSelector('.host-row', { timeout: 15000 });
        check('主机已出现在列表', true);
        const rowText = await page.locator('.host-row').first().innerText();
        check('主机行显示 user@host:port', /demo@127\.0\.0\.1:2222/.test(rowText), rowText);
        check('主机行显示地区', /香港/.test(rowText), rowText);
        check('分组标题渲染', (await page.locator('.group-head b').first().innerText()) === '生产环境');
        check('地区筛选标签出现', (await page.locator('#filters .filter').count()) >= 2);
        check('底部统计更新', /1 台主机/.test(await page.locator('#dash-count').innerText()));

        // seed a few more hosts through the API so the docs screenshots look real
        await page.evaluate(async () => {
            const seed = [
                { name: 'tokyo-edge', group: '生产环境', host: '203.0.113.24', port: 22, username: 'deploy', authType: 'password', country: 'JP', city: '东京', color: '#2f6fb5' },
                { name: 'fra-backup', group: '备份', host: '198.51.100.9', port: 2222, username: 'root', authType: 'password', country: 'DE', city: '法兰克福', color: '#7c5cff' },
                { name: 'sg-lab', group: '实验', host: '192.0.2.77', port: 22, username: 'ubuntu', authType: 'password', country: 'SG', city: '新加坡', color: '#1f9d55' },
                { name: 'sfo-build', group: '实验', host: '192.0.2.88', port: 22, username: 'ci', authType: 'password', country: 'US', city: '圣何塞', color: '#c98a12' },
            ];
            for (const h of seed) {
                await fetch('/api/hosts', {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(h),
                });
            }
        });
        await page.click('#btn-refresh');
        await page.waitForFunction(() => document.querySelectorAll('.host-row').length === 5, { timeout: 10000 });
        await page.waitForTimeout(1200);
        await page.screenshot({ path: path.join(SHOTS, 'dashboard.png') });

        /* --------------------------------------------------------- snippets */
        await page.click('.rail-item[data-nav="snippets"]');
        await page.waitForSelector('.modal');
        await page.click('.modal-foot .btn');
        await page.waitForSelector('.modal input[placeholder="例如 查看磁盘占用"]');
        await page.fill('.modal input[placeholder="例如 查看磁盘占用"]', '列目录');
        await page.fill('.modal textarea', 'ls');
        await page.click('.modal-foot .btn.primary');
        await page.waitForTimeout(400);
        const snipCount = await page.locator('.snip').count();
        check('代码片段已保存', snipCount === 1, 'count=' + snipCount);
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);

        /* --------------------------------------------------------- terminal */
        await page.locator('.host-row', { hasText: 'demo-server' }).locator('.act.go').click();
        await page.waitForSelector('#view-term:not([hidden])', { timeout: 15000 });
        check('进入终端页', true);

        // host key prompt
        await page.waitForSelector('.modal-head h3', { timeout: 20000 });
        const modalTitle = await page.locator('.modal-head h3').innerText();
        check('首次连接弹出主机密钥确认', modalTitle.indexOf('主机密钥') >= 0, modalTitle);
        await page.click('.modal-foot .btn.primary');

        const pane = page.locator('#panes .pane.on');
        await pane.waitFor();
        await page.waitForFunction(
            () => {
                const p = document.querySelector('#panes .pane.on');
                return p && /Welcome to test-box/.test(p.innerText);
            },
            { timeout: 25000 }
        );
        check('终端收到服务器欢迎信息', true);

        // interact with the shell
        await pane.click();
        await page.keyboard.type('echo hello-webssh');
        await page.keyboard.press('Enter');
        await page.waitForFunction(
            () => /hello-webssh/.test(document.querySelector('#panes .pane.on').innerText),
            { timeout: 10000 }
        );
        check('键盘输入与回显正常', true);

        // host bar: OS + live stats
        await page.waitForFunction(() => /Debian/.test(document.querySelector('#hb-os').textContent || ''), { timeout: 20000 });
        check('主机信息条显示系统信息', true);
        await page.waitForFunction(
            () => {
                const box = document.querySelector('#hb-stats');
                return box && /%/.test(box.textContent || '') && box.querySelectorAll('.bar').length >= 2;
            },
            { timeout: 25000 }
        );
        check('监控指标（CPU/MEM 进度条）已渲染', true);
        await page.waitForFunction(
            () => {
                const t = document.querySelector('#hb-stats').textContent || '';
                return /ms/.test(t) && /↓/.test(t) && !/↓0 B\/s/.test(t);
            },
            { timeout: 25000 }
        );
        const statsText = (await page.locator('#hb-stats').innerText()).replace(/\n/g, ' ');
        check('监控指标包含网络速率与 RTT', /↓/.test(statsText) && /\d+ ms/.test(statsText), statsText);

        // snippets from the host bar
        await page.click('#btn-snippets');
        await page.waitForSelector('.snip');
        await page.click('.snip');
        await page.waitForFunction(() => /ls/.test(document.querySelector('#panes .pane.on').innerText), { timeout: 8000 });
        check('从片段发送命令到会话', true);
        await page.waitForFunction(() => /notes\.txt/.test(document.querySelector('#panes .pane.on').innerText), { timeout: 8000 });
        check('片段命令执行结果回显', true);

        // special keys
        await page.click('#keys .key:has-text("Ctrl+C")');
        await page.waitForFunction(() => /\^C/.test(document.querySelector('#panes .pane.on').innerText), { timeout: 8000 });
        check('特殊按键条 Ctrl+C 生效', true);

        // wait until the CPU cell has a real percentage (needs two samples)
        await page.waitForFunction(
            () => /\d+%/.test((document.querySelector('#hb-stats .stat .v') || {}).textContent || ''),
            { timeout: 20000 }
        );
        await page.waitForTimeout(1800);
        await page.screenshot({ path: path.join(SHOTS, 'terminal.png') });

        // second tab
        await page.click('#btn-dup');
        await page.waitForFunction(() => document.querySelectorAll('.ttab').length === 2, { timeout: 20000 });
        check('可以新开多个会话标签', true);
        await page.waitForTimeout(1200);

        // close the second tab
        await page.locator('.ttab').nth(1).locator('.x').click();
        await page.waitForFunction(() => document.querySelectorAll('.ttab').length === 1, { timeout: 8000 });
        check('关闭标签后回到单个会话', true);

        /* ------------------------------------------------------------ back */
        await page.click('.term-top-actions [data-act="back"]');
        await page.waitForSelector('#view-dash:not([hidden])', { timeout: 8000 });
        check('从终端返回总览', true);

        /* -------------------------------------------------- persist reload */
        await page.reload({ waitUntil: 'domcontentloaded' });
        await page.waitForSelector('#view-dash:not([hidden])', { timeout: 15000 });
        check('刷新后保持登录', true);
        await page.waitForSelector('.host-row', { timeout: 10000 });
        check('刷新后主机仍在', (await page.locator('.host-row').count()) === 5);

        /* --------------------------------------------------------- logout */
        await page.click('.rail-item[data-nav="logout"]');
        await page.waitForSelector('#form-login:not([hidden])', { timeout: 10000 });
        check('退出后回到登录页', true);
        await page.fill('#form-login input[name="username"]', 'admin');
        await page.fill('#form-login input[name="password"]', 'sup3r-secret');
        await page.click('#form-login button[type="submit"]');
        await page.waitForSelector('#view-dash:not([hidden])', { timeout: 15000 });
        check('可以重新登录', true);
    } finally {
        check('无 JS 运行时错误', errors.length === 0, errors.slice(0, 6).join(' | '));
        await browser.close();
        dev.kill('SIGTERM');
        ssh.server.close();
    }

    const failed = results.filter((r) => !r.ok);
    console.log('\n' + (results.length - failed.length) + ' passed, ' + failed.length + ' failed, ' + results.length + ' total');
    if (failed.length) process.exitCode = 1;
}

main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
});
