// Single-page shell. All data comes from /api/*, so this markup holds no secrets.
const ICONS = {
    home: '<path d="M4 10.6 12 4l8 6.6V19a1 1 0 0 1-1 1h-4.5v-6h-5v6H5a1 1 0 0 1-1-1z"/>',
    server: '<rect x="3.5" y="4.5" width="17" height="6" rx="2"/><rect x="3.5" y="13.5" width="17" height="6" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    code: '<path d="m8.5 8.5-4 3.5 4 3.5M15.5 8.5l4 3.5-4 3.5"/>',
    terminal: '<path d="m5 8 4 4-4 4M12.5 16h6"/>',
    gear: '<circle cx="12" cy="12" r="3.2"/><path d="M19.4 14.5a7.7 7.7 0 0 0 0-5l1.6-1.2-1.8-3.1-1.9.8a7.6 7.6 0 0 0-4.3-2.5L12.6 1h-1.2l-.4 2.5a7.6 7.6 0 0 0-4.3 2.5l-1.9-.8L3 8.3l1.6 1.2a7.7 7.7 0 0 0 0 5L3 15.7l1.8 3.1 1.9-.8a7.6 7.6 0 0 0 4.3 2.5l.4 2.5h1.2l.4-2.5a7.6 7.6 0 0 0 4.3-2.5l1.9.8 1.8-3.1z"/>',
    logout: '<path d="M14 5.5h4a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1h-4M10 8.5 6 12l4 3.5M6 12h9"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    refresh: '<path d="M20 11a8 8 0 1 0-2.3 6.3M20 5v6h-6"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M15 6.5V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h1.5"/>',
    back: '<path d="M10 6.5 4.5 12l5.5 5.5M4.5 12H20"/>',
    power: '<path d="M12 4v7"/><path d="M7.5 6.8a7 7 0 1 0 9 0"/>',
    expand: '<path d="M9 4H4v5M15 4h5v5M15 20h5v-5M9 20H4v-5"/>',
    bolt: '<path d="M13.5 3 5 13.5h6L10.5 21 19 10.5h-6z"/>',
    key: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M17.5 12v3M20 12v2.5"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    edit: '<path d="m4 16.5-.8 4 4-.8L19 8a2.1 2.1 0 0 0-3-3z"/>',
    log: '<path d="M6 3.5h7l5 5v12H6z"/><path d="M13 3.5v5h5M9 13h6M9 16.5h4"/>',
    folder: '<path d="M3.5 6.5h6l1.8 2h9.2v10.5a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1z"/>',
    lock: '<rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    search: '<circle cx="10.5" cy="10.5" r="6"/><path d="m15 15 4.5 4.5"/>',
};

function icon(name, size) {
    const s = size || 20;
    return (
        '<svg class="ic" width="' +
        s +
        '" height="' +
        s +
        '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" ' +
        'stroke-linecap="round" stroke-linejoin="round">' +
        (ICONS[name] || '') +
        '</svg>'
    );
}

export function renderShell() {
    return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>WebSSH · 浏览器里的 SSH 终端</title>
<link rel="icon" href="/icons/favicon-32.png" sizes="32x32" type="image/png">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png" sizes="180x180">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#f03d08">
<meta name="application-name" content="WebSSH">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="WebSSH">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<link rel="stylesheet" href="/vendor/xterm.css">
<link rel="stylesheet" href="/style.css">
<link rel="stylesheet" href="/term.css">
</head>
<body>
<div class="boot" id="boot">
  <div class="boot-mark">${icon('terminal', 26)}</div>
  <div class="boot-text">正在加载 WebSSH…</div>
</div>

<!-- ============================ 登录 / 初始化 ============================ -->
<div class="auth" id="view-auth" hidden>
  <div class="auth-card">
    <div class="auth-brand">
      <div class="brand-mark">${icon('terminal', 20)}</div>
      <div>
        <h1>WebSSH</h1>
        <p>在浏览器中安全连接你的服务器</p>
      </div>
    </div>

    <form id="form-setup" class="auth-form" hidden autocomplete="off">
      <p class="eyebrow">FIRST RUN</p>
      <h2>初始化管理员</h2>
      <p class="hint">设置访问本工具的账号与密码，凭据只保存在你自己的 R2 存储里。</p>
      <label>用户名<input name="username" type="text" placeholder="admin" autocomplete="username" required minlength="3" maxlength="32"></label>
      <label id="setup-token-field">初始化口令<input name="token" type="password" placeholder="部署时设置的 WEBSSH_SETUP_TOKEN" autocomplete="off" required></label>
      <p class="form-hint" id="setup-token-hint" hidden>还没配置 <code>WEBSSH_SETUP_TOKEN</code>：先到 Worker 的变量里设置它，否则无法初始化（未设置时任何人都能抢先成为管理员）。</p>
      <label>密码<input name="password" type="password" placeholder="至少 10 位" autocomplete="new-password" required minlength="10" maxlength="200"></label>
      <label>确认密码<input name="password2" type="password" placeholder="再次输入" autocomplete="new-password" required minlength="10" maxlength="200"></label>
      <button type="submit" class="btn primary block">创建并进入</button>
      <p class="form-error" id="setup-error"></p>
    </form>

    <form id="form-login" class="auth-form" hidden autocomplete="off">
      <p class="eyebrow">SIGN IN</p>
      <h2>登录</h2>
      <label>用户名<input name="username" type="text" autocomplete="username" required></label>
      <label>密码<input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit" class="btn primary block">登录</button>
      <p class="form-error" id="login-error"></p>
    </form>
  </div>
  <p class="auth-foot">via Cloudflare Workers · 数据保存在你自己的 R2</p>
</div>

<!-- ================================ 总览 ================================ -->
<div class="app" id="view-dash" hidden>
  <aside class="rail">
    <div class="rail-brand">${icon('terminal', 20)}</div>
    <nav class="rail-nav">
      <button class="rail-item on" data-nav="overview">${icon('home')}<span>总览</span></button>
      <button class="rail-item" data-nav="groups">${icon('folder')}<span>分组</span></button>
      <button class="rail-item" data-nav="snippets">${icon('code')}<span>代码片段</span></button>
      <button class="rail-item" data-nav="quick">${icon('bolt')}<span>快速连接</span></button>
      <button class="rail-item" data-nav="known">${icon('key')}<span>主机密钥</span></button>
      <button class="rail-item" data-nav="keys">${icon('lock')}<span>凭据库</span></button>
      <button class="rail-item" data-nav="settings">${icon('gear')}<span>设置</span></button>
    </nav>
    <button class="rail-item rail-out" data-nav="logout">${icon('logout')}<span>退出</span></button>
  </aside>

  <section class="dash">
    <header class="dash-head">
      <div>
        <p class="eyebrow">YOUR INFRASTRUCTURE</p>
        <h1>我的主机</h1>
        <p class="sub">安全保存，随时连接。</p>
      </div>
      <div class="dash-tools">
        <label class="search">
          ${icon('search', 15)}
          <input id="host-search" type="search" placeholder="搜索名称 / 地址 / 备注" title="可按名称、地址、用户名、分组、城市、备注搜索" autocomplete="off" spellcheck="false" aria-label="搜索主机">
        </label>
        <button class="btn primary" id="btn-add-host">${icon('plus', 15)} 添加主机</button>
      </div>
    </header>

    <div class="filters" id="filters"></div>
    <div class="host-groups" id="host-groups"></div>

    <footer class="dash-foot">
      <span id="dash-count" class="muted-sm"></span>
      <button class="link" id="btn-refresh">刷新列表 ${icon('refresh', 13)}</button>
    </footer>
  </section>

  <aside class="globe-side">
    <div class="globe-head">
      <p class="eyebrow">A SMALLER WORLD</p>
      <h2>散布全球，<br><em>就在手边。</em></h2>
      <p class="sub">点击圆点查看主机，点名字连接。</p>
    </div>
    <div class="globe-wrap" id="globe-wrap">
      <canvas id="globe"></canvas>
      <div class="globe-labels" id="globe-labels"></div>
    </div>
    <footer class="globe-foot">
      <span id="globe-count" class="muted-sm"></span>
      <button class="link" id="btn-rotate">暂停旋转</button>
    </footer>
  </aside>
</div>

<!-- =============================== 终端页 =============================== -->
<div class="term" id="view-term" hidden>
  <header class="term-top">
    <div class="term-brand">
      <div class="brand-mark sm">${icon('terminal', 15)}</div>
      <span>WebSSH</span>
    </div>
    <div class="term-tabs" id="tabs"></div>
    <div class="term-top-actions">
      <button class="tbtn" data-act="back">${icon('back', 15)} 主机</button>
      <button class="tbtn" data-act="settings" title="设置">${icon('gear', 15)}</button>
      <button class="tbtn" data-act="logout" title="退出登录">${icon('power', 15)}</button>
    </div>
  </header>

  <div class="hostbar" id="hostbar">
    <div class="hb-id">
      <div class="hb-name">
        <span class="hb-dot" id="hb-dot"></span>
        <b id="hb-title">—</b>
        <span class="hb-badge">交互式 Shell</span>
      </div>
      <div class="hb-sub">
        <span class="hb-via">via Cloudflare Workers</span>
        <span class="hb-os" id="hb-os"></span>
      </div>
    </div>
    <div class="hb-stats" id="hb-stats"></div>
    <div class="hb-actions">
      <button class="tbtn ghost" id="btn-files">${icon('folder', 15)}<span>文件</span></button>
      <button class="tbtn ghost" id="btn-snippets">${icon('code', 15)}<span>代码片段</span></button>
      <button class="tbtn ghost" id="btn-dup" title="新开一个会话">${icon('plus', 15)}</button>
      <button class="tbtn ghost" id="btn-reconnect" title="重连">${icon('refresh', 15)}</button>
      <button class="tbtn ghost" id="btn-fullscreen" title="全屏">${icon('expand', 15)}</button>
      <button class="tbtn ghost danger" id="btn-disconnect" title="断开">${icon('power', 15)}</button>
    </div>
  </div>

  <div class="term-body">
    <div class="panes" id="panes"></div>
  </div>

  <footer class="term-keys">
    <div class="keys" id="keys"></div>
    <div class="term-keys-right">
      <span class="muted-sm" id="pane-count"></span>
      <button class="link" id="btn-logs">会话日志</button>
      <button class="link" id="btn-help">快捷键</button>
    </div>
  </footer>
</div>

<div class="toasts" id="toasts"></div>
<div id="modal-root"></div>

<script src="/vendor/xterm.js"></script>
<script src="/vendor/xterm-addon-fit.js"></script>
<script type="module" src="/js/app.js"></script>
</body>
</html>`;
}
