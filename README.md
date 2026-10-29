<h1 align="center">WebSSH</h1>

<p align="center">
<b>把 SSH 搬进浏览器</b><br>
<sub>☁️ 一个 Cloudflare Worker + 🗄️ 一个 R2 桶 · 无需服务器 · 免费计划够用</sub>
</p>

<p align="center">
<a href="#-功能">✨ 功能</a> ·
<a href="#-部署">🚀 部署</a> ·
<a href="#-使用">🧭 使用</a> ·
<a href="#-安全">🔐 安全</a>
</p>

---

## ✨ 功能

| 🖥️ 主机 | ⌨️ 终端 | 📁 文件 |
| :---: | :---: | :---: |
| 域名 / IPv4 / IPv6<br><sub>密码或私钥认证</sub> | 多标签 · 实时监控<br><sub>按键条 · 代码片段</sub> | SFTP 全功能<br><sub>浏览 / 上传 / 在线编辑</sub> |
| **🗺️ 仪表盘** | **🔑 凭据库** | **🛡️ 安全** |
| 分组收起 · 地区筛选<br><sub>可拖拽点阵地球</sub> | 账号与私钥复用<br><sub>AES-GCM 加密存储</sub> | 主机密钥强校验<br><sub>同源防护 · 日志加密</sub> |

## 🚀 部署
### 方式一
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jinhuaitao/OneSSH)

### 方式二

**1️⃣ 开通 R2 → 2️⃣ 推 GitHub → 3️⃣ 连接仓库 → 4️⃣ 部署 → 5️⃣ 设置管理员**

1. 🗄️ **开通 R2**：控制台 → R2 → 同意条款。没开通的话，首次部署自动建桶会失败。
2. 🐙 **推到 GitHub**：public / private 都行。
3. 🔗 **连接仓库**：控制台 → Workers & Pages → Create → Connect to Git。
4. ⚙️ **填构建设置**：

   | 配置项 | 值 |
   | :--- | :--- |
   | Project name | `webssh`（必须与 `wrangler.jsonc` 的 `name` 完全一致） |
   | Build command | `npm install` |
   | Deploy command | `npx wrangler deploy` |

5. 🚀 **部署**：R2 绑定故意不写桶名，首次部署会自动建桶并绑定。

   ```jsonc
   "r2_buckets": [{ "binding": "BUCKET" }]
   ```

6. 🌐 **打开**：`https://<worker>.<subdomain>.workers.dev`，按提示设置管理员账号密码。

<details>
<summary><b>⚠️ 注意 · 两个容易踩的坑</b></summary>

<br>

- Dashboard 部署会自动建桶，但**桶名不会写回仓库**。以后改用本地 `wrangler deploy` 时，先把桶名填进 `wrangler.jsonc` 的 `bucket_name`，否则 wrangler 会再建一套新的，看起来就像「数据丢了」。
- 改 `wrangler.jsonc` 的 `name` 等于换一个应用：会创建另一套 R2，原数据不会跟过来。

</details>

### 🧪 本地开发与测试

```bash
npm install
npx wrangler dev                # http://127.0.0.1:8787，本地 R2 在 .wrangler/ 下
npx wrangler deploy             # CLI 部署，需先 wrangler login
npm test                        # 93 个用例，不需要 wrangler / 网络 / sshd
npm run test:watch              # 改代码自动重跑
```

`npm test` 用 Node 自带的 `node:test` 跑，分五组：

| 文件 | 覆盖内容 |
| :--- | :--- |
| `tests/unit.test.mjs` | 主机地址归一化、SSH 二进制缓冲、AES-CTR 密钥流连续性、密钥派生、ed25519 / ECDSA / RSA 三种主机密钥的签名校验、私钥解析（PKCS#8）、PBKDF2、凭据加解密、Cookie 属性 |
| `tests/sftp.test.mjs` | SFTP 报文分帧、属性位解析、状态码翻译、`renameOverwrite` 的三级降级（posix-rename → 普通 rename → 备份再换名） |
| `tests/session.test.mjs` | 会话层：`knownKey` 归一化、原子上传的两个操作码（临时文件 → 还原权限 → 覆盖改名）、失败时清理临时文件、句柄释放 |
| `tests/api.test.mjs` | 直接调用 Worker 的 `fetch`：初始化 / 初始化口令 / 登录 / 限流 / 改密踢设备 / 登出、主机 · 分组 · 凭据库 CRUD、密文不落明文、跨站写请求与非法 Content-Type、安全响应头、路径穿越 |
| `tests/hardening.test.mjs` | 会话绑设备（UA 缺省也拒绝、IP 取不到也拒绝、XFF 默认不采信）、初始化口令必填、密文 AAD 绑定与旧日志兼容、SHA-1 签名拒绝、`first_kex_packet_follows` 丢包、主动重协商触发条件、密码 pepper 与哈希记录自动升级、`/api/state` 不泄露版本、主机数量上限、录制保留期 |

为了在 Node 里加载 Worker 代码，`tests/loader.mjs` 把 `cloudflare:sockets` 解析成一个桩，`tests/helpers.mjs` 提供一个内存版 R2（含 `If-None-Match: *` 条件写与分页）。所以整套测试不需要 Cloudflare 账号、不需要本地 sshd，也不需要浏览器。删掉 `.wrangler/state` 会清空本地全部数据。

需要「真 SSH 握手 + 真浏览器」的端到端验证时，仍然可以用 `ssh2` + `playwright-core` 自己搭：前者起一个本地 sshd，后者驱动 `wrangler dev` 的页面。这两个依赖已列在 `devDependencies` 里，只是 `npm test` 不再依赖它们，CI 里跑得快也更稳。

## 🧭 使用

### 🖥️ 主机与连接

| 操作 | 说明 |
| :--- | :--- |
| ➕ **添加主机** | 名称、分组、地址、端口、用户名，选密码或私钥，再选地区和城市；同一分组内按添加先后排列 |
| 🔍 **搜索** | 顶部搜索框按名称 / 地址 / 用户名 / 分组 / 城市 / 备注过滤，与地区筛选叠加生效，<kbd>⌘K</kbd>（或 <kbd>/</kbd>）聚焦、<kbd>Esc</kbd> 清空，页脚同步显示 `命中 / 总数` |
| 🌐 **IPv6** | 填 `2001:db8::1` 或 `[2001:db8::1]` 都行，列表统一显示为 `user@[addr]:port` |
| 🔌 **连接** | 点主机行一键直连；没存凭据则弹窗临时输入，只在内存里用 |
| ⚡ **快速连接** | 左侧闪电图标，临时连接不落库，可顺手保存到我的主机；为防止被当成端口扫描器，同一登录会话 10 分钟内最多连 10 个临时目标（连已保存的主机另按每分钟 20 条限速） |
| 🔑 **主机密钥** | 首次连接弹 `SHA256:...` 指纹确认（与 `ssh-keygen -lf` 一致）；指纹变了直接拒绝，并在弹窗里一键「删除旧记录并重连」 |

### 🗂️ 组织与凭据

| 操作 | 说明 |
| :--- | :--- |
| 🗃️ **分组** | 左侧「分组」面板新建 / 改名 / 删除；改名同步主机，删除后主机回到「未分组」 |
| 📌 **收起展开** | 点仪表盘分组标题即可收起或展开，状态记在本地 |
| 🗝️ **凭据库** | 「常用账号」存用户名 + 密码，「私钥」自动识别算法并计算 `SHA256:` 指纹 |
| 🔗 **引用** | 主机直接选条目复用，用户名和密码都不用再填；被引用的条目不能删除 |

### 📁 终端与文件

| 操作 | 说明 |
| :--- | :--- |
| 📄 **文件管理** | 终端顶部「文件」走 SFTP；单文件上限 64 MB，在线编辑限 512 KB 以内的文本；上传先写临时文件再覆盖改名，中断不会毁掉原文件 |
| 🧩 **代码片段** | 左侧「代码片段」维护常用命令，终端页右上角也能打开，点一下发送到当前会话 |
| 📊 **监控** | Linux 主机每 3 秒采样一次 `/proc`（独立 exec 通道，不打断 shell）；其他系统显示「不可用」 |
| 🎛️ **特殊按键** | Ctrl / Alt、Tab / Esc、方向键、Ctrl+C / Ctrl+D、PgUp / PgDn / Home / End / Del |
| 📼 **会话日志** | 设置里可默认开启录制，终端输出以文本存在 R2，随时回看 / 复制 / 删除 |

### ⌨️ 快捷键

| 快捷键 | 作用 |
| :--- | :--- |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>C</kbd> | 复制选中 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>V</kbd> | 粘贴（**两行以上会先弹确认**） |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>F</kbd> | 全屏 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>R</kbd> | 重连 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>W</kbd> | 关闭当前标签 |
| <kbd>Alt</kbd> + <kbd>1</kbd> … <kbd>9</kbd> | 切换标签 |
| 右键 | 粘贴（同样会先确认多行内容） |
| <kbd>⌘</kbd> / <kbd>Ctrl</kbd> + <kbd>K</kbd> | 回到主机列表时聚焦搜索框 |

### 📲 安装到桌面（PWA）

地址栏右侧的「安装」图标（Chrome / Edge），或 Safari「分享 → 添加到主屏幕」，就能把 WebSSH 当独立应用打开，有自己的图标和窗口。

| 项 | 位置 / 值 |
| :--- | :--- |
| 清单 | `public/manifest.webmanifest`（`display: standalone`、主题色 `#f03d08`、底色 `#faf8f4`） |
| 图标 | `public/icons/`：192 / 512（`any`）+ 192 / 512（`maskable`）+ iOS 的 `apple-touch-icon.png` |
| 重生成 | 改 `tools/make-icons.mjs` 里的坐标或配色后跑 `npm run icons` |

图标图形与 `public/favicon.svg` 同源（同一套 64 单位坐标），`tools/make-icons.mjs` 是零依赖的：SDF 光栅化 + 手写 PNG 编码，只用 Node 自带的 `zlib`。

**故意没有 Service Worker**：离线时本来也连不上 SSH 服务器；而 `worker-src 'none'` 的 CSP 会拦掉 SW 注册，为装个图标去放宽 CSP 不划算。现代 Chrome 已不再要求 SW 才能安装，manifest + 图标即可。

## 🔐 安全

- 👤 **单管理员**：第一个完成初始化的账号就是唯一账号，没有注册入口。忘记密码只能删掉 R2 里的 `sys/admin` 和 `sess/*` 重新初始化（主密钥不变，已存凭据仍能解开）。如果配了 `WEBSSH_PASSWORD_PEPPER`，重装时**必须用同一个 pepper**，否则已存的哈希永远对不上。
- 🎟️ **初始化口令（必须设置）**：`WEBSSH_SETUP_TOKEN` 现在是硬性要求 —— 没配就**不允许初始化**，接口直接回 `503 setup_token_missing`。原因是未配置时的语义等于「谁先打开网址谁就是管理员」，而这个窗口往往正好在部署完、把链接丢进群里的那几分钟。口令与登录密码共用同一套失败计数（超过阈值锁 15 分钟）：

  ```bash
  npx wrangler secret put WEBSSH_SETUP_TOKEN   # 或在控制台 Workers → 设置 → 变量 里加
  ```

- 🔑 **口令与会话**：密码至少 10 位、拒绝常见弱口令；PBKDF2-SHA256（10 万次迭代）加盐存储，校验用恒定时间比较。会话是 HttpOnly + SameSite=Lax 的随机 256 位 token，30 天绝对过期、7 天空闲过期，**改密后其它设备立即掉线**。
- 🧂 **密码 pepper（强烈建议）**：Workers 生产运行时把 PBKDF2 迭代次数**硬锁在 100000**（超了直接 `NotSupportedError`，本地 dev 不检查），所以「加迭代次数抗离线爆破」这条路是堵死的。能加的是 pepper —— 一段只存在环境变量、永远不写进 R2 的随机串，拼在密码前面一起过 PBKDF2。拿到桶转储的人没有 pepper，哈希对他就是一堆随机字节：

  ```bash
  npx wrangler secret put WEBSSH_PASSWORD_PEPPER   # 至少 16 字符，建议 openssl rand -base64 32
  ```

  加了 pepper 之后**旧密码仍然能登录**，登录成功那一刻记录自动升级（哈希记录带 `v: 2` / `peppered` 标记，升级时保留 `createdAt`）；pepper 短于 16 字符当作没配。反过来，**pepper 丢了 = 密码作废**，只能删 `sys/admin` 重新初始化。也正因为 pepper 和主密钥都在同一个环境变量里，这里没有把 `sys/admin` 整体加密 —— 加密不会多挡住任何人，却会让密钥配错时管理员彻底进不去。
- 🧷 **会话绑设备（fail-closed）**：会话写入时的 User-Agent 会参与校验 —— UA 变了**或者这次压根没带 UA**，都直接作废并删除记录（空 UA 算不匹配，否则 `curl -A ""` 就是一条绕过路径）。IP 按网段比对：IPv4 比 /24、IPv6 比 /48，换网段同样作废；建会话时知道 IP、这次却取不到，也按不匹配处理。手机切 4G/5G 只换尾段，不受影响。确实需要放宽（比如经常跨网络漫游）可以设 `WEBSSH_SESSION_IP_BIND=off` 关掉 IP 这一层，UA 那一层没有开关。
- 🕵️ **不采信客户端自报的 IP**：`cf-connecting-ip` 优先；`x-forwarded-for` / `x-real-ip` 是客户端可写的头，默认忽略 —— 否则换一个值就能把登录限流绕成无限次。确实在自己的反代后面（且反代会覆写这两个头）时，再设 `WEBSSH_TRUST_PROXY=on` 打开。
- 🧱 **跨站防线**：所有写接口和 WebSocket 升级都校验 `Origin` 同源，挡 CSRF 和跨站 WebSocket 劫持；页面带 `CSP`（`connect-src 'self'`、`object-src 'none'`、`frame-ancestors 'none'`）、`COOP` / `CORP` / `Permissions-Policy`，HTTPS 下加 `HSTS`。
- 🛡️ **主机密钥强校验**：握手时先验证服务器签名，拿不出这把主机私钥就直接断开（中间人无法用「点继续」绕过）；首次连接记录指纹，之后指纹变化自动拒绝。
- 🔒 **加密边界**：主机密码、私钥、常用账号、**会话录制**都用 AES-GCM 加密；密文格式升到 `v2`，把「这段密文属于哪个字段」绑进 AAD（`host:<id>` / `cred:<id>` / `key:<id>` / `log:<name>`）—— 只拿到 R2 写权限也搬不动别人的密文，换个字段解就是认证失败。旧数据是 `v1`（无 AAD），仍可正常读取：凭据靠 `v1:`/`v2:` 前缀分支，会话日志没有前缀可判，所以读取时先带上下文、失败再退回无上下文解密。主密钥默认放在同一个桶的 `sys/master` —— 防「桶被人翻到」，防不了「Cloudflare 账号被攻破」。可以自带密钥：

  ```bash
  npx wrangler secret put WEBSSH_MASTER_KEY   # 32 字节 base64 或 64 位 hex
  ```

  设置后不再使用 `sys/master`，但**换密钥后旧凭据都解不开**，需要重新录入。
- 🚦 **登录限流**：同一 IP 10 分钟内失败 6 次，锁 15 分钟；写接口只收 `application/json` 且限制请求体大小；账号是否存在不体现在响应内容或耗时上。
- 🧮 **连接预算**：登录态被拿走时，这个 Worker 就是一台免费代理。临时地址（`?host=`）每 10 分钟最多 10 个目标，**保存过的主机同样受限** —— 每会话每分钟最多新建 20 条连接，超了直接回一条 `error` 帧。Worker 是无状态的，跨 isolate 没有共享内存，所以限的是「新建速率」而不是「同时在线数」：会造成伤害的是短时间内打出去几百条 TCP。
- 🗂️ **数量与保留期**：主机最多 200 台、分组最多 50 个（到顶返回 `409 too_many`，改已有条目不受影响）；会话录制默认保留 30 天，每次写完新录制顺手清一批过期的，`WEBSSH_LOG_RETENTION_DAYS=0` 可永久保留。
- 🌍 **连不了内网**：Workers 只能连公网地址，Cloudflare 自家网段、localhost、内网地址都会被拒。

<details>
<summary><b>🚧 已知限制</b></summary>

<br>

- 免费计划单请求 CPU 只有 10ms，`yes`、`cat` 大文件这类持续大输出可能被中断；重度使用建议 Paid 计划（$5/月，30s CPU）。
- 监控依赖 Linux 的 `/proc`，BSD / macOS / Windows 显示「不可用」（终端本身照常可用）。
- 暂不支持端口转发、Agent 转发、带口令的私钥（OpenSSH 用 `bcrypt_pbkdf`、传统 PEM 用 MD5 派生，WebCrypto 都没有）。带口令的私钥请先去掉口令：`ssh-keygen -p -N "" -f <私钥文件>`（会覆盖原文件，先备份）。
- 只支持 `curve25519-sha256` 系列密钥交换和 CTR 系列加密，非常老的服务器（`diffie-hellman-group1-sha1` / `3des-cbc`）连不上。

</details>

<details>
<summary><b>🔧 实现细节</b></summary>

<br>

```
浏览器 (xterm.js)  ──WebSocket──▶  Worker  ──TCP(cloudflare:sockets)──▶  sshd:22
                                     │
                                     ├── 同一条 SSH 连接：shell + exec（采样 /proc）+ sftp（文件管理）
                                     └── R2：账号 / 会话 / 主机 / 分组 / 凭据库 / 已知主机密钥 / 录制 / 片段
```

SSH 协议栈是自己实现的（`src/ssh/`），只依赖 WebCrypto：`curve25519-sha256` 密钥交换、`aes{128,192,256}-ctr` 加密、`hmac-sha2-{256,512}` 校验、`ssh-ed25519` / `ecdsa-sha2-nistp256` / `rsa-sha2-{256,512}` 主机密钥，支持密码、公钥（OpenSSH / PKCS#1 / PKCS#8）和 keyboard-interactive 认证。

**SHA-1 系已从协商列表里移除**：`hmac-sha1` 与 `ssh-rsa`（用 SHA-1 签主机密钥）不再提供。RSA 主机密钥仍然支持，只是强制走 `rsa-sha2-256/512`。同时握手阶段会核对「协商到的算法」与「服务器实际报出来的签名算法」是否一致 —— 否则攻击者可以把 `rsa-sha2-512` 悄悄压回 `ssh-rsa`，而界面看不出任何异常。

**重协商与 KEX 细节**：累计收发到 1 GB（或服务端主动发起）会重算会话密钥，重协商时主机密钥仍然重新验签；服务器声明 `first_kex_packet_follows` 且猜错算法时，它那一个包按 RFC 4253 §7.1 丢弃。

| 文件 | 作用 |
| :--- | :--- |
| `src/worker.js` | 路由：页面、`/api/*`、`/ws` 升级；在 fetch 处理器内建立 TCP 连接 |
| `src/session.js` | WebSocket ↔ SSH 桥接：状态推送、主机密钥确认、窗口调整、录制、保活、监控采样 |
| `src/hostaddr.js` | 主机地址规范化：域名 / IPv4 / IPv6（IPv6 统一补方括号） |
| `src/ssh/client.js` | SSH-2 传输层 / 密钥交换 / 认证 / 多通道（shell + exec + sftp）；协商 `kex-strict-*`（Terrapin 缓解）与 `ext-info-c` |
| `src/ssh/sftp.js` | SFTP v3 客户端：读目录、读写文件、原子保存（临时文件 + 重命名） |
| `src/ssh/crypto.js` | CTR 密钥流（按包偏移连续）、HMAC、密钥派生、主机密钥签名校验 |
| `src/ssh/keys.js` | OpenSSH / PKCS#1 / PKCS#8 私钥解析与签名 |
| `src/auth.js` | PBKDF2 口令、会话 Cookie、登录限流、凭据加解密 |
| `src/store.js` | R2 读写封装 |
| `src/pages.js` | 单页骨架（数据都走 `/api/*`，HTML 里没有任何秘密） |
| `public/js/app.js` | 前端主控：登录、主机增删改、分组与凭据库面板、弹窗、设置 |
| `public/js/files.js` | 文件管理弹窗：目录浏览、上传 / 下载、在线编辑 |
| `public/js/globe.js` | 点阵地球：正交投影 + 拖拽旋转 + 海洋渐变与大气层 + 标签跟随 |
| `public/js/land.js` | 2°×2° 陆地掩码（构建期光栅化生成，运行时零依赖） |
| `public/js/term.js` | 终端页：多标签、WebSocket 会话、监控面板、按键条 |
| `public/vendor/` | xterm.js（随仓库内置，不依赖 CDN） |
| `tests/` | `node:test` 用例 + 内存 R2 + `cloudflare:sockets` 桩，见上文「本地开发与测试」 |

R2 数据布局：

```
sys/admin           管理员账号（PBKDF2-SHA256 + 随机盐）
sys/master          凭据加密主密钥（可用 WEBSSH_MASTER_KEY 覆盖）
sys/snippets        代码片段
sys/groups          分组名称列表
sys/keys            凭据库里的私钥（AES-GCM 密文 + 算法 / 指纹）
sys/creds           凭据库里的常用账号（密码为 AES-GCM 密文）
sess/<token>        登录会话（30 天绝对过期 / 7 天空闲过期）
hosts/<id>          主机配置（密码 / 私钥为密文，或引用 sys/keys / sys/creds）
known/<host>_<port> 已信任的主机密钥指纹
logs/<id>.log       会话录制（AES-GCM 密文 + 元数据）
throttle/<ip>       登录失败计数
```

</details>

---

<p align="center"><sub>⚡ MIT License · Built on ☁️ Cloudflare Workers</sub></p>
