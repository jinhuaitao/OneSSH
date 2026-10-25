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
| 分组收起 · 地区筛选<br><sub>可拖拽点阵地球</sub> | 账号与私钥复用<br><sub>AES-GCM 加密存储</sub> | 主机密钥 TOFU<br><sub>登录限流 · CSRF</sub> |

## 🚀 部署

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
npm test                        # 端到端：本地 sshd + wrangler dev + 真 Chrome
node tests/e2e.mjs --headful    # 想看着它点
```

`npm test` 覆盖初始化、分组、凭据库、主机密钥确认、终端交互、监控、代码片段、文件管理、刷新保持登录、退出登录；依赖 `ssh2` 与 `playwright-core`（用本机 Chrome）。删掉 `.wrangler/state` 会清空本地全部数据。

## 🧭 使用

### 🖥️ 主机与连接

| 操作 | 说明 |
| :--- | :--- |
| ➕ **添加主机** | 名称、分组、地址、端口、用户名，选密码或私钥，再选地区和城市；同一分组内按添加先后排列 |
| 🌐 **IPv6** | 填 `2001:db8::1` 或 `[2001:db8::1]` 都行，列表统一显示为 `user@[addr]:port` |
| 🔌 **连接** | 点主机行一键直连；没存凭据则弹窗临时输入，只在内存里用 |
| ⚡ **快速连接** | 左侧闪电图标，临时连接不落库，可顺手保存到我的主机 |
| 🔑 **主机密钥** | 首次连接弹 `SHA256:...` 指纹确认（与 `ssh-keygen -lf` 一致）；服务器重装后先删旧记录 |

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
| 📄 **文件管理** | 终端顶部「文件」走 SFTP；单文件上限 64 MB，在线编辑限 512 KB 以内的文本 |
| 🧩 **代码片段** | 左侧「代码片段」维护常用命令，终端页右上角也能打开，点一下发送到当前会话 |
| 📊 **监控** | Linux 主机每 3 秒采样一次 `/proc`（独立 exec 通道，不打断 shell）；其他系统显示「不可用」 |
| 🎛️ **特殊按键** | Ctrl / Alt、Tab / Esc、方向键、Ctrl+C / Ctrl+D、PgUp / PgDn / Home / End / Del |
| 📼 **会话日志** | 设置里可默认开启录制，终端输出以文本存在 R2，随时回看 / 复制 / 删除 |

### ⌨️ 快捷键

| 快捷键 | 作用 |
| :--- | :--- |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>C</kbd> | 复制选中 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>V</kbd> | 粘贴 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>F</kbd> | 全屏 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>R</kbd> | 重连 |
| <kbd>Ctrl</kbd> / <kbd>⌘</kbd> + <kbd>Shift</kbd> + <kbd>W</kbd> | 关闭当前标签 |
| <kbd>Alt</kbd> + <kbd>1</kbd> … <kbd>9</kbd> | 切换标签 |
| 右键 | 粘贴 |

## 🔐 安全

- 👤 **单管理员**：第一个完成初始化的账号就是唯一账号，没有注册入口。忘记密码只能删掉 R2 里的 `sys/admin` 和 `sess/*` 重新初始化（已存凭据会丢）。
- 🔒 **加密边界**：凭据用 AES-GCM 加密，主密钥默认也在同一个桶的 `sys/master`。这能防「桶被人翻到」，但防不了「Cloudflare 账号被攻破」。可以自带密钥：

  ```bash
  npx wrangler secret put WEBSSH_MASTER_KEY   # 32 字节 base64 或 64 位 hex
  ```

  设置后不再使用 `sys/master`，但**换密钥后旧凭据都解不开**，需要重新录入。
- 📝 **录制是明文**：记录的是终端原始输出，可能包含命令和打印出来的密钥。
- 🚦 **登录限流**：同一 IP 10 分钟内失败 6 次，锁 15 分钟；写接口只收 `application/json`，并校验 HttpOnly + SameSite=Lax 的会话 Cookie。
- 🌍 **连不了内网**：Workers 只能连公网地址，Cloudflare 自家网段、localhost、内网地址都会被拒。

<details>
<summary><b>🚧 已知限制</b></summary>

<br>

- 免费计划单请求 CPU 只有 10ms，`yes`、`cat` 大文件这类持续大输出可能被中断；重度使用建议 Paid 计划（$5/月，30s CPU）。
- 监控依赖 Linux 的 `/proc`，BSD / macOS / Windows 显示「不可用」（终端本身照常可用）。
- 暂不支持端口转发、Agent 转发、带口令的 OpenSSH 私钥（`bcrypt_pbkdf`）。带口令私钥请先 `ssh-keygen -p -m PEM` 转成无口令 PEM。
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

SSH 协议栈是自己实现的（`src/ssh/`），只依赖 WebCrypto：`curve25519-sha256` 密钥交换、`aes{128,192,256}-ctr` 加密、`hmac-sha2-{256,512}` / `hmac-sha1` 校验、`ssh-ed25519` / `ecdsa-sha2-nistp256` / `rsa-sha2-{256,512}` / `ssh-rsa` 主机密钥，支持密码、公钥（OpenSSH / PKCS#1 / PKCS#8）和 keyboard-interactive 认证。

| 文件 | 作用 |
| :--- | :--- |
| `src/worker.js` | 路由：页面、`/api/*`、`/ws` 升级；在 fetch 处理器内建立 TCP 连接 |
| `src/session.js` | WebSocket ↔ SSH 桥接：状态推送、主机密钥确认、窗口调整、录制、保活、监控采样 |
| `src/hostaddr.js` | 主机地址规范化：域名 / IPv4 / IPv6（IPv6 统一补方括号） |
| `src/ssh/client.js` | SSH-2 传输层 / 密钥交换 / 认证 / 多通道（shell + exec + sftp） |
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

R2 数据布局：

```
sys/admin           管理员账号（PBKDF2-SHA256 + 随机盐）
sys/master          凭据加密主密钥
sys/snippets        代码片段
sys/groups          分组名称列表
sys/keys            凭据库里的私钥（AES-GCM 密文 + 算法 / 指纹）
sys/creds           凭据库里的常用账号（密码为 AES-GCM 密文）
sess/<token>        登录会话（30 天）
hosts/<id>          主机配置（密码 / 私钥为密文，或引用 sys/keys / sys/creds）
known/<host>_<port> 已信任的主机密钥指纹
logs/<id>.log       会话录制（纯文本 + 元数据）
throttle/<ip>       登录失败计数
```

</details>

---

<p align="center"><sub>⚡ MIT License · Built on ☁️ Cloudflare Workers</sub></p>
