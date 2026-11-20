<div align="center">

# WebSSH

**把 SSH 搬进浏览器**

一个 Cloudflare Worker + 一个 R2 桶 · 无需服务器 · 免费计划够用

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jinhuaitao/OneSSH)

`SSH-2 自研协议栈` · `多标签终端` · `SFTP 文件管理` · `PWA`

</div>

---

## ✨ 功能

| 🖥️ 主机 | ⌨️ 终端 | 📁 文件 |
| :---: | :---: | :---: |
| 域名 / IPv4 / IPv6<br><sub>密码 · 私钥 · 快速连接</sub> | 多标签 · 实时监控<br><sub>按键条 · 代码片段</sub> | SFTP 全功能<br><sub>浏览 / 上传 / 在线编辑</sub> |
| **🌐 仪表盘** | **🗝️ 凭据库** | **🛡️ 安全** |
| 分组筛选 · 点阵地球<br><sub>可拖拽旋转 · 主机定位</sub> | 账号与私钥复用<br><sub>AES-GCM 加密存储</sub> | 主机密钥强校验<br><sub>同源防护 · 会话录制</sub> |

## ⚡ 连接速度

握手路径按「少等往返」重排过，对 OpenSSH / Dropbear / ssh2 等服务端兼容：

- **提前开始**：TCP 一连上就发版本串、KEXINIT 与 ECDH_INIT，不等服务器 banner；
- **凭据并行**：密钥交换与 R2 读取、前端 `init` 消息同时进行，KEX 完成时密码通常已就绪；
- **服务请求前置**：NEWKEYS 写出后立即发 `ssh-userauth`，把「等 NEWKEYS + 等服务接受」压成一个往返；
- **已知主机预取**：主机指纹在 TCP 建连时就开始读，验签不再等 R2。

在 100ms RTT 的链路上，`TCP 已连接 → shell ready` 从约 700ms 降到约 620ms（本地 ssh2 基准，`node tools/bench-handshake.mjs --delay=50 --rounds=5` 中位 621-622ms；`--delay=0` 中位约 178ms）；
浏览器到边缘的一整个往返也被 `warm()` 与握手重叠，`curve25519` 密钥对在 `warm()` 里与 socket 建连并行生成。可自行复测：

```bash
npm install
node tools/bench-handshake.mjs --delay=50 --rounds=5
```

启动与 R2 也做了并行化：前端启动改走一次 `GET /api/bootstrap`（主机/分组/密钥库/常用账号/片段/已知主机一次返回，失败回退逐个接口），模拟 R2（每操作 20ms 延迟、100 台主机）下从约 890ms 降到约 327ms；主密钥缓存 60 秒 TTL（轮换/导入时显式失效）；连接预算改有界扫描。可自行复测：

```bash
node --import ./tests/register.mjs tools/bench-r2.mjs
```

SFTP 分块按实测调过：`READ_CHUNK` 256K、`WRITE_CHUNK` 128K、并发保持 4（10MB 上传在 10ms 延迟下从约 3.6s 降到约 1.9s；0 延迟下载反而略慢于 128K，属噪声/重组开销，见 `OneSSH-perf-SUMMARY.md`）。可自行复测：

```bash
node tools/bench-transfer.mjs --read-chunk=262144 --write-chunk=131072 --delay=10
```

## 🚀 部署

**最快路径**：点上面的部署按钮，连接 GitHub，完成后打开 Worker 域名。

<details>
<summary><b>手动部署（5 步）</b></summary>

1. 控制台开通 **R2**（同意条款即可）
2. 仓库推到 GitHub（公开私有都行）
3. Workers & Pages → Create → **Connect to Git**
4. 构建设置：`Build = npm install`，`Deploy = npx wrangler deploy`
5. 部署后设置 `WEBSSH_SETUP_TOKEN` 密钥，打开域名初始化管理员

```bash
npx wrangler secret put WEBSSH_SETUP_TOKEN   # 必须设置，否则拒绝初始化
```

> R2 绑定故意不写桶名：首次部署自动建桶绑定。改 `wrangler.jsonc` 的 `name` 等于换一套数据。

</details>

## 🧭 使用

- **连接**：点主机行直连；未存凭据则弹窗临时输入。左侧闪电图标可临时连任意公网地址
- **搜索**：顶部搜索框按名称/地址/用户名/分组/城市/备注过滤，`⌘K` 或 `/` 聚焦
- **文件**：终端顶部「文件」走 SFTP，单文件上限 64 MB，上传先写临时文件再覆盖，中断不毁原文件；文件列表里可改权限（chmod，0-7777，支持 setuid/setgid/sticky），符号链接改的是链接目标；不支持 chown / 改时间
- **快捷键**：`Ctrl/⌘+Shift+C/V` 复制粘贴（多行先确认）· `+F` 全屏 · `+R` 重连 · `+W` 关标签 · `Alt+1…9` 切标签
- **PWA**：Chrome「安装」或 Safari「添加到主屏幕」，可当独立应用打开

<details>
<summary><b>⌨️ 全部快捷键</b></summary>

| 快捷键 | 作用 |
| :--- | :--- |
| `Ctrl/⌘ + Shift + C` / `+ V` | 复制选中 / 粘贴（两行以上先确认） |
| `Ctrl/⌘ + Shift + F` / `+ R` / `+ W` | 全屏 / 重连 / 关闭当前标签 |
| `Alt + 1…9` | 切换标签 |
| 右键 | 粘贴（同样先确认多行） |
| `⌘/Ctrl + K` 或 `/` | 聚焦搜索框 |
| `Esc` | 清空搜索 |
| 触屏长按 + 拖动 | 选择文本并复制 |

</details>

## 🔐 安全

- **单管理员**：无注册入口，口令 PBKDF2-SHA256 加盐存储，可选环境变量 pepper 加固
- **两步验证（可选）**：TOTP（RFC 6238，HMAC-SHA1，30 秒步长，±1 步容差，同一验证码防重放）+ 10 个一次性备用码（只存 SHA-256 哈希）；设置页可启用 / 停用（停用需密码 + 验证码），登录与导出都可要求验证码
- **会话**：256 位随机 token，HttpOnly + SameSite=Lax，30 天绝对 / 7 天空闲过期，绑 UA 与 IP 网段，改密踢掉所有设备
- **加密**：主机密码、私钥、常用账号、会话录制均 AES-GCM，v2 密文绑定字段归属（AAD），搬走解不开
- **主机密钥**：握手先验签，指纹首次记录、变更即拒绝，无法「点继续」绕过中间人
- **防线**：写接口 Origin 同源校验 · CSP/COOP/CORP/HSTS · 登录失败 6 次锁 15 分钟 · 连接频率预算 · 只连公网；字面私网 / 保留地址在创建与建连时都直接拒绝（`10/8、172.16/12、192.168/16、127/8、169.254/16、::1、fc00::/7、fe80::/10` 等，`2001:db8::/32` 文档段除外）；未登录时 `/api/state` 只返回 `{setup, authed}`，不暴露版本号与初始化配置
- **数据**：主机 / 密钥库 / 常用账号 / 分组 / 片段带 `version` 乐观并发（POST 可带 `expectedVersion`，冲突返回 409）；加密导出 / 导入（导出密码 PBKDF2 10 万次 + AES-GCM，AAD `oneshh-export-v1`，主密钥一起打包，导入需 `confirm: true`，失败不覆盖现有数据）；会话录制默认保留 90 天（`WEBSSH_LOG_RETENTION_DAYS` 可改，0 为永久保留），列表与会话结束时分批清理

<details>
<summary><b>🔧 实现细节与已知限制</b></summary>

浏览器 `xterm.js` ──WebSocket──▶ Worker ──TCP──▶ sshd，同一 SSH 连接内复用 shell + exec（监控）+ sftp；R2 存放账号、会话、主机、分组、凭据、已知主机密钥、录制、片段。

SSH 协议栈自研（`src/ssh/`），只用 WebCrypto：`curve25519-sha256` 与 `diffie-hellman-group14-sha256` 密钥交换、`aes*-ctr`、HMAC-SHA2、ed25519 / ECDSA P-256 / RSA-SHA2 主机密钥，密码/公钥/keyboard-interactive 认证，私钥支持 ed25519 / RSA / ECDSA P-256。SHA-1 系已移除，支持 strict-kex（Terrapin 缓解）与主动重协商。

**限制**：免费计划 10ms CPU，持续大输出可能中断（Paid $5/月为 30s）· 监控依赖 Linux `/proc` · 不支持端口转发、Agent 转发、带口令私钥 · 只支持较新的算法 · Workers 只能连公网地址。

**私网与 DNS 重绑定**：字面私网地址在代码层直接拦截，但域名解析后指向私网的 DNS 重绑定在 Worker 内无解——`connect()` 的 DNS 解析不在代码控制内，兜底靠 Workers 运行时只连公网。不要把本工具当作内网跳板机用。

**明确延期（未实现）**：ChaCha20-Poly1305（WebCrypto 无此算法，纯 JS 实现量大且易错）· 带口令 OpenSSH 私钥（需 bcrypt_pbkdf 纯 JS 实现）· AES-GCM SSH 密码套件。R2 单对象乐观并发只有 `version` 字段校验，校验与写回之间仍有竞态窗口（真 CAS 需 R2 If-Match/etag，`getJSON` 目前丢弃 etag、内存 R2 桩也不提供 etag，故未做）；`version` 至少让基于旧列表的编辑能被发现，而不是静默丢数据。

</details>

## 🧪 本地开发

```bash
npm install
npx wrangler dev        # http://127.0.0.1:8787
npm test                # 167 个用例，无需 Cloudflare / sshd / 浏览器
npm run test:e2e        # 6 个用例，ssh2 起真实本地 sshd（与 npm test 里的同款用例单独跑）
npx wrangler deploy     # 需先 wrangler login
```

`npm test` 用 Node 内置 `node:test`：内存 R2（含条件写与分页）+ `cloudflare:sockets` 桩，覆盖加解密、SFTP、API 鉴权、限流、安全加固等；E2E 用例用 `ssh2` 起真实本地服务器验证握手、认证、exec 与 SFTP chmod，无 `ssh-keygen` 的环境会自动跳过。

---

<p align="center"><sub>MIT License · Built on Cloudflare Workers</sub></p>
