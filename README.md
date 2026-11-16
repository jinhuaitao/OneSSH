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
- **文件**：终端顶部「文件」走 SFTP，单文件上限 64 MB，上传先写临时文件再覆盖，中断不毁原文件
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
- **会话**：256 位随机 token，HttpOnly + SameSite=Lax，30 天绝对 / 7 天空闲过期，绑 UA 与 IP 网段，改密踢掉所有设备
- **加密**：主机密码、私钥、常用账号、会话录制均 AES-GCM，v2 密文绑定字段归属（AAD），搬走解不开
- **主机密钥**：握手先验签，指纹首次记录、变更即拒绝，无法「点继续」绕过中间人
- **防线**：写接口 Origin 同源校验 · CSP/COOP/CORP/HSTS · 登录失败 6 次锁 15 分钟 · 连接频率预算 · 只连公网

<details>
<summary><b>🔧 实现细节与已知限制</b></summary>

浏览器 `xterm.js` ──WebSocket──▶ Worker ──TCP──▶ sshd，同一 SSH 连接内复用 shell + exec（监控）+ sftp；R2 存放账号、会话、主机、分组、凭据、已知主机密钥、录制、片段。

SSH 协议栈自研（`src/ssh/`），只用 WebCrypto：`curve25519-sha256` 密钥交换、`aes*-ctr`、HMAC-SHA2、ed25519 / ECDSA P-256 / RSA-SHA2 主机密钥，密码/公钥/keyboard-interactive 认证。SHA-1 系已移除，支持 strict-kex（Terrapin 缓解）与主动重协商。

**限制**：免费计划 10ms CPU，持续大输出可能中断（Paid $5/月为 30s）· 监控依赖 Linux `/proc` · 不支持端口转发、Agent 转发、带口令私钥 · 只支持较新的算法 · Workers 只能连公网地址。

</details>

## 🧪 本地开发

```bash
npm install
npx wrangler dev        # http://127.0.0.1:8787
npm test                # 115 个用例，无需 Cloudflare / sshd / 浏览器
npx wrangler deploy     # 需先 wrangler login
```

`npm test` 用 Node 内置 `node:test`：内存 R2（含条件写与分页）+ `cloudflare:sockets` 桩，覆盖加解密、SFTP、API 鉴权、限流、安全加固等。删 `.wrangler/state` 清空本地数据。

---

<p align="center"><sub>MIT License · Built on Cloudflare Workers</sub></p>
