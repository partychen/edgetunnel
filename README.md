# edgetunnel

edgetunnel 是一个运行在 Cloudflare Pages 上的轻量级边缘隧道项目。它提供可视化管理后台、订阅生成、优选地址、代理落地和多协议节点配置能力，适合通过 GitHub 自动部署到 Cloudflare Pages 后长期使用。

项目源码使用 TypeScript 维护，构建时会打包成 Cloudflare Pages 可运行的单文件 Worker。

## 功能特性

- **Cloudflare Pages 部署**：连接 GitHub 仓库后自动构建和发布。
- **管理后台**：通过 `/admin` 登录，可在浏览器中管理订阅、节点、优选地址和反代配置。
- **多协议支持**：支持 VLESS、Trojan、Shadowsocks。
- **多传输方式**：支持 WebSocket、XHTTP、gRPC。
- **订阅生成**：提供普通订阅、Base64 订阅，以及常见客户端可导入的订阅链接。
- **优选地址**：支持随机优选、自定义优选地址、订阅接口汇聚，节点备注使用中文运营商标识。
- **Cloudflare CDN 访问设置**：支持 PROXYIP 和代理落地配置，用于改善不同网络环境下的连接可用性。
- **KV 持久化配置**：后台配置、自定义优选地址和操作日志保存到 Cloudflare KV。
- **自定义域名**：可绑定自己的域名访问后台和订阅。

## 快速部署

### 1. Fork 仓库

点击 GitHub 页面右上角 **Fork**，把项目复制到自己的账号下。

### 2. 创建 Cloudflare Pages 项目

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages**
3. 点击 **Create** → **Pages** → **Connect to Git**
4. 选择 Fork 后的仓库
5. 构建配置填写：

| 配置项 | 值 |
| :--- | :--- |
| Build command | `npm run build` |
| Build output directory | `dist` |

6. 添加 Production 环境变量：

| 变量名 | 必填 | 说明 |
| :--- | :---: | :--- |
| `ADMIN` | 是 | 后台管理密码 |
| `UUID` | 否 | 固定 UUID；不填会自动生成 |

7. 保存并部署

### 3. 绑定 KV Namespace

后台配置需要 Cloudflare KV。进入 Pages 项目：

```text
Settings → Bindings → Add → KV Namespace
```

绑定名称必须填写：

```text
KV
```

可以选择已有 KV Namespace，也可以创建新的。保存后重新部署一次。

KV 会保存以下数据：

| Key | 用途 |
| :--- | :--- |
| `config.json` | 后台配置 |
| `ADD.txt` | 自定义优选地址 |
| `log.json` | 后台操作日志 |

### 4. 访问后台

部署完成后打开：

```text
https://你的域名/admin
```

如果还没有绑定自定义域名，也可以使用 Cloudflare Pages 默认域名：

```text
https://你的项目名.pages.dev/admin
```

输入 `ADMIN` 密码即可登录。

## 常用配置

### 环境变量

| 变量名 | 必填 | 说明 |
| :--- | :---: | :--- |
| `ADMIN` | 是 | 后台管理密码 |
| `UUID` | 否 | 固定 UUID，需使用 UUIDv4 格式 |
| `KEY` | 否 | 快速订阅路径密钥 |
| `HOST` | 否 | 自定义节点域名，支持多个 |
| `PATH` | 否 | 自定义节点路径 |
| `PROXYIP` | 否 | 自定义 PROXYIP；不设置时后台的自动 PROXYIP 默认使用 `pyip.ygkkk.dpdns.org` |
| `GO2SOCKS5` | 否 | SOCKS5 白名单 |
| `DEBUG` | 否 | 设置为 `1` 或 `true` 时输出调试日志 |

### 自定义域名

在 Cloudflare Pages 项目的 **Custom domains** 中添加你的域名，例如：

```text
tunnel.example.com
```

如果 DNS 也托管在 Cloudflare，通常会自动创建对应记录。手动配置时可添加：

| 类型 | 名称 | 目标 |
| :--- | :--- | :--- |
| CNAME | `tunnel` | `你的项目名.pages.dev` |

DNS 和证书生效后，即可通过自定义域名访问后台和订阅。

## 后台使用

登录后台后，可以完成以下配置：

1. **复制订阅链接**：用于导入 v2rayN、v2rayNG、V2Box、Shadowrocket 等客户端。
2. **设置订阅名称**：客户端中显示的订阅名称。
3. **选择协议**：VLESS、Trojan、Shadowsocks。
4. **选择传输方式**：WebSocket、XHTTP、gRPC。
5. **配置优选地址**：随机优选、自定义优选地址、订阅接口汇聚。
6. **配置 CDN 访问**：PROXYIP 或代理落地。
7. **查看操作日志**：用于确认后台保存、重置和配置变更记录。

## 客户端导入

后台会生成订阅链接。复制后导入客户端即可：

| 平台 | 推荐客户端 |
| :--- | :--- |
| Windows | v2rayN |
| macOS | v2rayN、V2rayU |
| iOS | V2Box、Shadowrocket |
| Android | v2rayNG |

如果客户端显示的节点名类似 `CF电信优选1`、`CF联通优选1`、`CF移动优选1`、`CF官方优选1`，表示正在使用内置优选地址生成。

## 本地开发

安装依赖：

```bash
npm install
```

类型检查：

```bash
npm run typecheck
```

构建：

```bash
npm run build
```

构建完成后会生成：

```text
dist/_worker.js
```

## 手动部署

推荐使用 GitHub 连接 Cloudflare Pages 自动部署。如果需要手动部署：

```bash
npm run deploy
```

如果你的 Pages 项目名或生产分支不是仓库默认值，请同步调整 `package.json` 中的部署脚本。

## 安全建议

- 设置强密码作为 `ADMIN`
- 不要公开后台地址和订阅 token
- 生产环境建议绑定自己的域名
- 如果重新部署或更换 KV，可以在后台重置配置重新初始化

## 免责声明

本项目仅供学习研究使用。使用者应自行了解并遵守所在地区的法律法规，因使用本项目产生的任何后果由使用者自行承担。
