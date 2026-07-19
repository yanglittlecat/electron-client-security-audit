# 自定义协议、OAuth 与本地服务专项审计

## 目录

1. 威胁模型
2. 协议入口与平台差异
3. URL 与 OAuth 检查
4. 本地服务检查
5. 静态追踪
6. 安全动态验证
7. 分级与报告
8. 修复基线

## 1. 威胁模型

按以下链路追踪，不要只检查 Electron `webPreferences`：

```text
外部网页/文件/其他应用
  → custom scheme / universal link / CLI argv
  → OS 唤醒与 Electron 单实例转发
  → URL 解析、路由、OAuth 回调或本地服务
  → 导航、凭据交换、本地操作、持久化或渲染
  → 正常用户触发的实际影响
```

自定义协议、recent project 二阶 XSS、OAuth 回调和本地服务可以形成同一条链，但每个阶段的可达性必须独立证明。

## 2. 协议入口与平台差异

- 查找 `app.setAsDefaultProtocolClient`、打包配置中的 protocol/file association、`app.on('open-url')`、`second-instance`、`process.argv`、启动参数和用户数据持久化。
- macOS 常通过 `open-url` 交付；Windows 和 Linux 常见初始 `argv` 或第二实例转发，但必须以目标的打包方式和运行证据为准。Electron 不得写成 iOS 平台逻辑。
- 确认冷启动与已运行状态是否使用同一校验函数，防止两条入口的校验差异。
- 浏览器对外部协议的用户手势、确认框、iframe/重定向和频率限制随浏览器与版本变化。必须动态记录，不得声称“已注册协议一定无感拉起”。

## 3. URL 与 OAuth 检查

1. 用结构化 URL 解析器处理协议，检查 scheme、hostname、port、pathname 和每个 query 参数的精确白名单。
2. 检查大小写、百分号编码、重复解码、Unicode/国际化域名、userinfo、空 hostname、反斜杠和路径规范化差异。
3. 追踪 URL 参数是否进入 `loadURL`、`openExternal`、本地文件、HTML sink、SQL、进程启动 API、recent project 或本地服务路由。
4. OAuth/OIDC 流程检查 `state`、PKCE、`nonce`、会话绑定、一次性消费、超时和 redirect URI 的精确匹配。
5. 分清授权码、access token、refresh token 和业务 session；不得在无数据流证据时声称 deep link 会携带 token。
6. 检查凭据是否出现在 URL query/fragment、浏览器历史、Referer、应用/代理/操作系统日志和错误页面中。

## 4. 本地服务检查

对 HTTP/WebSocket 端点分别回答以下三个问题：

| 结果 | 需证明的条件 |
|---|---|
| 请求可发出 | 浏览器/上下文允许请求，并通过 mixed-content、preflight/PNA 等限制 |
| 状态可改变 | 服务端接受请求，且缺少有效的能力 token/session、权限或重放防护；响应不必可读 |
| 响应可读 | CORS 允许攻击 origin；带 cookie/凭据时还需 `Access-Control-Allow-Credentials: true`和非 `*` 的精确 origin |

无 `Origin` 校验可能导致 CSRF 或 WebSocket 跨站连接，但不等于 HTTP 响应必然可读。`Access-Control-Allow-Origin: *` 可允许无凭据响应读取，但浏览器不允许它与 credentialed CORS 响应混用。

必须检查：

- 绑定 `127.0.0.1`/`::1` 还是 `0.0.0.0`/局域网接口，IPv4/IPv6 是否一致。
- 端口是固定、可预测还是随机；随机端口不能代替授权。
- 每个端点的能力 token/session、权限范围、时效、重放防护、参数 schema 和敏感数据输出。
- HTTP `Origin`/`Host`、WebSocket `Origin`、DNS rebinding、CORS、preflight/PNA、cookie `SameSite`/`Secure` 和浏览器版本差异。
- 本地服务是常驻启动，还是仅在 `open-url`/OAuth callback 时按需启动。
- 非浏览器客户端、恶意项目中的 webview/远端页面和本地 HTML 是否具有不同的网络限制。

对原生 TCP 服务，普通浏览器 JavaScript 不能直接建立任意 raw TCP 连接。必须找 WebSocket、HTTP bridge、preload API、插件或其他实际客户端，不得把 HTTP/WebSocket 结论直接套用到 raw TCP。

## 5. 静态追踪

1. 搜索 `setAsDefaultProtocolClient`、`open-url`、`second-instance`、`process.argv`、`protocol.handle/register*`、OAuth/OIDC、`redirect_uri`、`state`、PKCE 和 `nonce`。
2. 搜索 `http.createServer`、`https.createServer`、`express`、`app.listen`、`server.listen`、`WebSocketServer`、`net.createServer`、`dgram.createSocket` 和端口配置。
3. 确认启动时机、绑定地址、路由、middleware、鉴权、CORS/PNA、Origin/Host 检查和敏感响应。
4. 对协议参数建立 `source → parse/canonicalize → route/persistence → sink → trigger → impact` 数据流。
5. 对本地服务建立端点表：method/path、输入、授权、副作用、响应、CORS、Origin/Host、调用者与触发条件。

## 6. 安全动态验证

- 只使用 `127.0.0.1`/`localhost`、临时用户数据目录、最小 benign HTML 和固定测试字符串。
- 将攻击模型写成可打开的本地 HTML，不要仅在 DevTools console 手工执行 `fetch`。
- 分别记录协议是否唤醒应用、是否需要用户手势/确认、冷启动和二次实例的参数是否一致。
- 对本地服务分别证明请求发送、状态改变和响应读取，保存请求/响应头的脱敏证据。
- 不访问公网、真实 OAuth 提供方或第三方服务；不读取真实 token/cookie，使用模拟值。

## 7. 分级与报告

- **确认漏洞**：必须给出攻击者可控协议/网络输入、平台交付路径、服务端校验、正常用户操作和可观测结果。
- **跨站状态改变**：即使响应不可读，若可未授权执行高影响操作，仍可按实际影响汇报。
- **跨站读取**：必须证明实际 CORS/凭据/PNA 条件，不得根据“无 Origin 校验”推导。
- **待验证**：缺少浏览器行为、OAuth 会话绑定、路由可达性、授权或动态响应时降级。
- **加固建议**：仅有协议注册、固定端口、宽松 CORS 片段或 token 线索，但无完整业务链时不进入确认漏洞总览。

报告附上：协议 scheme/host/path，冷/热启动入口，URL 解析与参数流向，OAuth `state`/PKCE/回调绑定，本地端点授权，CORS/PNA/Origin/Host 条件，自然触发和 benign 现象。

## 8. 修复基线

- 对 scheme、host、port、path 和操作类型做结构化精确白名单，统一冷/热启动的校验函数。
- OAuth/OIDC 使用精确 redirect URI、随机且会话绑定的 `state`、PKCE、`nonce`、一次性 code 和短时效。
- 不在 URL query、历史、Referer 或日志中传递 access/refresh token。
- 本地端点使用随机能力 token、最小权限、参数 schema、短时效与重放防护；只暴露必要路由。
- 对 HTTP 使用精确 CORS、`Origin`/`Host` 策略和 PNA 兼容设计；对 WebSocket 校验 `Origin` 并独立授权。
- 默认绑定 loopback；若需绑定局域网地址，使用强认证、加密和显式用户授权。
