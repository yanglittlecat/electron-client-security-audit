---
name: electron-client-security-audit
description: "授权 Electron/桌面客户端安全审计：重点确认正常用户可触发的 XSS、恶意项目输入面、deep link/recent project 二阶 XSS、preload/IPC 自定义危险能力与 XSS-to-RCE 链路，并输出可向上级汇报的清晰复现步骤。"
---
# Electron/客户端产品安全漏洞审计 Skill

## 0. 核心验收口径

本 skill 的目标不是罗列所有安全配置问题，而是找出**对正常用户有实际危害、可通过自然业务路径触发、可复现说明清楚**的客户端漏洞。

报告中的"确认漏洞"必须满足：

1. **攻击入口真实**：payload 可通过恶意项目、恶意文件、deep link、`.url`、远端页面、recent project、剪贴板、拖拽文件、业务消息、第三方数据等正常入口带入客户端。
2. **受害者路径自然**：触发步骤必须是正常用户会做的操作（打开/导入项目、编译/预览、查看错误日志、点击错误项、右键异常项目、删除/重命名 recent project、打开链接/详情页、关闭/确认弹窗等）。
3. **禁止 DevTools 当复现入口**：不得把"打开 DevTools 后在 console 执行代码""手工改本地缓存/数据库""修改客户端源码/构建产物""手动调用内部函数"作为确认漏洞的复现步骤。此类内容只能作为调试辅助。
4. **危害证明明确**：
   - XSS-to-RCE 以弹出本机计算器或等价 benign 命令为准（Windows `calc.exe`，macOS `open -a Calculator`，Linux `xcalc`/`gnome-calculator`）。
   - `nodeIntegration:false` 且 `contextIsolation:true` 时，不能假设能直接 RCE，必须找 preload/contextBridge/IPC 暴露的自定义危险函数。
   - **TCP 外连即为独立高危网络能力**：preload/contextBridge 暴露的 `net.createConnection` / `net.connect` / `net.Socket`（Node.js 原生 TCP socket）允许 XSS 建立**任意地址的 raw TCP 双向通道**，绕过浏览器所有同源/CORS 限制。结合 XSS 本身的 JS 执行能力（`socket.write()` + `socket.on('data')`），攻击者即可通过 TCP 通道下发命令、接收结果，形成**交互式远程控制**（不依赖 `child_process`）。若同时暴露 IPC 或命令执行，则直接构成完整反向 Shell。因此 `net.createConnection` 的暴露应视同高危远控前置能力，不应仅按普通网络访问处理。
   - 网络能力验证只用本地 loopback（`127.0.0.1`/`localhost`）：启动监听 → 通过 XSS 调用暴露的 `createNetConnection` 连接 → 双向收发固定 benign 字符串（如 `audit-proof`）→ 验证成功。结论写为"XSS 可调用 TCP 外连能力，具备被滥用为反连/远程控制前置能力的风险"。不得提供真实反连 shell、远程 C2、外传、下载执行 payload。
5. **证据链完整**：确认漏洞必须给出 `source → persistence/transform → sink → trigger → capability → impact`。缺少任一环节时标记为"待验证"或"加固建议"。

## 1. 约束模型

本节定义整个审计过程的**唯一约束来源**。后续章节不再重复这些规则，仅引用本节。

### 1.1 执行模式

审计采用**非交互连续执行模式**——默认一直向前推进直到完成全部审计和报告。允许给用户发简短进度更新（如"已完成窗口地图，正在追踪 recent project 链路"），但**禁止抛选择题**（如"是否继续扫描？""是否弹计算器验证？"）。不确定时按本节默认策略执行，不中断询问。

### 1.2 默认允许（直接执行，不询问）

| 类别 | 范围 |
|------|------|
| 只读扫描 | `pwd`、`ls`、`find`、`rg`、`cat`、`sed`、`jq`、只读 Python 扫描脚本 |
| 审计产出 | 创建 `audit-artifacts/` 及其子目录（`poc/`、`asar-unpacked/`、`static-scan/`、`runtime/`）；生成/覆盖审计报告和 PoC 材料 |
| 静态追踪 | 对 `.asar`、source map、webpack bundle、preload、main/renderer process、IPC、HTML 模板、日志面板、recent project、deep link 等进行多轮追踪 |
| 启动客户端 | 启动已安装/已解包客户端或当前仓库的 Electron 应用；前提是依赖已存在、命令不会触发联网安装 |
| 项目命令 | 允许执行与复现相关的 `npm start`、`npm run dev/build/test`、`yarn start`、`pnpm start`、`electron .` 等；前提是不触发 `npm install` |
| RCE 验证 | 通过真实漏洞链触发计算器或等价 benign 命令；**禁止**直接在终端执行 `calc` 当作漏洞证明 |
| 网络验证 | 启动仅监听 `127.0.0.1`/`localhost` 的 TCP/HTTP/WebSocket 服务，通过漏洞链连接并发送固定 benign 字符串（如 `audit-proof`） |
| 恶意材料 | 在目标客户端中打开本次生成的恶意项目、deep link、`.url`、本地 HTML 等，模拟正常受害路径 |
| 截图/日志 | 保存验证截图、命令输出、监听日志到 `audit-artifacts/`；敏感信息必须脱敏 |

动态验证优先使用临时运行目录和临时用户数据目录（设置 `HOME`、`USERPROFILE`、`APPDATA`、`TMPDIR` 等指向 `audit-artifacts/runtime/`），避免污染真实用户配置。验证结束后关闭测试进程。

### 1.3 硬性禁止（自动跳过，记录原因）

| 禁止项 | 说明 |
|--------|------|
| 越界读取 | 不读取审计范围外的目录/文件 |
| 联网安装 | 禁止 `npm install`、`yarn install`、`pnpm install`、`bun install` 及任何触发 `postinstall`/安装脚本的命令 |
| 访问公网 | 不访问公网、第三方服务、真实远端回连地址 |
| 攻击 payload | 禁止反连 shell、远程 C2、下载执行、外传、持久化、提权、免杀、绕过检测、破坏性文件操作 |
| 破坏性写入 | 不删除/覆盖/移动非本次生成的文件，不写入系统敏感位置、启动项、插件目录、用户真实配置目录 |
| 泄露敏感信息 | 不读取/导出/展示 token、cookie、私钥、账号、数据库敏感内容、用户隐私路径；必要时只展示脱敏片段和文件/行号 |
| 管理员权限 | 不以管理员/root 执行非必要命令 |

### 1.4 默认策略（不确定时照此执行）

- 是否继续审计 / 深入追踪 / 生成报告 / 生成 PoC：**默认继续/生成**
- 是否启动客户端或执行项目代码：**默认允许**（先判断是否触发联网安装或破坏性操作）
- 是否执行 RCE 验证：**默认允许**（通过真实漏洞链触发计算器）
- 网络验证：**只用 loopback**，不访问公网
- 是否读取范围外文件 / 删除非本次生成文件 / 展示敏感值：**默认不做**
- 多个分支无法确定优先级时：**全部做静态分析**，不中断询问

### 1.5 失败处理

某步骤失败时不停止等待。记录失败原因、影响范围和替代方案，继续后续步骤。例如：asar 无法解包 → 审计未解包文件和 bundle；source map 缺失 → 基于压缩 bundle 关键字审计；GUI 不可用 → 降级为"待验证"但给出完整复现步骤。

### 1.6 输出优先级（范围大或时间有限时按此顺序）

1. 窗口/权限地图
2. 正常用户可触发入口
3. source → sink → trigger 链路
4. `nodeIntegration:true` 的 XSS-to-RCE 计算器证明链
5. preload/contextBridge 暴露的 `net.createConnection` / `net.connect` / `net.Socket` TCP 外连能力（独立高危网络能力，不依赖 nodeIntegration）
6. `nodeIntegration:false` 且 `contextIsolation:true` 时的 preload/IPC 自定义危险能力（命令执行、文件读写等）
7. 本地 loopback 网络能力证明链（TCP/HTTP/WebSocket）
8. 可向上级汇报的确认漏洞复现步骤
9. 待验证问题、加固建议和残余风险

### 1.7 验证项目规则

在 `audit-artifacts/poc/<vuln-id>/` 创建最小化验证材料：

- 只创建新目录；已存在则换名或拒绝覆盖
- 只包含复现所需的最小文件、README、触发步骤和无害 payload
- XSS 优先用 `alert`、DOM 标记、`console.log` 或可见样式标记证明
- RCE 只用计算器验证；网络只用 loopback 验证
- README 必须写明：产品/版本、攻击者准备、受害者操作、预期现象、清理方式
- 无法构造验证项目或无法动态验证时，在报告中说明缺失条件并降级为"待验证"

## 2. 报告输出

在当前工作目录生成中文 Markdown 报告：`客户端产品安全漏洞审计报告.md`。使用 `references/report_template.md` 作为结构模板。

报告必须包含：

- 审计范围、方法、限制与时间
- 窗口/权限地图：BrowserWindow、BrowserView、webview、Prompt/Dialog、preload、webPreferences
- 漏洞总览表：编号、标题、严重性、状态、证据强度、影响组件、证据文件/行号、是否具备正常用户复现路径
- 每个确认漏洞的：原因、影响对象、正常用户利用链、危害证明、清晰复现步骤（直接写在正文中，不得只写"详见 PoC 文件"）、修复建议
- 对开发者工具/IDE/小程序工具：覆盖恶意项目输入面、编译日志/代码帧、recent project、deep link、Prompt/Modal/Dialog、右键菜单
- 对未确认但可疑的问题标记为"待验证"并说明缺失条件
- 对未发现可利用链的风险点只给加固建议，不放入确认漏洞总览
- 区分"确认漏洞""待验证问题""配置加固建议"
- 未发现确认漏洞时也要生成报告，说明已检查范围、未发现结论、残余风险

## 3. 严重性与证据强度标准

### 3.1 严重性

| 等级 | 定义 |
|------|------|
| **高危** | 正常用户可通过自然业务路径触发，且可造成 RCE、任意文件读写、敏感凭据读取、权限绕过；或 XSS 可调用 preload/IPC/Node 能力造成上述危害；或 XSS 可调用超出普通浏览器权限的 TCP/HTTP 外连能力 |
| **中危** | 正常用户可触发 XSS 或危险能力，但未证明 RCE/文件/敏感数据等高危后果；或需额外交互、特殊配置、复杂前置条件 |
| **低危** | 安全配置不佳、理论风险、仅开发/调试模式可触发、普通浏览器权限范围内的问题，或暂无明确用户可控输入 |
| **待验证** | 存在 source/sink/能力线索，但缺少触发条件、调用链、默认配置、动态现象或正常用户复现路径 |
| **不可达** | 危险 API 存在，但无用户可控输入、无默认路径、被有效 sanitizer/白名单阻断，或仅死代码 |

### 3.2 证据强度

| 级别 | 定义 |
|------|------|
| **A** | source → persistence/transform → sink → natural trigger → 扩权能力 → impact 完整，有可执行复现步骤或 PoC |
| **B** | source → sink → trigger 可达，但扩权能力或动态现象待验证 |
| **C** | 危险 API/模板/配置存在，但 source、trigger、窗口权限或正常用户路径不完整 |
| **D** | 仅配置加固项、理论风险或安全基线偏离 |

### 3.3 汇报门槛

进入"确认漏洞"必须达到：正常用户路径 + 攻击者可准备的输入材料 + 明确触发动作 + 可观察结果。XSS-to-RCE 必须能说明或验证弹计算器；自定义能力必须说明如何被 XSS 或恶意输入调用。

以下内容**不得单独作为"确认高危漏洞"**：

- 仅发现 `nodeIntegration:true`、`contextIsolation:false` 等配置，但无用户可控注入或正常触发链
- 仅通过 DevTools/console 调用 `window.xxx`、`ipcRenderer`、`require` 成功
- 仅通过修改本机数据库、缓存、源码、打包产物触发
- 仅证明 `shell.openExternal` 打开普通 URL，但未证明可造成正常用户危害

## 4. 辅助脚本

可选脚本（位于 skill 目录内，非被审计项目目录内）：

- `scripts/static_scout.py`：递归扫描，列出 XSS source/sink、HTML 属性上下文模板、开发者工具攻击面、deep link/recent project、Electron 配置、preload/IPC、危险能力、asar 文件候选。**脚本只是辅助发现线索，不能替代人工数据流和可达性分析。**
- `scripts/extract_asar_safe.sh`：安全解包 `.asar` 文件（不执行代码、不联网安装依赖）。

```bash
python3 .agents/skills/electron-client-security-audit/scripts/static_scout.py . \
  --out audit-artifacts/static_scout_report.md \
  --include-sourcemaps \
  --max-bytes 20000000
```

禁止执行被审计项目 `node_modules/.bin/*` 下的工具。若脚本不存在，不中断审计，改为手工分析。

## 5. 审计流程

### 5.1 建立窗口/权限地图

1. 列出目录结构：`package.json`、构建配置（`electron-builder`/`forge`/`vite`/`webpack`）、`src/`、`app/`、`renderer/`、`main/`、`preload/`、`dist/`、`release/`、`resources/`、`*.asar`。
2. 查找 Electron 主进程入口、renderer 入口、preload 脚本、路由、IPC handler、webview、BrowserView、BrowserWindow 创建点。
3. 发现 `.asar` 时，解包到 `audit-artifacts/asar-unpacked/<asar-name>/` 后审计（不执行解包出的代码）。
4. 建立窗口/权限地图：主窗口、欢迎页、recent project 页、编译/构建面板、日志面板、预览页、Prompt/Dialog/Modal、设置页、webview、BrowserView、OAuth/远端页、自定义协议落地页。
5. 对每个窗口记录：创建位置、`loadURL/loadFile`、路由、`webPreferences`（`nodeIntegration`、`contextIsolation`、`sandbox`、`preload`、`enableRemoteModule`、`webviewTag`）、CSP、导航限制。

> 不要等确认 XSS 后才看 Electron 配置。窗口权限地图是判断漏洞影响的前置证据；但配置问题必须与用户可控触发链结合后才能升级为可汇报漏洞。

### 5.2 开发者工具 / IDE / 小程序工具专项模式

如果目标是 IDE、开发者工具、小程序开发者工具、低代码编辑器、打包工具、调试器、插件宿主、预览器，或任何会打开第三方项目的 Electron 客户端，必须进入"恶意项目输入面"审计模式。

核心威胁模型：攻击者构造看似正常的第三方项目/deep link/项目配置/源码片段/构建错误/recent project 记录，让受害开发者用客户端打开、编译、预览、删除或管理该项目。

**必须追踪的 source：**

- 第三方项目目录名、文件名、路径 basename、workspace 名称
- `projectUri`、deep link/custom protocol、`.url` 文件、CLI 参数、`process.argv`、`open-url`、`second-instance`
- `package.json`、项目配置、小程序配置、页面路径、插件配置、依赖/脚本名称
- 项目源码内容（尤其是语法错误、注释、字符串、异常代码片段）
- 编译器、打包器、linter、type checker、source map、构建失败信息
- recent project、history、cache、localStorage、IndexedDB、SQLite、JSON 配置中的项目记录
- 导入/打开项目、预览、编译、构建、上传、删除、重命名等 UI 流程

**必须审计的 sink / 渲染点：**

- 编译错误面板、构建日志、代码帧、错误高亮、点击定位文件的链接
- recent project 列表、项目卡片、项目名称、路径展示
- 右键菜单、删除确认、重命名弹窗、Prompt/Input/Modal/Dialog
- 项目详情页、欢迎页、最近打开页、异常项目提示页
- Markdown/HTML/ANSI 日志渲染、语法高亮、diff viewer、stack trace viewer
- 任何 HTML 字符串模板：`<input value="${x}">`、`title="${x}"`、`href="${x}"`、`src="${x}"`、`data-*="${x}"` 等属性上下文
- 任何将项目数据拼接进 HTML 后写入 `innerHTML`、`outerHTML`、`insertAdjacentHTML`、`document.write`、`loadURL(data:text/html,...)`、Prompt 模板或自定义 modal 的逻辑

**必须枚举的自然用户触发动作：**

打开/导入项目 → 编译/预览/构建 → 查看错误日志 → 点击错误项/代码帧/文件路径/高亮片段 → 右键异常项目 → 删除/重命名/从 recent project 移除 → 打开项目详情/设置/上传/预览窗口 → 关闭异常弹窗/聚焦输入框/触发 `autofocus`/`onload`/`onerror` 等事件

如果项目可控内容进入上述 UI，必须做 source → persistence/transform → sink → trigger 的二阶链路分析，不能只检查是否存在直接 `innerHTML`。

### 5.3 审计 XSS 与 HTML 上下文注入

**常见输入源：**

- `location.href/search/hash`、`URLSearchParams`、路由参数、query、deep link/custom protocol
- IPC：`ipcRenderer.on/invoke/send`、`webContents.send`、`ipcMain.handle/on`
- `postMessage`、`message` event、`BroadcastChannel`
- 远端 API 响应、本地配置文件、缓存、数据库、localStorage/sessionStorage、IndexedDB
- 剪贴板、拖拽文件、打开文件、导入项目、日志/Markdown/HTML 预览、富文本编辑器
- `<webview>`、BrowserView、iframe、外部 URL、OAuth 回调、更新公告等半可信内容

**常见危险 sink：**

- 原生 DOM：`innerHTML`、`outerHTML`、`insertAdjacentHTML`、`document.write`、`DOMParser(..., 'text/html')` 后插入、`srcdoc`、`Range.createContextualFragment`
- 框架：React `dangerouslySetInnerHTML`，Vue `v-html`，Angular `bypassSecurityTrustHtml`，Svelte `{@html}`，lit-html `unsafeHTML`
- 模板/渲染：未安全处理的 Markdown/HTML 渲染、Handlebars/Mustache/EJS/Nunjucks 原始 HTML 输出、marked/markdown-it 配置允许 HTML、ANSI/日志 HTML 化
- 脚本执行：`eval`、`new Function`、动态 `import()`、字符串形式 `setTimeout/setInterval`
- URL/属性上下文：`href/src` 可控且允许 `javascript:`、事件属性 `on*`、CSS 注入可转脚本的特殊场景

**HTML 属性上下文注入专项规则：**

不要只搜索 `innerHTML`。凡是将不可信数据拼接到 HTML 字符串、模板字符串或 Prompt/Modal/Dialog 模板中，都必须按上下文判断是否正确转义。

高危模式：`<input value="${x}">` | `<div title="${x}">` | `<a href="${x}">` | `<img src="${x}">` | `<span data-x="${x}">` | `'<input value="' + x + '">'` | `loadURL('data:text/html,' + html)` | `new Prompt({ value: x })` 且内部用 HTML 模板渲染

检查重点：双引号/单引号/反引号是否被属性上下文转义；是否可闭合属性后注入事件属性或新标签；是否存在 `autofocus`、`onload`、`onerror`、`onclick`、`contextmenu` 等自然触发点；是否只做了 HTML 文本节点转义却没有做属性上下文转义。

判断 XSS 时区分：输入是否真实可控；是否经过可信 sanitizer/编码（DOMPurify、sanitize-html、严格模板自动转义、Trusted Types、CSP）；sanitizer 配置是否允许危险标签/属性/协议；sink 所在窗口/路由是否用户可触发；XSS 所在上下文（renderer/webview/iframe/远端页面）的后续危害不同。

### 5.4 二阶 XSS / recent project / deep link 链路

对 deep link、custom protocol、CLI 参数、projectUri、recent project、history/cache/database 中的项目记录，必须按二阶 XSS 分析。追踪链路：

1. 外部输入如何进入客户端（deep link、`.url`、命令行、拖拽、打开项目）
2. 是否被写入 recent project、配置文件、缓存、localStorage、IndexedDB、SQLite 或 JSON
3. **序列化/反序列化过程中 payload 是否被破坏**（如 JSON.stringify/parse、`path.basename()` 截断）
4. 后续哪些 UI 读取并展示该数据
5. 展示时进入什么上下文（HTML 文本/HTML 属性/URL/CSS/JS/Prompt 模板）
6. 触发是否依赖自然操作（右键、删除、重命名、点击异常项目、查看详情）
7. 触发窗口是否具有 Node 能力、preload 能力、IPC 危险能力或关闭 contextIsolation

不要因为 deep link 打开时没有立即执行就判定不可利用。若能证明"先污染 recent project，后续用户右键/删除/重命名触发"，应按真实二阶漏洞处理。

### 5.5 preload / IPC / 主进程危险能力独立审计

不要只在确认 XSS 后才审计 preload/IPC。必须独立梳理 renderer 可调用的高危能力，标注调用条件：已确认可被不可信 renderer 调用 / 仅可信 renderer 可调用 / 需 XSS 或项目记录污染后调用 / 暂未证明可达。

**重点审计对象：**

- `contextBridge.exposeInMainWorld(...)` 暴露的对象、方法、参数
- `window.xxx = ...`、全局变量、DOM 注入 API、legacy preload 注入
- `ipcRenderer.invoke/send/on` 包装器是否允许任意 channel 或任意参数透传
- 主进程 `ipcMain.handle/on` 是否有危险操作且缺少鉴权、来源校验、参数校验
- `event.senderFrame.url`、`webContents.id`、窗口来源、协议、路径、项目 ID 是否校验

**重点寻找的能力：**

| 类别 | 具体能力 |
|------|---------|
| 命令执行 | `child_process.exec/spawn/execFile`、`node-pty`、terminal/open shell |
| 网络（TCP 外连 = 独立高危网络能力） | **`net.createConnection` / `net.connect` / `net.Socket` — 见下方专项说明**；`http/https.request`、WebSocket、自定义 TCP/UDP |
| 文件系统 | 任意读写、覆盖启动项、写入脚本/插件/配置、路径穿越、解压写入 |
| Electron 高危 API | `shell.openExternal`、`shell.openPath`、`dialog`、`clipboard`、`desktopCapturer`、`nativeImage`、`protocol`、`session`、`webContents`、`BrowserWindow`、`remote`、`@electron/remote` |
| 加载与导航 | 任意 URL 打开、`loadURL`、`window.open`、webview `src`、外部协议处理 |
| 认证/敏感数据 | token、cookie、keychain、`safeStorage`、配置、日志、数据库访问 |

> **🔥 `net.createConnection` / `net.connect` / `net.Socket` = 独立高危网络能力**：Node.js 原生 TCP socket 一旦通过 preload/contextBridge 暴露给渲染进程，即使 `nodeIntegration:false`，XSS 也可建立到任意地址的 **raw TCP 双向通道**。该通道完全绕过浏览器同源/CORS 策略。攻击者组合 XSS 本身的 JS 执行能力（`socket.write()` 下发指令 + `socket.on('data')` 接收结果），即可实现交互式远程控制。若同进程还暴露了 IPC 或命令执行，则直接构成完整反向 Shell。**审计时必须将此能力独立标记为高危网络能力，不得仅归类为"网络信息泄露"。**

> 特别注意 `shell.openExternal`：如果 URL 部分可控（scheme 固定但 path 可控），需分析在不同平台上的实际风险。检查是否可通过 `file://` 协议打开本地可执行文件或通过自定义协议处理器绕过检查。

### 5.6 本地服务连接来源校验

客户端可能在本地监听 HTTP/WebSocket/TCP 服务（如 `127.0.0.1:7805`）用于本地 IPC、同步、代理中转等。若未对连接来源做 Origin/Referer 校验，攻击者可通过外部恶意网站、本地 HTML 页面、恶意项目中的 webview 等绕过客户端权限模型直连本地服务。

**可利用入口：** 外部恶意网站通过 WebSocket/fetch 直连本地端口（跨站连接攻击）；本地恶意 HTML（`file://` 打开或嵌入 iframe）；恶意项目通过 webview 或 BrowserWindow 加载的远程页面；浏览器中打开的恶意网页（若服务绑定 `127.0.0.1` 且浏览器可发起跨域请求）。

**危害：** 未授权读取用户认证态数据；劫持代理配置中转流量；窃取本地存储的 token/session/cookie；批量枚举用户数据。

**检测方法：**

1. 扫描 `server.listen`、`new WebSocketServer`、`http.createServer`、`express()`、`net.createServer` 等本地监听
2. 检查是否验证 `Origin`/`Referer` 头
3. 检查 CORS 配置（`Access-Control-Allow-Origin: *`）或完全无校验
4. 检查绑定地址是 `127.0.0.1` 还是 `0.0.0.0`
5. 检查是否要求自定义认证 token 或 session 校验
6. 动态验证：启动客户端后，通过独立浏览器/进程检测是否能直连本地端口获取业务数据

### 5.7 其他检查项

- **webview/BrowserView**：检查 `preload` 属性是否可控（若 src 和 preload 同时可控可导致注入）、`partition` 是否与主窗口共享 session（共享 cookie 风险）、`webPreferences` 是否比主窗口权限更高、与主 renderer 的 postMessage/IPC 桥接是否有来源校验
- **自定义协议处理器**：除接收端（`app.on('open-url')`）外，检查发送端（`protocol.registerFileProtocol` 等）是否可被利用绕过安全检查
- **自动更新**：检查更新机制是否使用 HTTPS、是否验证更新包签名、更新 URL 是否可控

## 6. XSS-to-RCE 与自定义能力链路分析

### 6.1 情况 A：`nodeIntegration:true`

若 XSS 所在 renderer 启用了 Node 集成，评估 XSS 是否可直接访问 Node.js/Electron API 形成本地命令执行。

确认要求：必须先证明 XSS 来源于攻击者可控输入且能通过正常用户操作触发；必须证明触发窗口与 XSS 所在窗口一致且该窗口 `nodeIntegration:true`（注意交叉验证 `sandbox` 是否开启——开启时即使 `nodeIntegration:true` 也会受限；以及 CSP 是否阻止 inline script）；PoC 只用计算器作为检测标准。不满足条件的降级为待验证并记录缺失项。

### 6.1.1 情况 A-2：preload/contextBridge 暴露了 `net.createConnection` / `net.connect` / `net.Socket`（TCP 外连 = 独立高危网络能力）

**这是独立于 `nodeIntegration` 的高危网络能力，必须独立审计和汇报。**

即使 `nodeIntegration:false` 且 `contextIsolation:true`，只要 preload 通过 `contextBridge.exposeInMainWorld` 或 `global` 挂载暴露了 Node.js 原生 TCP socket 创建能力（`net.createConnection`、`net.connect`、`net.Socket`），XSS 即可：

1. 调用暴露的 API 创建到**任意地址**的 raw TCP 连接
2. 获得全双工 Socket 对象（`socket.write()` 发送 + `socket.on('data')` 接收）
3. 该通道**完全绕过浏览器同源策略、CORS、Content-Security-Policy**
4. 攻击者通过 TCP 通道下发指令，XSS payload 在渲染进程执行后将结果通过同一 socket 回传
5. 形成**交互式远程控制**（C2 等效），不依赖 `child_process`

**确认要求（loopback 验证）：**
- 在本地 `127.0.0.1:<port>` 启动 TCP 监听（`net.createServer` 或 `nc -l`）
- 通过 XSS 调用 `createConnection({host:'127.0.0.1', port:<port>})`
- 双向收发固定 benign 字符串（如 `audit-proof`）
- 服务端确认收到消息并回复，客户端确认收到回复
- 结论写为："XSS 可调用 TCP 外连能力，可建立到任意地址的 raw TCP 双向通道，具备被滥用为反连/远程控制前置能力的风险"

**若同时暴露了以下能力，直接构成完整反向 Shell：**
- `ElectronIpcRenderer` / `ipcRenderer`：TCP 为 C2 通道，IPC 执行主进程操作
- `child_process.spawn/exec` / `node-pty`：TCP 通道 + 直接命令执行 = 完整反向 Shell
- `shell.openPath` / 任意文件读写：TCP 通道 + 文件操作

**严重性判定：**
- 仅暴露 `net.createConnection`（无其他执行原语）：**中危到高危**（取决于是否可接触敏感数据、内网探测或认证态）
- `net.createConnection` + IPC/命令执行/文件读写：**高危**（完整反向 Shell / 远程控制）
- `net.createConnection` + `nodeIntegration:true`：**高危**（RCE 无可争议）

审计时必须将 `net.createConnection` 的暴露独立标记，不得将其与普通 HTTP/WebSocket 网络能力混为一谈。

### 6.2 情况 B：`nodeIntegration:false`，但存在 preload/custom API

无论 `contextIsolation` 是 true 还是 false，都要分析 XSS 能否调用 preload 暴露的能力。重点寻找：命令执行、文件系统、网络（TCP/UDP/HTTP/WebSocket 外连）、协议/导航（`shell.openExternal`、任意 URL、deep link）、敏感数据（token、cookie、keychain、safeStorage、数据库）。

网络能力验证只用本地 loopback：启动监听 `127.0.0.1:<port>` → 通过 XSS 调用暴露的网络 API 连接 → 观察收到固定 benign 字符串 → 结论写为"XSS 可调用外连能力，具备被滥用为反连前置能力的风险"。

### 6.3 情况 C：`contextIsolation:false`

判断 XSS 是否能直接访问 preload 中的 Node 对象、闭包、全局变量，或通过 prototype pollution / DOM clobbering 影响 preload 逻辑。即使没有显式 `contextBridge`，也要审计 preload 是否把能力挂到 `window` 或 DOM。

### 6.4 情况 D：sandbox/权限较强的 webview 或 iframe

若 XSS 位于 `<webview>` 或 iframe，需确认 preload、`nodeintegration`、`allowpopups`、`webpreferences`、`partition`、IPC bridge、postMessage bridge，分析是否能从子上下文跨到主 renderer 或主进程。

## 7. 利用链与复现步骤写法

### 7.1 确认漏洞的复现模板

每个确认漏洞必须按以下结构写，且不能只写"详见 PoC 文件"：

```markdown
### 漏洞标题

**影响对象**
使用该客户端打开第三方项目/点击 deep link/查看某类内容的正常用户。

**漏洞原因**
说明可控数据进入了哪个 HTML/属性/脚本/URL 上下文，或调用了哪个 preload/IPC 危险能力。

**攻击者准备**
1. 攻击者准备什么材料：恶意项目、`.url` 文件、deep link、恶意文件名、恶意源码片段、恶意网页等。
2. 关键 payload（给出编码前与编码后的关键片段）。
3. 说明 payload 是无害验证载荷（alert/DOM 标记/弹计算器/loopback 连接）。

**受害者复现步骤**
1. 安装/打开目标客户端，说明版本。
2. 受害者通过正常入口打开攻击者准备的材料（打开项目、点击 `.url`、导入目录、触发编译、查看日志、右键异常项目、点击错误高亮片段）。
3. 每一步写清楚用户在界面上看到什么，下一步为什么是自然行为。
4. 写清楚触发点（点击哪个按钮/面板/高亮/右键菜单/弹窗）。
5. 写清楚预期结果（alert/DOM 高亮/计算器弹出/本地监听收到连接）。

**证明现象**
- 现象 1：payload 进入 DOM，证明注入生效。
- 现象 2：alert 或可见标记出现，证明 JavaScript 执行。
- 现象 3：计算器弹出证明 XSS-to-RCE；或 loopback 收到连接证明危险网络能力可被调用。

**代码证据**
- source / persistence / sink / trigger / capability（各附文件:行号）

**影响**
说明对正常用户的实际危害，不夸大。

**修复建议**
按根因给出输入校验、上下文转义、关闭 Node、启用 contextIsolation、收敛 preload/IPC、来源校验、参数 schema 校验等建议。
```

### 7.2 禁止作为确认漏洞的写法

以下写法必须降级为"待验证"，不能作为确认漏洞复现：

- "打开 DevTools，在 console 执行 `window.xxx(...)`"
- "手工编辑 localStorage/IndexedDB/SQLite/recent project JSON 后刷新"
- "修改客户端源码/HTML/打包文件后打开"
- "假设存在 XSS 后即可 RCE"但未给出 XSS 的实际 source、sink 和自然触发动作
- "配置中存在 `nodeIntegration:true`，因此高危"但没有用户可控注入点
- "`openExternal` 可打开 URL，因此高危"但未证明攻击者如何让正常用户触发以及能造成什么实际危害

### 7.3 开发者工具类复现模板

**模板 A：编译错误 / 代码帧注入**

```markdown
复现步骤：
1. 攻击者准备恶意项目 `<poc-project>`，其中 `<file>` 包含故意构造的语法错误或源码片段。
2. 受害者使用目标客户端打开该项目。
3. 受害者点击"编译/预览/构建"。
4. 编译失败后，受害者打开"构建/编译/错误日志"面板。
5. 在错误代码帧中可以看到 `<proof>` 或明显高亮片段，说明项目源码已进入日志 DOM。
6. 受害者点击错误项/高亮片段/文件路径以定位错误。
7. 观察到 alert/计算器/本地 loopback 连接，证明漏洞触发。
```

必须说明：该点击是开发者定位错误的自然操作；payload 来自项目源码、文件名或错误 message；触发窗口的 Electron 权限是什么。

**模板 B：deep link 污染 recent project**

```markdown
复现步骤：
1. 攻击者准备恶意 deep link 或 `.url` 文件，其中 projectUri/路径 basename/项目名包含无害验证 payload。
2. 受害者点击该 deep link 或 `.url` 文件。
3. 客户端启动并把异常项目写入 recent project；此时可能打不开项目，但 payload 已持久化。
4. 受害者下次打开客户端，在最近项目列表看到异常项目。
5. 受害者按照正常逻辑右键异常项目，或点击删除/重命名/移除。
6. 触发 Prompt/菜单/弹窗渲染，payload 执行。
7. 观察到 alert/计算器/本地 loopback 连接。
```

必须说明：deep link 编码前后的 payload、recent project 如何持久化、哪个 UI 读取并渲染、右键/删除为什么是自然操作。

### 7.4 普通客户端复现模板

若目标不是开发者工具，必须找到等价的正常用户入口（打开分享的笔记/文档/网页/链接、导入文件、点击消息/公告/历史记录/搜索结果/附件/外部链接、打开展示远端内容或本地缓存的页面）。只能通过 DevTools 或手工改缓存触发的，不能作为确认漏洞。

## 8. 开发者工具回归测试场景

审计开发者工具/IDE/小程序工具时，至少检查以下两个回归场景：

### 场景 A：编译错误 / 代码帧注入

- 恶意项目源码能否影响编译错误内容、代码帧、stack trace、日志面板
- 错误内容是否被 HTML 渲染或进入属性上下文
- 文件路径、源码片段、错误 message 是否被转义
- 点击错误项、高亮片段、定位文件时是否触发
- 所在窗口是否有 Node 能力、preload 危险能力或关闭 contextIsolation

### 场景 B：deep link 污染 recent project

- deep link / `.url` / custom protocol / CLI 参数是否可控
- `projectUri`、路径 basename、项目名是否会持久化进 recent project
- recent project 的项目名、路径、basename 是否会进入 Prompt/Input/Modal/Dialog 或右键菜单
- 右键、删除、重命名、打开详情等自然操作是否触发
- 触发窗口是否是高权限 Electron renderer，或是否可调用 preload/IPC 危险能力

## 9. 修复建议基线

- 禁用 `nodeIntegration`；启用 `contextIsolation`；启用 `sandbox`；禁用 `enableRemoteModule` / `@electron/remote`
- 避免加载不可信远端内容；若必须加载，隔离到无 Node、无 preload、强 CSP 的窗口或 webview
- 所有 HTML/Markdown/ANSI 日志渲染使用严格 sanitizer，禁用危险协议、事件属性、raw HTML
- 避免 `innerHTML` 等危险 sink；优先使用文本 API 或框架自动转义
- 对 HTML 属性上下文做专用转义，不能只做文本节点转义
- 为 IPC 建立固定 channel 白名单，禁止 renderer 任意指定 channel，所有参数做 schema 校验
- preload 只暴露最小必要 API，**严禁暴露 `net.createConnection` / `net.connect` / `net.Socket`（= 独立高危网络能力）**、`ipcRenderer`、`fs`、`child_process`、`shell` 等能力
- `shell.openExternal`、导航、deep link、自定义协议必须做 scheme/host/path 白名单
- 强化 CSP，移除 `unsafe-inline`、`unsafe-eval`，限制 `script-src`、`connect-src`、`frame-src`
- 对文件读写使用固定目录、路径规范化、扩展名/大小/内容校验
- 对 recent project、history、cache、数据库中的用户可控字段做统一编码和上下文转义
- 报告中不得原样展示密钥、token、cookie、私钥、会话凭据、个人隐私路径或其他敏感值
