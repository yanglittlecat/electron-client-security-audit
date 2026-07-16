# 客户端产品安全漏洞审计报告

> 项目/目录：`<当前工作目录>`  
> 审计时间：`<YYYY-MM-DD>`  
> 审计人员/工具：支持 Agent Skills 的客户端 + electron-client-security-audit Skill
> 审计类型：授权静态安全审计，重点覆盖 XSS、Electron 配置、开发者工具恶意项目输入面、deep link/recent project 二阶链路、preload/contextBridge/IPC、自定义函数与 XSS-to-RCE 链路。

## 1. 结论摘要

- 总体风险等级：`高/中/低/未发现确认漏洞`
- 确认漏洞数量：`<n>`
- 待验证风险点数量：`<n>`
- 最高影响：`XSS / XSS-to-RCE / 任意文件读写 / 任意外连 / 敏感信息读取 / 其他`
- 是否发现开发者工具恶意项目链路：`是/否/不适用`
- 是否生成验证项目：`是/否`
- 验证项目目录：`<../audit-poc-... 或 不适用>`

## 2. 审计范围与限制

### 2.1 审计范围

- 当前目录：`<path>`
- 关键入口：`<main/preload/renderer/package/asar>`
- 已解包 asar：`<paths>`
- 已审计模块：`<list>`
- 开发者工具专项入口：`<打开项目/deep link/recent project/编译面板/日志面板/Prompt/右键菜单/其他>`

### 2.2 限制说明

- 未执行破坏性或真实攻击操作。
- RCE 验证仅建议使用本地计算器或等价 benign 命令。
- 网络能力验证仅建议使用本地 loopback，不包含真实反连或外传。
- 未读取审计范围外的无关文件。
- `<无法读取/未覆盖/需动态验证的内容>`

## 3. 严重性与证据强度标准

### 3.1 严重性

- 高危：默认或低交互可触发 XSS，且所在 Electron 上下文可扩大为 RCE、任意文件读写、敏感凭据读取、任意外连能力；或无需 XSS 即可通过 IPC/协议/恶意项目触发高危能力。
- 中危：默认可触发 XSS，但未发现 Node/preload/IPC 扩权链路；或危险能力需要额外权限、特殊配置、复杂交互。
- 低危：安全配置不佳、理论风险、仅开发模式可触发、或暂无明确用户可控输入。
- 待验证：存在 source/sink/能力线索，但缺少触发条件、调用链、默认配置或环境证据。
- 不可达：危险 API 存在，但无用户可控输入、无默认路径、被有效 sanitizer/白名单阻断，或仅死代码。

### 3.2 证据强度

- A：source → persistence/transform → sink → trigger → privilege 链完整，有默认触发步骤或验证项目。
- B：source → sink 可达，触发或权限链基本明确，但缺少完整动态验证。
- C：危险 sink/API 存在，source、trigger 或窗口权限不完整。
- D：仅配置加固项或理论风险。

## 4. 漏洞总览

| 编号 | 标题 | 严重性 | 状态 | 证据强度 | 影响组件 | 证据 |
|---|---|---:|---|---|---|---|
| V-001 | `<标题>` | 高/中/低 | 已确认/待验证/不可达 | A/B/C/D | `<窗口/功能>` | `<文件:行号>` |

## 5. Electron 窗口地图

| 窗口/组件 | 创建位置 | 加载内容 | nodeIntegration | contextIsolation | sandbox | preload | 数据来源 | 风险备注 |
|---|---|---|---|---|---|---|---|---|
| `<主窗口>` | `<file:line>` | `<url/html>` | `<true/false/unknown>` | `<true/false/unknown>` | `<true/false/unknown>` | `<path/none>` | `<项目/日志/API>` | `<说明>` |

## 6. 开发者工具专项攻击面检查

> 仅当目标是 IDE、开发者工具、小程序开发者工具、低代码编辑器、调试器、插件宿主、预览器或任何会打开第三方项目的客户端时填写。

| 攻击面 | 输入是否可控 | 持久化/转换 | 渲染点 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|
| 项目目录名/文件名/basename | `<是/否/不确定>` | `<recent/cache/无>` | `<项目列表/Prompt/日志>` | `<右键/删除/打开>` | `<高/低/未知>` | `<说明>` |
| projectUri/deep link | `<是/否/不确定>` | `<recent/cache/无>` | `<欢迎页/异常项目/Prompt>` | `<点击链接/右键删除>` | `<高/低/未知>` | `<说明>` |
| 编译错误/代码帧/日志 | `<是/否/不确定>` | `<build output/source map>` | `<编译面板/日志面板>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |
| Prompt/Input/Modal/Dialog | `<是/否/不确定>` | `<模板变量>` | `<HTML 属性/HTML 文本>` | `<打开/聚焦/onload>` | `<高/低/未知>` | `<说明>` |

## 7. 详细发现

### V-001：`<漏洞标题>`

**严重性**：`高/中/低`  
**状态**：`已确认/待验证/不可达`  
**证据强度**：`A/B/C/D`  
**影响组件**：`<窗口/路由/功能/进程>`  
**证据位置**：`<file:line>`  
**验证项目**：`<../audit-poc-... 或 不适用>`

#### 7.1 漏洞原因

`<说明用户可控输入如何进入危险 sink，配置或 API 为什么导致漏洞。>`

#### 7.2 可达性分析

- Source：`<输入源，例如 projectUri/deep link/项目源码/文件名/编译错误/API 响应>`
- Persistence/Transform：`<recent project/basename/cache/source map/日志格式化/模板变量>`
- Sanitizer/Encoder：`<处理逻辑，是否按上下文转义>`
- Sink：`<危险 sink，例如 innerHTML、Prompt 属性模板、v-html、loadURL data:text/html>`
- Context：`<HTML 文本/HTML 属性/URL/CSS/JS/Markdown/日志 HTML>`
- Trigger：`<触发条件，例如打开项目、编译、点击错误项、右键异常项目、删除、重命名>`
- Privilege：`<nodeIntegration/contextIsolation/sandbox/preload/IPC 能力>`
- 默认可触发：`是/否/不确定`

#### 7.3 影响

`<XSS、XSS-to-RCE、任意文件读写、任意外连、敏感信息读取、权限绕过等。>`

#### 7.4 利用链

1. `<步骤 1：输入进入 source>`
2. `<步骤 2：被持久化或转换，例如 recent project/basename/编译错误>`
3. `<步骤 3：到达 XSS sink>`
4. `<步骤 4：通过自然动作触发>`
5. `<步骤 5：结合 Electron 配置或 preload/custom API 扩大影响>`

> 注意：不得提供真实反连、下载执行、外传或破坏性 payload；RCE 只用本地计算器作为 benign 验证标准。

#### 7.5 无害验证步骤

- XSS 验证：`<alert/DOM 标记/console log>`
- RCE 验证：`<仅计算器或等价 benign 命令，需授权隔离环境>`
- 网络能力验证：`<仅本地 loopback，例如本地测试服务；不使用外部地址>`
- 验证项目文件：`<README/最小项目文件/触发文件>`
- 预期现象：`<可观测结果>`
- 清理方式：`<删除验证项目/关闭客户端/清理 recent project>`

#### 7.6 修复建议

- `<输出编码/sanitizer/移除危险 sink>`
- `<属性上下文转义/URL 协议白名单>`
- `<Electron 安全配置>`
- `<preload/IPC 最小权限与参数校验>`
- `<CSP/导航/外部协议限制>`
- `<recent project/deep link/日志/代码帧专项修复>`

## 8. Electron 安全配置检查

| 配置项 | 当前值 | 风险 | 建议 |
|---|---|---|---|
| nodeIntegration | `<true/false/unknown>` | `<说明>` | `false` |
| contextIsolation | `<true/false/unknown>` | `<说明>` | `true` |
| sandbox | `<true/false/unknown>` | `<说明>` | `true` |
| enableRemoteModule | `<true/false/unknown>` | `<说明>` | `false` |
| webSecurity | `<true/false/unknown>` | `<说明>` | `true` |
| allowRunningInsecureContent | `<true/false/unknown>` | `<说明>` | `false` |
| webviewTag | `<true/false/unknown>` | `<说明>` | 按需关闭或隔离 |
| nodeIntegrationInWorker | `<true/false/unknown>` | `<说明>` | `false` |
| nodeIntegrationInSubFrames | `<true/false/unknown>` | `<说明>` | `false` |
| nativeWindowOpen | `<true/false/unknown>` | `<说明>` | 按需关闭并限制 |

## 9. 自定义函数 / preload / IPC 风险清单

| API/Channel | 暴露位置 | 主进程处理 | 能力 | 可被恶意项目自然流程调用 | 可被 XSS 调用 | 风险 | 建议 |
|---|---|---|---|---|---|---|---|
| `<api>` | `<preload file>` | `<ipcMain handler>` | `<fs/net/exec/etc>` | 是/否/不确定 | 是/否/不确定 | `<风险>` | `<建议>` |

## 10. Deep link / 协议 / recent project 检查

| 入口 | 处理位置 | 参数 | 是否持久化 | 展示位置 | 上下文 | 触发动作 | 结论 |
|---|---|---|---|---|---|---|---|
| `<protocol/projectUri>` | `<file:line>` | `<参数>` | `<recent/cache>` | `<欢迎页/Prompt>` | `<属性/HTML/文本>` | `<右键/删除>` | `<说明>` |

## 11. 编译错误 / 日志 / 代码帧检查

| 输入 | 处理位置 | 渲染位置 | 渲染方式 | 是否转义 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|---|
| `<源码片段/文件名/error.message>` | `<file:line>` | `<编译面板>` | `<innerHTML/模板>` | `<是/否/不确定>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |

## 12. 残余风险与后续建议

- `<需动态测试的路由/功能>`
- `<需补充的构建产物/asar/源码>`
- `<建议加入 CI 安全检查项>`
- `<建议补充的验证项目或回归用例>`

## 13. 附录：关键证据摘录

```text
<必要的最短代码片段，避免泄露敏感信息>
```
# 客户端产品安全漏洞审计报告

> 项目/目录：`<当前工作目录>`  
> 审计时间：`<YYYY-MM-DD>`  
> 审计人员/工具：支持 Agent Skills 的客户端 + electron-client-security-audit Skill
> 审计类型：授权静态安全审计，重点覆盖 XSS、Electron 配置、开发者工具恶意项目输入面、deep link/recent project 二阶链路、preload/contextBridge/IPC、自定义函数与 XSS-to-RCE 链路。

## 1. 结论摘要

- 总体风险等级：`高/中/低/未发现确认漏洞`
- 确认漏洞数量：`<n>`
- 待验证风险点数量：`<n>`
- 最高影响：`XSS / XSS-to-RCE / 任意文件读写 / 任意外连 / 敏感信息读取 / 其他`
- 是否发现开发者工具恶意项目链路：`是/否/不适用`
- 是否生成验证项目：`是/否`
- 验证项目目录：`<../audit-poc-... 或 不适用>`

## 2. 审计范围与限制

### 2.1 审计范围

- 当前目录：`<path>`
- 关键入口：`<main/preload/renderer/package/asar>`
- 已解包 asar：`<paths>`
- 已审计模块：`<list>`
- 开发者工具专项入口：`<打开项目/deep link/recent project/编译面板/日志面板/Prompt/右键菜单/其他>`

### 2.2 限制说明

- 未执行破坏性或真实攻击操作。
- RCE 验证仅建议使用本地计算器或等价 benign 命令。
- 网络能力验证仅建议使用本地 loopback，不包含真实反连或外传。
- 未读取审计范围外的无关文件。
- `<无法读取/未覆盖/需动态验证的内容>`

## 3. 严重性与证据强度标准

### 3.1 严重性

- 高危：默认或低交互可触发 XSS，且所在 Electron 上下文可扩大为 RCE、任意文件读写、敏感凭据读取、任意外连能力；或无需 XSS 即可通过 IPC/协议/恶意项目触发高危能力。
- 中危：默认可触发 XSS，但未发现 Node/preload/IPC 扩权链路；或危险能力需要额外权限、特殊配置、复杂交互。
- 低危：安全配置不佳、理论风险、仅开发模式可触发、或暂无明确用户可控输入。
- 待验证：存在 source/sink/能力线索，但缺少触发条件、调用链、默认配置或环境证据。
- 不可达：危险 API 存在，但无用户可控输入、无默认路径、被有效 sanitizer/白名单阻断，或仅死代码。

### 3.2 证据强度

- A：source → persistence/transform → sink → trigger → privilege 链完整，有默认触发步骤或验证项目。
- B：source → sink 可达，触发或权限链基本明确，但缺少完整动态验证。
- C：危险 sink/API 存在，source、trigger 或窗口权限不完整。
- D：仅配置加固项或理论风险。

## 4. 漏洞总览

| 编号 | 标题 | 严重性 | 状态 | 证据强度 | 影响组件 | 证据 |
|---|---|---:|---|---|---|---|
| V-001 | `<标题>` | 高/中/低 | 已确认/待验证/不可达 | A/B/C/D | `<窗口/功能>` | `<文件:行号>` |

## 5. Electron 窗口地图

| 窗口/组件 | 创建位置 | 加载内容 | nodeIntegration | contextIsolation | sandbox | preload | 数据来源 | 风险备注 |
|---|---|---|---|---|---|---|---|---|
| `<主窗口>` | `<file:line>` | `<url/html>` | `<true/false/unknown>` | `<true/false/unknown>` | `<true/false/unknown>` | `<path/none>` | `<项目/日志/API>` | `<说明>` |

## 6. 开发者工具专项攻击面检查

> 仅当目标是 IDE、开发者工具、小程序开发者工具、低代码编辑器、调试器、插件宿主、预览器或任何会打开第三方项目的客户端时填写。

| 攻击面 | 输入是否可控 | 持久化/转换 | 渲染点 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|
| 项目目录名/文件名/basename | `<是/否/不确定>` | `<recent/cache/无>` | `<项目列表/Prompt/日志>` | `<右键/删除/打开>` | `<高/低/未知>` | `<说明>` |
| projectUri/deep link | `<是/否/不确定>` | `<recent/cache/无>` | `<欢迎页/异常项目/Prompt>` | `<点击链接/右键删除>` | `<高/低/未知>` | `<说明>` |
| 编译错误/代码帧/日志 | `<是/否/不确定>` | `<build output/source map>` | `<编译面板/日志面板>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |
| Prompt/Input/Modal/Dialog | `<是/否/不确定>` | `<模板变量>` | `<HTML 属性/HTML 文本>` | `<打开/聚焦/onload>` | `<高/低/未知>` | `<说明>` |

## 7. 详细发现

### V-001：`<漏洞标题>`

**严重性**：`高/中/低`  
**状态**：`已确认/待验证/不可达`  
**证据强度**：`A/B/C/D`  
**影响组件**：`<窗口/路由/功能/进程>`  
**证据位置**：`<file:line>`  
**验证项目**：`<../audit-poc-... 或 不适用>`

#### 7.1 漏洞原因

`<说明用户可控输入如何进入危险 sink，配置或 API 为什么导致漏洞。>`

#### 7.2 可达性分析

- Source：`<输入源，例如 projectUri/deep link/项目源码/文件名/编译错误/API 响应>`
- Persistence/Transform：`<recent project/basename/cache/source map/日志格式化/模板变量>`
- Sanitizer/Encoder：`<处理逻辑，是否按上下文转义>`
- Sink：`<危险 sink，例如 innerHTML、Prompt 属性模板、v-html、loadURL data:text/html>`
- Context：`<HTML 文本/HTML 属性/URL/CSS/JS/Markdown/日志 HTML>`
- Trigger：`<触发条件，例如打开项目、编译、点击错误项、右键异常项目、删除、重命名>`
- Privilege：`<nodeIntegration/contextIsolation/sandbox/preload/IPC 能力>`
- 默认可触发：`是/否/不确定`

#### 7.3 影响

`<XSS、XSS-to-RCE、任意文件读写、任意外连、敏感信息读取、权限绕过等。>`

#### 7.4 利用链

1. `<步骤 1：输入进入 source>`
2. `<步骤 2：被持久化或转换，例如 recent project/basename/编译错误>`
3. `<步骤 3：到达 XSS sink>`
4. `<步骤 4：通过自然动作触发>`
5. `<步骤 5：结合 Electron 配置或 preload/custom API 扩大影响>`

> 注意：不得提供真实反连、下载执行、外传或破坏性 payload；RCE 只用本地计算器作为 benign 验证标准。

#### 7.5 无害验证步骤

- XSS 验证：`<alert/DOM 标记/console log>`
- RCE 验证：`<仅计算器或等价 benign 命令，需授权隔离环境>`
- 网络能力验证：`<仅本地 loopback，例如本地测试服务；不使用外部地址>`
- 验证项目文件：`<README/最小项目文件/触发文件>`
- 预期现象：`<可观测结果>`
- 清理方式：`<删除验证项目/关闭客户端/清理 recent project>`

#### 7.6 修复建议

- `<输出编码/sanitizer/移除危险 sink>`
- `<属性上下文转义/URL 协议白名单>`
- `<Electron 安全配置>`
- `<preload/IPC 最小权限与参数校验>`
- `<CSP/导航/外部协议限制>`
- `<recent project/deep link/日志/代码帧专项修复>`

## 8. Electron 安全配置检查

| 配置项 | 当前值 | 风险 | 建议 |
|---|---|---|---|
| nodeIntegration | `<true/false/unknown>` | `<说明>` | `false` |
| contextIsolation | `<true/false/unknown>` | `<说明>` | `true` |
| sandbox | `<true/false/unknown>` | `<说明>` | `true` |
| enableRemoteModule | `<true/false/unknown>` | `<说明>` | `false` |
| webSecurity | `<true/false/unknown>` | `<说明>` | `true` |
| allowRunningInsecureContent | `<true/false/unknown>` | `<说明>` | `false` |
| webviewTag | `<true/false/unknown>` | `<说明>` | 按需关闭或隔离 |
| nodeIntegrationInWorker | `<true/false/unknown>` | `<说明>` | `false` |
| nodeIntegrationInSubFrames | `<true/false/unknown>` | `<说明>` | `false` |
| nativeWindowOpen | `<true/false/unknown>` | `<说明>` | 按需关闭并限制 |

## 9. 自定义函数 / preload / IPC 风险清单

| API/Channel | 暴露位置 | 主进程处理 | 能力 | 可被恶意项目自然流程调用 | 可被 XSS 调用 | 风险 | 建议 |
|---|---|---|---|---|---|---|---|
| `<api>` | `<preload file>` | `<ipcMain handler>` | `<fs/net/exec/etc>` | 是/否/不确定 | 是/否/不确定 | `<风险>` | `<建议>` |

## 10. Deep link / 协议 / recent project 检查

| 入口 | 处理位置 | 参数 | 是否持久化 | 展示位置 | 上下文 | 触发动作 | 结论 |
|---|---|---|---|---|---|---|---|
| `<protocol/projectUri>` | `<file:line>` | `<参数>` | `<recent/cache>` | `<欢迎页/Prompt>` | `<属性/HTML/文本>` | `<右键/删除>` | `<说明>` |

## 11. 编译错误 / 日志 / 代码帧检查

| 输入 | 处理位置 | 渲染位置 | 渲染方式 | 是否转义 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|---|
| `<源码片段/文件名/error.message>` | `<file:line>` | `<编译面板>` | `<innerHTML/模板>` | `<是/否/不确定>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |

## 12. 残余风险与后续建议

- `<需动态测试的路由/功能>`
- `<需补充的构建产物/asar/源码>`
- `<建议加入 CI 安全检查项>`
- `<建议补充的验证项目或回归用例>`

## 13. 附录：关键证据摘录

```text
<必要的最短代码片段，避免泄露敏感信息>
```
# 客户端产品安全漏洞审计报告

> 项目/目录：`<当前工作目录>`  
> 审计时间：`<YYYY-MM-DD>`  
> 审计人员/工具：Codex + electron-client-security-audit skill  
> 审计类型：授权静态安全审计，重点覆盖 XSS、Electron 配置、开发者工具恶意项目输入面、deep link/recent project 二阶链路、preload/contextBridge/IPC、自定义函数与 XSS-to-RCE 链路。

## 1. 结论摘要

- 总体风险等级：`高/中/低/未发现确认漏洞`
- 确认漏洞数量：`<n>`
- 待验证风险点数量：`<n>`
- 最高影响：`XSS / XSS-to-RCE / 任意文件读写 / 任意外连 / 敏感信息读取 / 其他`
- 是否发现开发者工具恶意项目链路：`是/否/不适用`
- 是否生成验证项目：`是/否`
- 验证项目目录：`<../audit-poc-... 或 不适用>`

## 2. 审计范围与限制

### 2.1 审计范围

- 当前目录：`<path>`
- 关键入口：`<main/preload/renderer/package/asar>`
- 已解包 asar：`<paths>`
- 已审计模块：`<list>`
- 开发者工具专项入口：`<打开项目/deep link/recent project/编译面板/日志面板/Prompt/右键菜单/其他>`

### 2.2 限制说明

- 未执行破坏性或真实攻击操作。
- RCE 验证仅建议使用本地计算器或等价 benign 命令。
- 网络能力验证仅建议使用本地 loopback，不包含真实反连或外传。
- 未读取审计范围外的无关文件。
- `<无法读取/未覆盖/需动态验证的内容>`

## 3. 严重性与证据强度标准

### 3.1 严重性

- 高危：默认或低交互可触发 XSS，且所在 Electron 上下文可扩大为 RCE、任意文件读写、敏感凭据读取、任意外连能力；或无需 XSS 即可通过 IPC/协议/恶意项目触发高危能力。
- 中危：默认可触发 XSS，但未发现 Node/preload/IPC 扩权链路；或危险能力需要额外权限、特殊配置、复杂交互。
- 低危：安全配置不佳、理论风险、仅开发模式可触发、或暂无明确用户可控输入。
- 待验证：存在 source/sink/能力线索，但缺少触发条件、调用链、默认配置或环境证据。
- 不可达：危险 API 存在，但无用户可控输入、无默认路径、被有效 sanitizer/白名单阻断，或仅死代码。

### 3.2 证据强度

- A：source → persistence/transform → sink → trigger → privilege 链完整，有默认触发步骤或验证项目。
- B：source → sink 可达，触发或权限链基本明确，但缺少完整动态验证。
- C：危险 sink/API 存在，source、trigger 或窗口权限不完整。
- D：仅配置加固项或理论风险。

## 4. 漏洞总览

| 编号 | 标题 | 严重性 | 状态 | 证据强度 | 影响组件 | 证据 |
|---|---|---:|---|---|---|---|
| V-001 | `<标题>` | 高/中/低 | 已确认/待验证/不可达 | A/B/C/D | `<窗口/功能>` | `<文件:行号>` |

## 5. Electron 窗口地图

| 窗口/组件 | 创建位置 | 加载内容 | nodeIntegration | contextIsolation | sandbox | preload | 数据来源 | 风险备注 |
|---|---|---|---|---|---|---|---|---|
| `<主窗口>` | `<file:line>` | `<url/html>` | `<true/false/unknown>` | `<true/false/unknown>` | `<true/false/unknown>` | `<path/none>` | `<项目/日志/API>` | `<说明>` |

## 6. 开发者工具专项攻击面检查

> 仅当目标是 IDE、开发者工具、小程序开发者工具、低代码编辑器、调试器、插件宿主、预览器或任何会打开第三方项目的客户端时填写。

| 攻击面 | 输入是否可控 | 持久化/转换 | 渲染点 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|
| 项目目录名/文件名/basename | `<是/否/不确定>` | `<recent/cache/无>` | `<项目列表/Prompt/日志>` | `<右键/删除/打开>` | `<高/低/未知>` | `<说明>` |
| projectUri/deep link | `<是/否/不确定>` | `<recent/cache/无>` | `<欢迎页/异常项目/Prompt>` | `<点击链接/右键删除>` | `<高/低/未知>` | `<说明>` |
| 编译错误/代码帧/日志 | `<是/否/不确定>` | `<build output/source map>` | `<编译面板/日志面板>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |
| Prompt/Input/Modal/Dialog | `<是/否/不确定>` | `<模板变量>` | `<HTML 属性/HTML 文本>` | `<打开/聚焦/onload>` | `<高/低/未知>` | `<说明>` |

## 7. 详细发现

### V-001：`<漏洞标题>`

**严重性**：`高/中/低`  
**状态**：`已确认/待验证/不可达`  
**证据强度**：`A/B/C/D`  
**影响组件**：`<窗口/路由/功能/进程>`  
**证据位置**：`<file:line>`  
**验证项目**：`<../audit-poc-... 或 不适用>`

#### 7.1 漏洞原因

`<说明用户可控输入如何进入危险 sink，配置或 API 为什么导致漏洞。>`

#### 7.2 可达性分析

- Source：`<输入源，例如 projectUri/deep link/项目源码/文件名/编译错误/API 响应>`
- Persistence/Transform：`<recent project/basename/cache/source map/日志格式化/模板变量>`
- Sanitizer/Encoder：`<处理逻辑，是否按上下文转义>`
- Sink：`<危险 sink，例如 innerHTML、Prompt 属性模板、v-html、loadURL data:text/html>`
- Context：`<HTML 文本/HTML 属性/URL/CSS/JS/Markdown/日志 HTML>`
- Trigger：`<触发条件，例如打开项目、编译、点击错误项、右键异常项目、删除、重命名>`
- Privilege：`<nodeIntegration/contextIsolation/sandbox/preload/IPC 能力>`
- 默认可触发：`是/否/不确定`

#### 7.3 影响

`<XSS、XSS-to-RCE、任意文件读写、任意外连、敏感信息读取、权限绕过等。>`

#### 7.4 利用链

1. `<步骤 1：输入进入 source>`
2. `<步骤 2：被持久化或转换，例如 recent project/basename/编译错误>`
3. `<步骤 3：到达 XSS sink>`
4. `<步骤 4：通过自然动作触发>`
5. `<步骤 5：结合 Electron 配置或 preload/custom API 扩大影响>`

> 注意：不得提供真实反连、下载执行、外传或破坏性 payload；RCE 只用本地计算器作为 benign 验证标准。

#### 7.5 无害验证步骤

- XSS 验证：`<alert/DOM 标记/console log>`
- RCE 验证：`<仅计算器或等价 benign 命令，需授权隔离环境>`
- 网络能力验证：`<仅本地 loopback，例如本地测试服务；不使用外部地址>`
- 验证项目文件：`<README/最小项目文件/触发文件>`
- 预期现象：`<可观测结果>`
- 清理方式：`<删除验证项目/关闭客户端/清理 recent project>`

#### 7.6 修复建议

- `<输出编码/sanitizer/移除危险 sink>`
- `<属性上下文转义/URL 协议白名单>`
- `<Electron 安全配置>`
- `<preload/IPC 最小权限与参数校验>`
- `<CSP/导航/外部协议限制>`
- `<recent project/deep link/日志/代码帧专项修复>`

## 8. Electron 安全配置检查

| 配置项 | 当前值 | 风险 | 建议 |
|---|---|---|---|
| nodeIntegration | `<true/false/unknown>` | `<说明>` | `false` |
| contextIsolation | `<true/false/unknown>` | `<说明>` | `true` |
| sandbox | `<true/false/unknown>` | `<说明>` | `true` |
| enableRemoteModule | `<true/false/unknown>` | `<说明>` | `false` |
| webSecurity | `<true/false/unknown>` | `<说明>` | `true` |
| allowRunningInsecureContent | `<true/false/unknown>` | `<说明>` | `false` |
| webviewTag | `<true/false/unknown>` | `<说明>` | 按需关闭或隔离 |
| nodeIntegrationInWorker | `<true/false/unknown>` | `<说明>` | `false` |
| nodeIntegrationInSubFrames | `<true/false/unknown>` | `<说明>` | `false` |
| nativeWindowOpen | `<true/false/unknown>` | `<说明>` | 按需关闭并限制 |

## 9. 自定义函数 / preload / IPC 风险清单

| API/Channel | 暴露位置 | 主进程处理 | 能力 | 可被恶意项目自然流程调用 | 可被 XSS 调用 | 风险 | 建议 |
|---|---|---|---|---|---|---|---|
| `<api>` | `<preload file>` | `<ipcMain handler>` | `<fs/net/exec/etc>` | 是/否/不确定 | 是/否/不确定 | `<风险>` | `<建议>` |

## 10. Deep link / 协议 / recent project 检查

| 入口 | 处理位置 | 参数 | 是否持久化 | 展示位置 | 上下文 | 触发动作 | 结论 |
|---|---|---|---|---|---|---|---|
| `<protocol/projectUri>` | `<file:line>` | `<参数>` | `<recent/cache>` | `<欢迎页/Prompt>` | `<属性/HTML/文本>` | `<右键/删除>` | `<说明>` |

## 11. 编译错误 / 日志 / 代码帧检查

| 输入 | 处理位置 | 渲染位置 | 渲染方式 | 是否转义 | 触发动作 | 窗口权限 | 结论 |
|---|---|---|---|---|---|---|---|
| `<源码片段/文件名/error.message>` | `<file:line>` | `<编译面板>` | `<innerHTML/模板>` | `<是/否/不确定>` | `<编译/点击错误项>` | `<高/低/未知>` | `<说明>` |

## 12. 残余风险与后续建议

- `<需动态测试的路由/功能>`
- `<需补充的构建产物/asar/源码>`
- `<建议加入 CI 安全检查项>`
- `<建议补充的验证项目或回归用例>`

## 13. 附录：关键证据摘录

```text
<必要的最短代码片段，避免泄露敏感信息>
```
