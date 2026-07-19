# 路径与命令注入专项审计

## 目录

1. 验收口径
2. 进程启动 API 语义
3. 平台与 shell 差异
4. 审计流程
5. 动态验证
6. 分级与报告
7. 修复基线

## 1. 验收口径

将命令注入作为独立漏洞链审计，不要等待 XSS。确认漏洞必须同时证明：

`attacker-controlled source → transform/quoting → process-launch sink → actual interpreter semantics → natural user trigger → benign impact`

只看到 `exec`/`spawn` 或字符串拼接时先标记线索。未确认平台分支、`shell` 选项、可控字符保留情况和正常用户触发前，不得直接定为高危。

## 2. 进程启动 API 语义

| API/模式 | 默认是否经过 shell | 主要审计点 |
|---|---|---|
| `exec` / `execSync` | 是 | 整个字符串由实际 shell 解析；追踪所有插值 |
| `spawn` / `spawnSync` | 否，除非 `shell:true` 或指定 shell | 分开检查可执行文件、参数数组、`shell`、`windowsVerbatimArguments` |
| `execFile` / `execFileSync` | 通常否 | 可控可执行文件仍可直接造成代码执行；某些平台/配置可重新引入 shell |
| `fork` | 否 | 它启动 Node.js 模块；可控 module path 是代码加载问题，不是 shell 注入 |
| `node-pty` / terminal wrapper | 取决于启动的 shell | 确认 shell 类型、初始命令、后续 `write` 输入与会话权限 |
| `shelljs`、`execa`、`cross-spawn`、业务包装器 | 按具体选项 | 追踪到底层 API，不要根据函数名推测 |
| Electron `shell.openPath` / `showItemInFolder` | 不是 shell 字符串 | 仍要校验路径权限和目标类型，但不得误报为 shell 注入 |

不得把“使用了参数数组”等同于绝对安全。若攻击者可控可执行文件，或目标程序本身支持危险选项/配置加载，仍要按参数注入或任意程序启动分析。

## 3. 平台与 shell 差异

| 解释器 | 需重点确认的语义 |
|---|---|
| POSIX `sh`/`bash`/`zsh` | `;`、`&`、`|`、换行、`$()`、反引号、重定向和 glob；双引号内仍可发生变量与命令替换 |
| Windows `cmd.exe` | `&`、`&&`、`|`、`||`、`^`、`%VAR%`、启用 delayed expansion 时的 `!VAR!`、括号与重定向；`;` 和 `$()` 不是 `cmd.exe` 命令分隔/替换语义 |
| PowerShell | `;`、`|`、`&`、反引号、`$()`、`@()` 等；不得将 PowerShell 规则套到 `cmd.exe` |

Windows 路径段禁止 `< > : " / \ | ? *`、NUL/控制字符，并有保留名、尾部点号/空格等规则。`&`、`%`、`!`、`^`、括号等在部分路径中可出现，但是否危险取决于实际解释器和所处上下文。

不要将手工加双引号作为跨平台通用修复。优先完全取消 shell，使用固定可执行文件和独立参数数组。

## 4. 审计流程

1. 全局搜索 `child_process`、`exec*`、`spawn*`、`fork`、`node-pty`、`shell:true`、终端/文件管理器打开逻辑和业务包装器。
2. 对每个 sink 记录进程、文件、行号、API、可执行文件、参数、`shell`、`cwd`、`env` 和平台分支。
3. 向上追踪 source：项目目录名/文件名、解压路径、workspace、deep link、CLI、配置、包脚本、插件和用户输入。
4. 追踪 transform：`resolve/join/normalize/basename`、引号/转义、序列化、IPC、包装器、环境变量和平台选择。
5. 根据最终 API 和 shell 重建精确命令；不要根据中间字符串推断。
6. 证明自然触发：导入、编译、预览、打开终端、打开本地目录、安装插件或其他正常操作。
7. 审查保护是否适用于实际解释器，并检查是否存在二次拼接或二次 shell。

## 5. 动态验证

- 仅在授权隔离环境中，通过真实漏洞链使用计算器或等价 benign 可见命令。
- 根据已确认的解释器选择最小载荷；不得将 Bash 载荷直接用于 `cmd.exe`，反之亦然。
- 验证项目只包含最小文件和触发步骤，不做持久化、下载执行、外传或反连。
- 不得在终端直接执行计算器当作漏洞证明。
- 如果无法在安全条件下动态验证，保留静态证据并降级为待验证。

## 6. 分级与报告

| 状态 | 标准 |
|---|---|
| 确认高危 | 攻击者可控输入经自然操作进入已确认的解释器语义，可执行 benign 命令 |
| 待验证 | source/sink 存在，但平台、shell、字符保留、触发或动态现象不完整 |
| 不可达 | 无 shell、可执行文件固定、参数边界明确，且目标程序不解释危险参数 |
| 加固建议 | 仅存在手工引号、宽松白名单等脆弱设计，未形成可利用链 |

报告必须附上最终调用形态、实际 shell/平台、source 变换、自然触发步骤、可观测现象和根因修复。

## 7. 修复基线

- 优先使用固定可执行文件、`shell:false` 和独立参数数组。
- 打开路径时使用 Electron/OS 结构化 API，不要构造 `open/start/xdg-open` shell 字符串。
- 固定可执行文件路径，不从项目、deep link、配置或环境变量选择任意程序。
- 对目标程序的参数做 schema 与语义白名单，阻断危险选项和配置/脚本加载能力。
- 不要自行实现“通用 shell 转义”；无法取消 shell 时，使用与确定解释器匹配的成熟库并添加平台测试。
