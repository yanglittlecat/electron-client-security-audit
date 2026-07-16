# Electron Client Security Audit Skill

这是一个给 Codex 使用的安全审计 Skill。它指导 Codex 审计 Electron/桌面客户端中可由正常用户路径触发的 XSS、deep link/recent project 二阶 XSS、preload/IPC 危险能力和 XSS-to-RCE 链路，并输出可复核的证据链和复现步骤。

## 安装

在 Codex 中调用 `$skill-installer` 从本 GitHub 仓库安装：

```text
使用 $skill-installer 从 GitHub 仓库 https://github.com/yanglittlecat/electron-client-security-audit 的根目录安装 Skill，并命名为 electron-client-security-audit。
```

也可以把本目录放到项目的 `.agents/skills/electron-client-security-audit/`，作为该项目的仓库级 Skill；需要对所有项目生效时，放到 `~/.agents/skills/electron-client-security-audit/`。

安装后如果 Codex 没有立即显示该 Skill，重启 Codex 或开启新任务。

## 用法

安装后，在 Codex 任务中选择 `electron-client-security-audit` Skill，或用 `$electron-client-security-audit` 显式调用：

```text
使用 $electron-client-security-audit 审计 /path/to/unpacked-electron-client，重点检查恶意项目输入、deep link/recent project、开发者工具错误面板，以及 preload/IPC 到 RCE 的链路。
```

该 Skill 也支持自然语言触发，例如：

```text
请审计这个 Electron 客户端，确认正常用户能否通过恶意项目或 deep link 触发 XSS，并判断是否能进一步调用 preload/IPC 危险能力。
```

建议同时提供以下材料中的一种或多种：客户端安装包、解包后的 `app.asar`、源码、构建产物、复现项目或已有运行日志。Skill 会根据材料选择静态扫描、asar 解包、运行时验证和人工数据流分析。

`scripts/` 下的扫描和 asar 解包脚本是 Skill 执行审计时按需使用的内部辅助资源，不是面向用户的启动命令，不需要手动运行。

## 仓库内容

- `SKILL.md`：Skill 的运行时入口和审计流程。Codex 触发 Skill 后读取它。
- `references/report_template.md`：报告结构模板，按需加载。
- `scripts/static_scout.py`：只读静态线索扫描器，由 Skill 按需调用，不是 Skill 的入口。
- `scripts/extract_asar_safe.sh`：安全解包 `.asar` 的辅助脚本，由 Skill 按需调用。

通常不需要手动运行 `scripts/` 下的脚本；直接调用 Skill 即可。

## 安全边界

- 审计验证只使用 benign、本地 loopback 和最小化 PoC。
- 不执行真实反连、C2、数据外传、下载执行或破坏性 payload。
- 扫描脚本只做只读文本扫描，不执行被审计项目代码，不安装依赖，不联网。
