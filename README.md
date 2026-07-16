# Electron Client Security Audit Agent Skill

这是一个基于 [Agent Skills 开放标准](https://agentskills.io) 的 Electron/桌面客户端安全审计 Skill，可供 **Codex** 和 **Claude Code** 使用。它重点追踪正常用户路径可触发的 XSS、deep link/recent project 二阶 XSS、preload/IPC 危险能力和 XSS-to-RCE 链路，并输出可复核的证据链和复现步骤。

## 安装

### Codex

在 Codex 中调用 `$skill-installer`：

```text
使用 $skill-installer 从 GitHub 仓库 https://github.com/yanglittlecat/electron-client-security-audit 的根目录安装 Skill，并命名为 electron-client-security-audit。
```

也可以手动将本目录放到：

- 个人级：`~/.agents/skills/electron-client-security-audit/`
- 项目级：`<project>/.agents/skills/electron-client-security-audit/`

### Claude Code

将本目录下载或复制到：

- 个人级：`~/.claude/skills/electron-client-security-audit/`
- 项目级：`<project>/.claude/skills/electron-client-security-audit/`

目录中必须保留 `SKILL.md`、`scripts/` 和 `references/` 的相对位置。如果安装前顶层 skills 目录尚不存在，安装后重启对应客户端或开启新会话。

## 调用

### Codex

```text
使用 $electron-client-security-audit 审计 /path/to/unpacked-electron-client，重点检查恶意项目输入、deep link/recent project、开发者工具错误面板，以及 preload/IPC 到 RCE 的链路。
```

### Claude Code

```text
/electron-client-security-audit 审计 /path/to/unpacked-electron-client，重点检查恶意项目输入、deep link/recent project、开发者工具错误面板，以及 preload/IPC 到 RCE 的链路。
```

两者都可以根据 `SKILL.md` 的 `description` 自动触发。也可直接使用自然语言：

```text
请使用 electron-client-security-audit Skill 审计这个 Electron 客户端，确认正常用户能否通过恶意项目或 deep link 触发 XSS，并判断是否能进一步调用 preload/IPC 危险能力。
```

建议同时提供客户端安装包、解包后的 `app.asar`、源码、构建产物、复现项目或已有运行日志。

## 兼容性

| 组件 | Codex | Claude Code |
|---|---|---|
| `SKILL.md` | 支持 | 支持 |
| `scripts/` | Skill 内部按需使用 | Skill 内部按需使用 |
| `references/` | 支持 | 支持 |
| `agents/openai.yaml` | Codex UI 元数据 | 忽略，不影响 Skill 执行 |

`scripts/` 下的扫描和 asar 解包脚本是 Agent 执行审计时按需使用的内部辅助资源，不是面向用户的启动命令，通常不需要手动运行。

## 安全边界

- 审计验证只使用 benign、本地 loopback 和最小化 PoC。
- 不执行真实反连、C2、数据外传、下载执行或破坏性 payload。
- 辅助脚本只做只读文本扫描或 asar 解包，不联网安装依赖。
