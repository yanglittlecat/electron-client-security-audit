# Electron Client Security Audit Skill

这是一个给 Codex 使用的安全审计 Skill。它指导 Codex 审计 Electron/桌面客户端中可由正常用户路径触发的 XSS、deep link/recent project 二阶 XSS、preload/IPC 危险能力和 XSS-to-RCE 链路，并输出可复核的证据链和复现步骤。

## 安装

推荐使用 Codex 的 Skill 安装器从本仓库安装：

```text
$skill-installer https://github.com/yanglittlecat/electron-client-security-audit/tree/main
```

也可以把本目录放到项目的 `.agents/skills/electron-client-security-audit/`，作为该项目的仓库级 Skill；需要对所有项目生效时，放到 `~/.agents/skills/electron-client-security-audit/`。

安装后如果 Codex 没有立即显示该 Skill，重启 Codex 或开启新任务。

## 使用

显式调用 Skill：

```text
使用 $electron-client-security-audit 审计 /path/to/unpacked-electron-client，重点检查恶意项目输入、deep link/recent project、开发者工具错误面板，以及 preload/IPC 到 RCE 的链路。
```

也可以直接用自然语言提出审计请求，例如：

```text
请审计这个 Electron 客户端，确认正常用户能否通过恶意项目或 deep link 触发 XSS，并判断是否能进一步调用 preload/IPC 危险能力。
```

建议同时提供以下材料中的一种或多种：客户端安装包、解包后的 `app.asar`、源码、构建产物、复现项目或已有运行日志。Skill 会根据材料选择静态扫描、asar 解包、运行时验证和人工数据流分析，并在需要时生成报告模板。

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
# electron-client-security-audit v2

这版针对前一版漏掉的两类 Electron 开发者工具漏洞做了专项增强：

1. 恶意第三方项目内容进入编译错误、代码帧、构建日志、错误高亮面板后触发 XSS/RCE。
2. deep link / projectUri 污染 recent project，再由右键、删除、Prompt/Input/Modal 等二阶 UI 流程触发属性上下文 XSS/RCE。

3. **新增：本地服务连接来源校验攻击面** —— 客户端在本地监听 HTTP/WebSocket/TCP 服务（如 127.0.0.1:7805），若未校验连接来源，外部恶意页面可直连本地端口读取用户认证态数据。云盘/笔记/代理类客户端为重点关注对象。详见 SKILL.md §5.6。

## 文件结构

```text
electron-client-security-audit/
  SKILL.md
  README.md
  scripts/
    static_scout.py
    extract_asar_safe.sh
  references/
    report_template.md
```

## 推荐扫描命令

```bash
python3 scripts/static_scout.py . --out audit-artifacts/static_scout_report.md --include-sourcemaps --max-bytes 20000000
```

如果审计的是商业客户端解包后的 bundle，必要时加：

```bash
python3 scripts/static_scout.py . --out audit-artifacts/static_scout_report.md --include-sourcemaps --include-vendor --all-text --max-bytes 50000000
```

## 安全边界

- 脚本只做只读文本扫描，不执行项目代码，不安装依赖，不联网。
- asar 解包脚本只使用本地已有的 `asar` 或 `npx --no-install asar`，不会安装包。
- 允许在上层目录创建最小化验证项目，但必须是新目录，不覆盖已有内容，不包含反连、外传、持久化或破坏性 payload。
