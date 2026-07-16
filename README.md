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
