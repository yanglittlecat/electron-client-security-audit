#!/usr/bin/env python3
"""
Static scout for authorized Electron/client security audits.

This helper performs read-only recursive scanning and writes a Markdown summary.
It does not execute project code, does not install dependencies, and does not
contact the network. Treat results as leads; confirm reachability manually.

v2 focus:
- developer-tool / IDE malicious-project attack surface
- deep link -> recent project -> second-order XSS chains
- compile error / code frame / log panel rendering
- HTML attribute-context injection in Prompt/Modal/Input templates
- Electron window permission hints and preload/IPC capabilities
"""
from __future__ import annotations

import argparse
import bisect
import datetime as _dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

DEFAULT_SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    ".cache", ".parcel-cache", ".turbo",
    "coverage", ".nyc_output", "__pycache__",
}
DEFAULT_SKIP_PATHS = {
    (".next", "cache"),
}
VENDOR_DIRS = {"node_modules", "vendor", "third_party", "bower_components"}
TEXT_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".html", ".htm", ".css", ".scss",
    ".json", ".md", ".yml", ".yaml", ".toml", ".xml",
    ".ejs", ".hbs", ".handlebars", ".njk", ".mustache",
    ".py", ".sh", ".bat", ".cmd", ".ps1",
    ".txt", ".log",
}
SOURCEMAP_EXTS = {".map"}

PatternDef = Tuple[str, re.Pattern[str]]


def cre(pattern: str, flags: int = re.I) -> re.Pattern[str]:
    return re.compile(pattern, flags)


PATTERNS: Dict[str, List[PatternDef]] = {
    "xss_sources": [
        ("location source", cre(r"(?:window\.)?location\.(?:href|hash|search|pathname)")),
        ("URLSearchParams", cre(r"\bURLSearchParams\s*\(")),
        ("router/query/params", cre(r"\b(?:route|router)\.(?:query|params)|\buseParams\s*\(|\buseSearchParams\s*\(")),
        ("postMessage/message", cre(r"postMessage|addEventListener\s*\(\s*['\"]message")),
        ("local/session storage", cre(r"\b(?:localStorage|sessionStorage)\b")),
        ("IndexedDB", cre(r"\bindexedDB\b|\bIDB(?:Database|ObjectStore)\b")),
        ("clipboard", cre(r"\bclipboard\b|navigator\.clipboard")),
        ("ipcRenderer receive/invoke/send", cre(r"\bipcRenderer\.(?:on|once|invoke|send|sendSync)\s*\(")),
        ("webContents send", cre(r"\bwebContents\.send\s*\(")),
        ("remote/api fetch", cre(r"\bfetch\s*\(|axios\.|XMLHttpRequest")),
        ("file input/drop", cre(r"type=['\"]file|DataTransfer|ondrop|drop\s*=>|addEventListener\s*\(\s*['\"]drop")),
    ],
    "html_sinks": [
        ("innerHTML assignment", cre(r"\.innerHTML\s*=")),
        ("outerHTML assignment", cre(r"\.outerHTML\s*=")),
        ("insertAdjacentHTML", cre(r"\binsertAdjacentHTML\s*\(")),
        ("document.write", cre(r"\bdocument\.write(?:ln)?\s*\(")),
        ("Range.createContextualFragment", cre(r"createContextualFragment\s*\(")),
        ("DOMParser text/html", cre(r"DOMParser\s*\(|text/html")),
        ("srcdoc", cre(r"\bsrcdoc\b")),
        ("dangerouslySetInnerHTML", cre(r"dangerouslySetInnerHTML")),
        ("Vue v-html", cre(r"\bv-html\b")),
        ("Angular bypassSecurityTrust*", cre(r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)")),
        ("Svelte raw html", cre(r"\{@html\s+")),
        ("lit unsafeHTML", cre(r"\bunsafeHTML\s*\(")),
        ("raw markdown html option", cre(r"\bhtml\s*:\s*true\b|allowDangerousHtml|sanitize\s*:\s*false")),
        ("eval", cre(r"\beval\s*\(")),
        ("new Function", cre(r"new\s+Function\s*\(")),
        ("string timer", cre(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]")),
        ("script creation", cre(r"createElement\s*\(\s*['\"]script['\"]|appendChild\s*\([^)]*script")),
    ],
    "html_attribute_sinks": [
        ("template attr interpolation", cre(
            r"<[^>]{0,1200}\b(?:value|title|href|src|alt|placeholder|name|id|class|style|data-[\w-]+|aria-[\w-]+)"
            r"\s*=\s*['\"][^'\"]*\$\{",
            re.I | re.S,
        )),
        ("template attr concat", cre(
            r"<[^>]{0,1200}\b(?:value|title|href|src|alt|placeholder|name|id|class|style|data-[\w-]+|aria-[\w-]+)"
            r"\s*=\s*['\"][^'\"]*['\"]\s*\+",
            re.I | re.S,
        )),
        ("event attr in html string", cre(r"<[^>]{0,1200}\bon[a-z]+\s*=", re.I | re.S)),
        ("setAttribute event/url attr", cre(r"\.setAttribute\s*\(\s*['\"](?:on\w+|href|src|srcdoc|style)['\"]")),
        ("loadURL data:text/html", cre(r"\.loadURL\s*\(\s*['\"]data:text/html|data:text/html")),
        ("input autofocus html", cre(r"<input\b[^>]{0,1200}\bautofocus\b", re.I | re.S)),
        ("javascript/data URL literal", cre(r"(?:href|src)\s*=\s*['\"]\s*(?:javascript:|data:text/html)")),
    ],
    "devtool_attack_surfaces": [
        ("projectUri/deep link/recent project", cre(
            r"\b(projectUri|recentProjects?|recentProject|workspace|workspacePath|external-launch|"
            r"setAsDefaultProtocolClient|open-url|second-instance|process\.argv|protocol client|custom protocol)\b"
        )),
        ("project path/name/basename", cre(
            r"\b(basename|dirname|projectName|projectPath|workspaceName|workspacePath|rootPath|"
            r"filePath|folderPath|path\.basename|path\.dirname)\b"
        )),
        ("compile/build/log/codeframe", cre(
            r"\b(compile|compiler|compilation|build|diagnostic|diagnostics|codeFrame|code-frame|"
            r"stackTrace|stack|trace|errorMessage|error\.message|logPanel|consolePanel|buildLog|"
            r"sourceMap|sourcemap|ansi-to-html|highlight|prism|monaco)\b"
        )),
        ("recent project UI/context menu", cre(
            r"\b(contextmenu|context-menu|Menu\.buildFromTemplate|\.popup\s*\(|right.?click|"
            r"removeRecent|deleteProject|deleteRecent|recentList|removeProject|clearRecent)\b"
        )),
        ("prompt/modal/input template", cre(
            r"\b(prompt|modal|dialog|confirm|input|showMessageBox|showOpenDialog)\b|<input\b"
        )),
        ("miniapp/devtool vocabulary", cre(
            r"\b(miniapp|mini-app|小程序|developer tool|devtool|ide|preview|upload|project\.config)\b"
        )),
    ],
    "second_order_sources": [
        ("deep link protocol registration", cre(r"setAsDefaultProtocolClient\s*\(|app\.on\s*\(\s*['\"]open-url['\"]")),
        ("second-instance argv", cre(r"app\.on\s*\(\s*['\"]second-instance['\"]|\bprocess\.argv\b")),
        ("projectUri parameter", cre(r"projectUri|projectPath|workspacePath|external-launch|volDriverLaunchMode")),
        ("recent/history/cache persistence", cre(r"recentProjects?|history|cache|store\.(?:get|set)|localStorage\.(?:getItem|setItem)|indexedDB|sqlite|leveldb")),
        ("basename derived display", cre(r"path\.basename\s*\(|basename\s*\(|projectName\s*=")),
        ("url/file path decode", cre(r"decodeURIComponent|new\s+URL\s*\(|fileURLToPath|pathToFileURL")),
    ],
    "electron_window_config": [
        ("BrowserWindow", cre(r"\bnew\s+BrowserWindow\s*\(")),
        ("BrowserView", cre(r"\bnew\s+BrowserView\s*\(")),
        ("webview tag", cre(r"<webview\b|webviewTag\s*:\s*true")),
        ("webPreferences", cre(r"\bwebPreferences\b")),
        ("nodeIntegration true", cre(r"nodeIntegration\s*:\s*true")),
        ("nodeIntegration false", cre(r"nodeIntegration\s*:\s*false")),
        ("contextIsolation false", cre(r"contextIsolation\s*:\s*false")),
        ("contextIsolation true", cre(r"contextIsolation\s*:\s*true")),
        ("sandbox false", cre(r"sandbox\s*:\s*false")),
        ("sandbox true", cre(r"sandbox\s*:\s*true")),
        ("enableRemoteModule true", cre(r"enableRemoteModule\s*:\s*true")),
        ("webSecurity false", cre(r"webSecurity\s*:\s*false")),
        ("allowRunningInsecureContent true", cre(r"allowRunningInsecureContent\s*:\s*true")),
        ("nodeIntegrationInWorker true", cre(r"nodeIntegrationInWorker\s*:\s*true")),
        ("nodeIntegrationInSubFrames true", cre(r"nodeIntegrationInSubFrames\s*:\s*true")),
        ("nativeWindowOpen true", cre(r"nativeWindowOpen\s*:\s*true")),
        ("preload", cre(r"\bpreload\s*:")),
        ("loadURL", cre(r"\.loadURL\s*\(")),
        ("loadFile", cre(r"\.loadFile\s*\(")),
        ("shell.openExternal", cre(r"shell\.openExternal\s*\(")),
        ("setWindowOpenHandler", cre(r"setWindowOpenHandler\s*\(")),
        ("will-navigate/new-window", cre(r"will-navigate|new-window|will-redirect|did-navigate")),
        ("certificate-error", cre(r"certificate-error|select-client-certificate")),
        ("@electron/remote", cre(r"@electron/remote|remote\.require|enableRemoteModule")),
    ],
    "preload_ipc_custom_api": [
        ("contextBridge exposure", cre(r"contextBridge\.exposeInMainWorld\s*\(")),
        ("window global assignment", cre(r"\bwindow\.[A-Za-z_$][\w$]*\s*=")),
        ("ipcRenderer direct", cre(r"\bipcRenderer\.(?:invoke|send|sendSync|on|once)\s*\(")),
        ("ipcMain handler", cre(r"\bipcMain\.(?:handle|on|once|handleOnce)\s*\(")),
        ("webContents.send", cre(r"\bwebContents\.send\s*\(")),
        ("senderFrame/source check", cre(r"senderFrame|event\.sender|webContents\.fromId|webContents\.getAllWebContents")),
        ("any channel passthrough hint", cre(r"channel\s*[,)]|ipcRenderer\.(?:send|invoke)\s*\(\s*channel|ipcMain\.(?:on|handle)\s*\(\s*channel")),
    ],
    "dangerous_capabilities": [
        ("child_process import/use", cre(r"child_process|\b(?:exec|execFile|spawn)\s*\(")),
        ("node-pty", cre(r"node-pty|pty\.spawn")),
        ("fs direct read/write", cre(r"\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|rm|rename|copyFile|mkdir|readdir|stat)\s*\(")),
        ("fs.promises read/write", cre(r"\bfs\.promises\.(?:readFile|writeFile|appendFile|unlink|rm|rename|copyFile|mkdir|readdir|stat)\s*\(")),
        ("path traversal hints", cre(r"\.\./|path\.(?:join|resolve|normalize)\s*\(")),
        ("archive extract", cre(r"\b(?:adm-zip|yauzl|unzipper|tar\.|extract-zip|decompress)\b")),
        ("net socket/connect", cre(r"\bnet\.(?:connect|createConnection|Socket)\b|new\s+net\.Socket")),
        ("http/https request", cre(r"\bhttps?\.(?:request|get)\s*\(")),
        ("WebSocket", cre(r"\bnew\s+WebSocket\s*\(")),
        ("shell open/path", cre(r"shell\.(?:openExternal|openPath|showItemInFolder)\s*\(")),
        ("dialog", cre(r"\bdialog\.(?:showOpenDialog|showSaveDialog|showMessageBox)")),
        ("protocol register/handle", cre(r"\bprotocol\.(?:register|handle|registerFileProtocol|registerStringProtocol|intercept)")),
        ("session/cookies", cre(r"\bsession\.|cookies\.")),
        ("safeStorage/keytar", cre(r"safeStorage|keytar")),
        ("autoUpdater", cre(r"autoUpdater|electron-updater")),
    ],
    "local_service": [
        ("local HTTP server listen", cre(r"\b(?:http\.createServer|express\(\)|server\.listen)\b")),
        ("WebSocket server", cre(r"\b(?:new\s+WebSocketServer|ws\.Server|WebSocket\.Server)\b")),
        ("TCP server", cre(r"\b(?:net\.createServer|dgram\.createSocket)\b")),
        ("127.0.0.1/localhost binding", cre(r"['\"]127\.0\.0\.1['\"]|['\"]localhost['\"]")),
        ("Origin/Referer validation", cre(r"\b(?:Origin|origin|referrer|Referer)\s*(?:===?|!==?)")),
        ("CORS wildcard", cre(r"Access-Control-Allow-Origin\s*:\s*\*|allowOrigin\s*:\s*['\"]\*['\"]")),
        ("config port number", cre(r"['\"]port['\"]\s*:\s*\d{4,5}|PORT|port\s*=\s*\d{4,5}")),
    ],
    "sanitizer_csp": [
        ("DOMPurify/sanitize-html", cre(r"DOMPurify|sanitizeHtml|sanitize-html|xss\(|filterXSS")),
        ("dangerous sanitizer config", cre(r"ADD_TAGS|ADD_ATTR|ALLOWED_URI_REGEXP|allowProtocolRelative|allowedSchemes|allowedAttributes")),
        ("CSP unsafe-inline/eval", cre(r"Content-Security-Policy|unsafe-inline|unsafe-eval|script-src")),
        ("Trusted Types", cre(r"trustedTypes|TrustedHTML|createPolicy")),
    ],
}

CATEGORY_TITLES = {
    "xss_sources": "XSS 输入源线索",
    "html_sinks": "HTML / XSS 危险 Sink 线索",
    "html_attribute_sinks": "HTML 属性上下文注入线索",
    "devtool_attack_surfaces": "开发者工具 / 恶意项目攻击面线索",
    "second_order_sources": "Deep link / recent project / 二阶链路线索",
    "electron_window_config": "Electron 窗口配置线索",
    "preload_ipc_custom_api": "Preload / IPC / 自定义 API 线索",
   "dangerous_capabilities": "危险能力线索",
    "local_service": "本地服务连接来源校验线索",
   "sanitizer_csp": "Sanitizer / CSP / 安全策略线索",
}

CATEGORY_ORDER = [
    "devtool_attack_surfaces",
   "second_order_sources",
   "html_attribute_sinks",
    "local_service",
   "xss_sources",
   "html_sinks",
    "electron_window_config",
    "preload_ipc_custom_api",
    "dangerous_capabilities",
    "sanitizer_csp",
]


@dataclass
class Hit:
    category: str
    name: str
    path: str
    line: int
    snippet: str


@dataclass
class FileSummary:
    path: str
    categories: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    hits: int = 0


@dataclass
class Hotspot:
    path: str
    score: int
    reasons: List[str]
    categories: List[str]


@dataclass
class ScanResult:
    root: Path
    scanned_files: int = 0
    skipped_files: List[str] = field(default_factory=list)
    skipped_dirs: List[str] = field(default_factory=list)
    asar_files: List[str] = field(default_factory=list)
    package_json_files: List[str] = field(default_factory=list)
    hits: List[Hit] = field(default_factory=list)
    file_summaries: Dict[str, FileSummary] = field(default_factory=dict)


def is_probably_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    # Large proportion of control characters is a binary hint.
    sample = data[:4096]
    if not sample:
        return False
    controls = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return controls / max(len(sample), 1) > 0.25


def should_scan_file(path: Path, include_sourcemaps: bool, all_text: bool) -> bool:
    suffix = path.suffix.lower()
    if include_sourcemaps and suffix in SOURCEMAP_EXTS:
        return True
    if suffix in TEXT_EXTS:
        return True
    if all_text:
        return True
    # Extensionless JS launchers/configs can be useful, but avoid binary blobs later.
    return suffix == "" and path.name.lower() in {"package", "electron", "main", "preload", "renderer"}


def path_has_skip_tuple(rel_parts: Sequence[str]) -> bool:
    parts = tuple(rel_parts)
    for skip in DEFAULT_SKIP_PATHS:
        n = len(skip)
        for i in range(0, max(len(parts) - n + 1, 0)):
            if parts[i:i + n] == skip:
                return True
    return False


def iter_files(root: Path, include_vendor: bool, result: ScanResult) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        try:
            rel_parts = current.relative_to(root).parts
        except ValueError:
            rel_parts = current.parts

        kept = []
        for dirname in dirnames:
            candidate = current / dirname
            try:
                candidate_parts = candidate.relative_to(root).parts
                rel = str(candidate.relative_to(root))
            except ValueError:
                candidate_parts = candidate.parts
                rel = str(candidate)

            should_skip = False
            reason = ""
            if dirname in DEFAULT_SKIP_DIR_NAMES:
                should_skip = True
                reason = "default skip"
            elif path_has_skip_tuple(candidate_parts):
                should_skip = True
                reason = "default nested skip"
            elif not include_vendor and dirname in VENDOR_DIRS:
                should_skip = True
                reason = "vendor; use --include-vendor to scan"

            if should_skip:
                result.skipped_dirs.append(f"{rel} ({reason})")
                continue
            kept.append(dirname)
        dirnames[:] = kept

        for filename in filenames:
            yield current / filename


def newline_offsets(text: str) -> List[int]:
    return [m.start() for m in re.finditer("\n", text)]


def line_for_offset(newlines: Sequence[int], offset: int) -> int:
    return bisect.bisect_right(newlines, offset) + 1


def make_snippet(text: str, start: int, end: int, context_chars: int) -> str:
    left = max(0, start - context_chars)
    right = min(len(text), end + context_chars)
    snippet = text[left:right]
    snippet = snippet.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if left > 0:
        snippet = "..." + snippet
    if right < len(text):
        snippet += "..."
    return snippet[:600]


def record_file_hit(result: ScanResult, hit: Hit) -> None:
    result.hits.append(hit)
    summary = result.file_summaries.setdefault(hit.path, FileSummary(path=hit.path))
    summary.categories.add(hit.category)
    summary.names.add(hit.name)
    summary.hits += 1


def scan_text(rel: str, text: str, result: ScanResult, max_hits_per_file: int, context_chars: int) -> None:
    hits_for_file = 0
    newlines = newline_offsets(text)
    for category, patterns in PATTERNS.items():
        if hits_for_file >= max_hits_per_file:
            break
        for name, pattern in patterns:
            if hits_for_file >= max_hits_per_file:
                break
            local_count = 0
            for match in pattern.finditer(text):
                lineno = line_for_offset(newlines, match.start())
                snippet = make_snippet(text, match.start(), match.end(), context_chars)
                record_file_hit(result, Hit(category, name, rel, lineno, snippet))
                hits_for_file += 1
                local_count += 1
                # Avoid one repetitive pattern drowning out the file.
                if local_count >= 8 or hits_for_file >= max_hits_per_file:
                    break


def scan(root: Path, max_bytes: int, include_vendor: bool, include_sourcemaps: bool,
         all_text: bool, max_hits_per_file: int, context_chars: int) -> ScanResult:
    result = ScanResult(root=root)
    for path in iter_files(root, include_vendor, result):
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)

        if path.name == "package.json":
            result.package_json_files.append(rel)
        if path.suffix.lower() == ".asar":
            result.asar_files.append(rel)
            continue
        if not should_scan_file(path, include_sourcemaps, all_text):
            continue

        try:
            size = path.stat().st_size
            if size > max_bytes:
                result.skipped_files.append(f"{rel} (>{max_bytes} bytes; use --max-bytes to raise limit)")
                continue
            data = path.read_bytes()
            if is_probably_binary(data):
                result.skipped_files.append(f"{rel} (binary-like)")
                continue
            text = data.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.skipped_files.append(f"{rel} ({exc})")
            continue

        result.scanned_files += 1
        scan_text(rel, text, result, max_hits_per_file, context_chars)
    return result


def group_hits(hits: List[Hit]) -> Dict[str, List[Hit]]:
    grouped: Dict[str, List[Hit]] = {}
    for hit in hits:
        grouped.setdefault(hit.category, []).append(hit)
    return grouped


def load_package_summaries(root: Path, package_paths: List[str]) -> List[str]:
    summaries = []
    for rel in package_paths[:30]:
        path = root / rel
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        interesting = {
            "name": data.get("name"),
            "version": data.get("version"),
            "main": data.get("main"),
            "scripts": data.get("scripts", {}),
        }
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            obj = data.get(key) or {}
            for dep in (
                "electron", "@electron/remote", "asar", "dompurify", "sanitize-html", "xss",
                "marked", "markdown-it", "ansi-to-html", "highlight.js", "prismjs", "monaco-editor",
                "node-pty", "keytar", "electron-updater", "extract-zip", "adm-zip", "unzipper",
            ):
                if dep in obj:
                    deps[dep] = obj[dep]
        interesting["interestingDeps"] = deps
        summaries.append(f"### `{rel}`\n\n```json\n{json.dumps(interesting, ensure_ascii=False, indent=2)}\n```\n")
    return summaries


def build_hotspots(result: ScanResult) -> List[Hotspot]:
    hotspots: List[Hotspot] = []
    for rel, summary in result.file_summaries.items():
        cats = summary.categories
        names = summary.names
        score = 0
        reasons: List[str] = []

        if "devtool_attack_surfaces" in cats and "html_attribute_sinks" in cats:
            score += 6
            reasons.append("开发者工具输入面 + HTML 属性上下文 sink")
        if "second_order_sources" in cats and "html_attribute_sinks" in cats:
            score += 6
            reasons.append("deep link/recent project 二阶 source + 属性 sink")
        if "devtool_attack_surfaces" in cats and "html_sinks" in cats:
            score += 5
            reasons.append("恶意项目/日志/代码帧输入面 + HTML sink")
        if "devtool_attack_surfaces" in cats and "second_order_sources" in cats:
            score += 4
            reasons.append("开发者工具输入面 + 二阶持久化链路")
        if "html_sinks" in cats and "xss_sources" in cats:
            score += 4
            reasons.append("XSS source + HTML sink 同文件")
        if "electron_window_config" in cats and any(n in names for n in ("nodeIntegration true", "contextIsolation false", "sandbox false")):
            score += 3
            reasons.append("高权限 Electron 窗口配置线索")
        if "preload_ipc_custom_api" in cats and "dangerous_capabilities" in cats:
            score += 4
            reasons.append("preload/IPC + 危险能力同文件")
        if "electron_window_config" in cats and ("html_sinks" in cats or "html_attribute_sinks" in cats):
            score += 3
            reasons.append("窗口配置 + HTML 渲染线索同文件")
        if "local_service" in cats:
            has_local_listener = any(n in names for n in ("local HTTP server listen", "WebSocket server", "TCP server"))
            if has_local_listener:
                score += 3
                reasons.append("本地服务监听线索")
                if "Origin/Referer validation" not in names:
                    score += 3
                    reasons.append("未发现来源校验线索，需人工确认")
            if "CORS wildcard" in names:
                score += 4
                reasons.append("本地服务存在宽松 CORS 配置")
            if has_local_listener and any(n in names for n in ("127.0.0.1/localhost binding", "config port number")):
                score += 1
                reasons.append("存在本地绑定/端口配置线索")
        if "sanitizer_csp" in cats and ("html_sinks" in cats or "html_attribute_sinks" in cats):
            score += 1
            reasons.append("存在 sanitizer/CSP 线索，需检查配置是否足够")

        if score > 0:
            hotspots.append(Hotspot(rel, score, reasons, sorted(cats)))

    hotspots.sort(key=lambda h: (h.score, len(h.reasons)), reverse=True)
    return hotspots


def md_escape_cell(value: str) -> str:
    return value.replace("`", "\\`").replace("|", "\\|").replace("\n", " ")


def write_markdown(result: ScanResult, out: Path) -> None:
    grouped = group_hits(result.hits)
    hotspots = build_hotspots(result)
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: List[str] = []
    lines.append("# Static Scout v2 初筛报告\n")
    lines.append(f"- 扫描时间：{now}")
    lines.append(f"- 根目录：`{result.root}`")
    lines.append(f"- 已扫描文本文件数：{result.scanned_files}")
    lines.append(f"- 命中线索数：{len(result.hits)}")
    lines.append(f"- 高优先级候选文件数：{len(hotspots)}")
    lines.append("\n> 说明：本报告只是静态初筛线索，不能替代人工 source → persistence/transform → sink → trigger → privilege 可达性确认。\n")

    if result.asar_files:
        lines.append("## ASAR 文件候选\n")
        for p in result.asar_files:
            lines.append(f"- `{p}`")
        lines.append("")

    if result.package_json_files:
        lines.append("## package.json 摘要\n")
        lines.extend(load_package_summaries(result.root, result.package_json_files))

    lines.append("## 高优先级人工确认候选\n")
    if hotspots:
        lines.append("| 分数 | 文件 | 原因 | 类别 |")
        lines.append("|---:|---|---|---|")
        for h in hotspots[:80]:
            reasons = md_escape_cell("；".join(h.reasons))
            cats = md_escape_cell(", ".join(h.categories))
            lines.append(f"| {h.score} | `{h.path}` | {reasons} | `{cats}` |")
        if len(hotspots) > 80:
            lines.append(f"\n仅展示前 80 个候选，另有 {len(hotspots) - 80} 个。\n")
    else:
        lines.append("未发现高优先级组合线索。\n")
    lines.append("")

    for category in CATEGORY_ORDER:
        hits = grouped.get(category, [])
        lines.append(f"## {CATEGORY_TITLES.get(category, category)} ({len(hits)})\n")
        if not hits:
            lines.append("未发现明显线索。\n")
            continue
        lines.append("| 规则 | 位置 | 上下文片段 |")
        lines.append("|---|---|---|")
        for hit in hits[:400]:
            snippet = md_escape_cell(hit.snippet)
            lines.append(f"| {md_escape_cell(hit.name)} | `{hit.path}:{hit.line}` | `{snippet}` |")
        if len(hits) > 400:
            lines.append(f"\n仅展示前 400 条，另有 {len(hits) - 400} 条。\n")
        lines.append("")

    if result.skipped_dirs:
        lines.append("## 跳过的目录\n")
        for item in result.skipped_dirs[:200]:
            lines.append(f"- `{item}`")
        if len(result.skipped_dirs) > 200:
            lines.append(f"- ... 另有 {len(result.skipped_dirs) - 200} 个")
        lines.append("")

    if result.skipped_files:
        lines.append("## 跳过的文件\n")
        for item in result.skipped_files[:250]:
            lines.append(f"- `{item}`")
        if len(result.skipped_files) > 250:
            lines.append(f"- ... 另有 {len(result.skipped_files) - 250} 个")
        lines.append("")

    lines.append("## 下一步人工确认建议\n")
    lines.append("1. 先建立 Electron 窗口地图，标注每个窗口的 `nodeIntegration`、`contextIsolation`、`sandbox`、`preload` 与数据来源。")
    lines.append("2. 对开发者工具/IDE/小程序工具，优先追踪恶意项目目录名、文件名、projectUri、recent project、编译错误、代码帧、日志面板、Prompt/Modal。")
    lines.append("3. 对属性上下文命中，检查是否可闭合属性、是否触发 autofocus/onload/onerror/contextmenu，以及是否做了属性上下文转义。")
    lines.append("4. 对 deep link/recent project 命中，做 source → persistence → display → trigger 的二阶链路分析，不要因为首次打开未执行就判定不可利用。")
    lines.append("5. 对 HTML/日志/代码帧 sink，确认项目源码、错误信息、路径 basename 或配置字段是否能进入 sink。")
    lines.append("6. 对 preload/IPC 命中，独立建立能力清单，区分可被恶意项目自然流程调用、可被 XSS 调用、仅可信 renderer 可调用。")
    lines.append("7. 最终生成中文报告 `客户端产品安全漏洞审计报告.md`，区分已确认、待验证和不可达问题；无害验证只使用 alert/DOM 标记/计算器。")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Read-only Electron/client security scout v2")
    parser.add_argument("root", nargs="?", default=".", help="Root directory to scan; default current directory")
    parser.add_argument("--out", default="audit-artifacts/static_scout_report.md", help="Markdown output path")
    parser.add_argument("--max-bytes", type=int, default=8_000_000, help="Skip text files larger than this")
    parser.add_argument("--include-vendor", action="store_true", help="Also scan vendor directories such as node_modules")
    parser.add_argument("--include-sourcemaps", action="store_true", help="Also scan .map source map files")
    parser.add_argument("--all-text", action="store_true", help="Try to scan any non-binary file regardless of extension")
    parser.add_argument("--max-hits-per-file", type=int, default=160, help="Limit hits per file")
    parser.add_argument("--context-chars", type=int, default=160, help="Context characters around each match")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"[!] Root is not a directory: {root}", file=sys.stderr)
        return 2

    result = scan(
        root=root,
        max_bytes=args.max_bytes,
        include_vendor=args.include_vendor,
        include_sourcemaps=args.include_sourcemaps,
        all_text=args.all_text,
        max_hits_per_file=args.max_hits_per_file,
        context_chars=args.context_chars,
    )
    out = Path(args.out)
    write_markdown(result, out)
    hotspots = build_hotspots(result)
    print(f"[+] Wrote {out}")
    print(f"[+] Scanned files: {result.scanned_files}; hits: {len(result.hits)}; asar: {len(result.asar_files)}; hotspots: {len(hotspots)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
