#!/usr/bin/env python3
"""autodiscover.py — 出口渠道自动发现（自学习哨兵生成）

原理：Agent 每次用某个二进制"发送文件"，都会在会话日志里留下 tool/call 记录。
本模块扫描近期会话日志，识别出"携带文件参数的外发二进制"，
自动合并进出口配置并生成拦截 shim——接入新聊天工具零人工干预。

反应式声明：首次使用可能漏拦（尚未学习），第二次起必拦。
"""
import json
import re
import shlex
from pathlib import Path

# 这些是日常工具，即使带 --file 类参数也不是外发渠道
SAFE_BINARIES = {
    "git", "gh", "ls", "cat", "cd", "echo", "grep", "rg", "find", "sed", "awk",
    "python3", "python", "node", "npm", "pnpm", "pip3", "pip",
    "gcc", "g++", "clang", "make", "cargo", "go",
    "curl", "wget", "tar", "zip", "unzip", "gzip", "gunzip",
    "ssh", "scp", "rsync", "chmod", "chown", "mkdir", "rm", "cp", "mv",
    "touch", "diff", "patch", "head", "tail", "less", "more", "wc", "sort",
    "uniq", "date", "which", "whoami", "pwd", "env", "export", "true", "false",
    "brew", "launchctl", "osascript", "open", "codesign", "security",
    "dsh", "node", "bash", "sh", "zsh", "sudo",
}

# 判定"这个调用在发文件"的参数特征
FILE_FLAG_RE = re.compile(
    r"(--file|--attach|--image|--media|--document|--photo|--video|--upload)\b")


def scan_lines(lines, known_channels=None):
    """从解析后的日志行中识别外发渠道候选。

    lines: 可迭代的 JSON 对象（tool/call 类型）
    known_channels: 已在配置中的渠道名集合（这些跳过）
    返回: {binary_name: {"file_flags": sorted set, "count": n}}
    """
    known = set(known_channels or [])
    found = {}
    for obj in lines:
        try:
            if obj.get("type") != "tool/call":
                continue
            d = obj.get("data") or {}
            name = (d.get("name") or "").strip()
        except AttributeError:
            continue
        # name 可能直接是二进制名，也可能藏在 arguments 的首 token
        args = d.get("arguments")
        tokens = []
        args_str = args if isinstance(args, str) else json.dumps(args or {})
        try:
            tokens = shlex.split(args_str)
        except ValueError:
            tokens = args_str.split()
        binary = None
        if name in ("bash", "sh", "zsh", "shell"):
            # bash 包装：取命令的首 token 作为候选二进制
            for t in tokens:
                if not t.startswith("-"):
                    binary = t.split("/")[-1]
                    break
        elif name and not name.startswith(("builtin", "mcp__")):
            binary = name.split("/")[-1]
        if not binary or binary in SAFE_BINARIES or binary in known:
            continue
        if FILE_FLAG_RE.search(args_str):
            entry = found.setdefault(binary, {"file_flags": set(), "count": 0})
            entry["count"] += 1
            for t in tokens:
                if FILE_FLAG_RE.search(t) and t.startswith("-"):
                    entry["file_flags"].add(t)
    return {k: {"file_flags": sorted(v["file_flags"]), "count": v["count"]}
            for k, v in found.items()}


def _read_log(path: Path) -> str:
    """读会话日志：zstd 魔数则解压，否则按纯文本。"""
    import subprocess
    data = Path(path).read_bytes()
    if data[:4] == b"\x28\xb5\x2f\xfd":            # zstd 魔数
        try:
            import zstandard
            return zstandard.ZstdDecompressor().stream_reader(data).read().decode("utf-8", "replace")
        except ImportError:
            r = subprocess.run(["zstd", "-dc", str(path)], capture_output=True)
            return r.stdout.decode("utf-8", "replace")
    return data.decode("utf-8", "replace")


def discover_in_file(session_path, known_channels=None):
    """扫描单个会话文件（支持 zstd 与纯文本）。"""
    text = _read_log(Path(session_path))
    lines = []
    for raw in text.splitlines():
        try:
            lines.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return scan_lines(lines, known_channels)
