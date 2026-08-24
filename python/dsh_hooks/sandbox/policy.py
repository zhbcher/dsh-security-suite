#!/usr/bin/env python3
"""policy.py — 沙箱策略模型：JSON 加载 / 校验 / 归一化

策略文件示例（examples/hooks-sandbox.json）：
{
  "mode": "workspace-write",
  "writable_roots": [
    "~/deepseek",
    {"path": "/tmp"},
    {"path": "~/.dsh", "exclude": ["settings.yaml", "profiles"]}
  ],
  "deny_read": ["~/.proxy-token", "~/.ssh/**", "~/Library/Keychains/**"],
  "network": {
    "mode": "restricted",
    "allow_remote": ["api.example.com:443"],
    "allow_local_binding": false
  }
}

设计对齐 codex-parity-design.md §1.1 第1层「策略是数据不是代码」：
- mode 三态对齐 DSH 沙箱概念：read-only / workspace-write / danger-full-access
  （danger-full-access 下沙箱仍有意义：deny_read 与网络白名单继续生效，
   这是相对 DSH 原生 full-access 裸奔的核心增强）
- deny_read 只放「进程级绝不可碰」的秘密（SSH 私钥/钥匙串/GPG）；
  凭据内容级扫描归 hooks 总线（known_secret_guard），分层防御互不越位
"""
import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

VALID_MODES = ("read-only", "workspace-write", "danger-full-access")
VALID_NET_MODES = ("disabled", "restricted", "full")


def _expand(p: str) -> str:
    """~ 与 $VAR 展开，并规范化（保留符号链接不解析——与 Codex 同立场：
    更深层组件可能被已运行进程替换，跟随会把路径检查变成新授权）"""
    return os.path.normpath(os.path.expanduser(os.path.expandvars(p)))


def canonicalize_macos_alias(path: str) -> str:
    """macOS 顶层系统别名归一化（对齐 Codex normalize_writable_root_for_sandbox）：
    只解析 /tmp /var /etc /home 这些内核 firmlink 别名（/tmp → /private/tmp），
    更深层的 symlink 一律不跟随。Seatbelt 以 vnode 真实路径匹配，
    不做这步会导致 subpath/regex 全部落空。"""
    if platform.system() != "Darwin":
        return path
    for alias, real in (("/tmp/", "/private/tmp/"), ("/var/", "/private/var/"),
                        ("/etc/", "/private/etc/"), ("/home/", "/System/Volumes/Data/home/")):
        if path == alias.rstrip("/"):
            return real.rstrip("/")
        if path.startswith(alias):
            return real + path[len(alias):]
    return path


import platform  # noqa: E402


@dataclass
class WritableRoot:
    path: str                                   # 已展开规范化
    exclude_literals: List[str] = field(default_factory=list)   # 精确文件排除
    exclude_subtrees: List[str] = field(default_factory=list)   # 子树排除


@dataclass
class NetworkPolicy:
    mode: str = "disabled"
    allow_remote: List[str] = field(default_factory=list)   # "host[:port]" 白名单(代理层过滤,支持 *.通配)
    deny_remote: List[str] = field(default_factory=list)    # 黑名单,恒胜白名单(Codex 同款)
    allow_local_binding: bool = False
    proxy_ports: List[int] = field(default_factory=list)    # Codex 受限形态:仅放行 localhost:<port>

    def validate(self, where: str) -> None:
        if self.mode not in VALID_NET_MODES:
            raise ValueError(f"{where}: network.mode 必须是 {VALID_NET_MODES}")
        for hp in self.allow_remote + self.deny_remote:
            if not hp or " " in hp:
                raise ValueError(f"{where}: 非法条目 {hp!r}(应为 host 或 host:port)")
        if self.mode == "restricted" and not self.proxy_ports:
            # macOS SBPL 的 remote ip 不支持域名(host must be * or localhost),
            # 域名过滤必须走本地代理层。Phase E 起 proxy_ports 即代表
            # 「由 dsh_hooks.netproxy 提供审查代理」;缺端口则无法表达 → 显性报错。
            raise ValueError(
                f"{where}: restricted 模式需要 network.proxy_ports=[本地审查代理端口]"
                "(dsh_hooks.netproxy 将自动拉起),或使用 disabled / full 模式")


@dataclass
class SandboxPolicy:
    mode: str = "workspace-write"
    writable_roots: List[WritableRoot] = field(default_factory=list)
    deny_read: List[str] = field(default_factory=list)          # git 风格 glob，已展开
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    source: str = ""

    def validate(self) -> None:
        if self.mode not in VALID_MODES:
            raise ValueError(f"{self.source or 'policy'}: mode 必须是 {VALID_MODES}")
        if self.mode == "workspace-write" and not self.writable_roots:
            raise ValueError(f"{self.source or 'policy'}: workspace-write 模式至少需要一个 writable_root")
        for r in self.writable_roots:
            if not os.path.isabs(r.path):
                raise ValueError(f"{self.source or 'policy'}: writable_root 路径必须绝对: {r.path}")
            if not os.path.exists(r.path):
                raise ValueError(f"{self.source or 'policy'}: writable_root 不存在: {r.path}")
            for e in r.exclude_subtrees + r.exclude_literals:
                if not os.path.isabs(e):
                    raise ValueError(f"{self.source or 'policy'}: exclude 路径必须绝对: {e}")
        self.network.validate(self.source or "policy")


def _parse_root(item, where: str) -> WritableRoot:
    if isinstance(item, str):
        return WritableRoot(path=_expand(item))
    if isinstance(item, dict):
        path = item.get("path")
        if not path:
            raise ValueError(f"{where}: writable_root 缺少 path")
        base = _expand(path)
        ex = item.get("exclude", [])
        # 相对 exclude 相对于 root 自身解析（如 {"path":"~/.dsh","exclude":["settings.yaml"]}）
        norm = [e if e.startswith(("/", "~", "$")) else base.rstrip("/") + "/" + e for e in ex]
        expanded = [_expand(e) for e in norm]
        lits = [e for e in expanded if "*" not in e and "?" not in e]
        subs = [e.replace("/**", "").rstrip("/") for e in expanded if ("*" in e or "?" in e)]
        return WritableRoot(path=base, exclude_literals=lits, exclude_subtrees=subs)
    raise ValueError(f"{where}: writable_root 条目必须是字符串或对象")


def load_policy(path: str = None) -> SandboxPolicy:
    """从 JSON 文件加载策略；path 为空时依次探测 ~/.dsh/hooks-sandbox.json"""
    candidates = [path] if path else [
        os.environ.get("DSH_HOOKS_SANDBOX", ""),
        str(Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh"))) / "hooks-sandbox.json"),
    ]
    src = next((c for c in candidates if c and Path(c).exists()), None)
    if src is None:
        raise FileNotFoundError(
            f"找不到沙箱策略（--policy / DSH_HOOKS_SANDBOX / ~/.dsh/hooks-sandbox.json 均未命中）")

    raw = json.loads(Path(src).read_text(encoding="utf-8"))
    from .policy import canonicalize_macos_alias as _canon
    pol = SandboxPolicy(mode=raw.get("mode", "workspace-write"), source=str(src))
    pol.writable_roots = [_parse_root(x, src) for x in raw.get("writable_roots", [])]
    for r in pol.writable_roots:
        r.path = _canon(r.path)
        r.exclude_literals = [_canon(e) for e in r.exclude_literals]
        r.exclude_subtrees = [_canon(e) for e in r.exclude_subtrees]
    pol.deny_read = [_canon(_expand(g)) for g in raw.get("deny_read", [])]

    net = raw.get("network") or {}
    pol.network = NetworkPolicy(
        mode=net.get("mode", "disabled"),
        allow_remote=[str(h) for h in net.get("allow_remote", [])],
        deny_remote=[str(h) for h in net.get("deny_remote", [])],
        allow_local_binding=bool(net.get("allow_local_binding", False)),
        proxy_ports=[int(p) for p in net.get("proxy_ports", [])],
    )
    pol.validate()
    return pol
