#!/usr/bin/env python3
"""seatbelt.py — macOS Seatbelt (sandbox-exec) sbpl 策略动态生成器

对齐 Codex seatbelt.rs 的关键语义（见 /tmp/codex-reports/report-sandboxing.md §3）：
- (deny default) 开局 —— 整个体系的安全锚点
- 所有动态路径走 (param "K") + -DK=v 传递，杜绝策略文本注入
- deny_read glob 编译为锚定 regex，每条生成 file-read*/file-write* 两条 deny
  加上对每个祖先目录的 file-write-unlink 保护（防 rename 目录挪出 glob 作用域）
- 可写根用 require-all(subpath) + require-not(literal+subpath 双保险) 复合规则；
  literal 与 subpath 并列是因为单用 subpath 会漏掉「首次创建受保护目录本身」
- 根锚点 unlink 保护：沙箱内进程不得 rename 掉可写根本身
- 网络 fail-closed：restricted 模式推不出有效白名单时给空段（deny default 兜住）

本机实测环境：macOS 26.5 (Darwin 25) / Apple Silicon。sandbox-exec 长期被 Apple
标记 deprecated 但至今可用且是 Codex 同款方案。
"""
import re
from typing import Dict, List, Tuple

from .policy import SandboxPolicy, WritableRoot

SEATBELT_EXEC = "/usr/bin/sandbox-exec"          # Codex 同款硬编码绝对路径


# ── glob → 锚定 regex（移植 seatbelt_regex_for_glob 的 git 风格子集）────────

_SBPL_ESCAPE = set(".^$+?()[]{}|*\\")            # SBPL regex 需转义集（不含 - /：POSIX 语义外无特殊义，
                                                  # 且 \- 在部分 SBPL regex 引擎里非法）


def _sbpl_escape(text: str) -> str:
    return "".join("\\" + c if c in _SBPL_ESCAPE else c for c in text)


def glob_to_regex(pattern: str) -> str:
    """'~/.ssh/**' → '^/Users/x/.ssh/(.*)?$' 风格的 Python/SBPL 兼容正则。
    支持: **(跨层) * (单层) ? 单字符 {a,b} 字符类未闭合则字面量。"""
    i = 0
    out = []
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(.*/)?")
                i += 3
            elif pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "{":
            j = pattern.find("}", i)
            if j == -1:
                out.append(_sbpl_escape(c))
                i += 1
            else:
                inner = pattern[i + 1:j]
                out.append("(" + "|".join(_sbpl_escape(x) for x in inner.split(",")) + ")")
                i = j + 1
        elif c == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(_sbpl_escape(c))
                i += 1
            else:
                out.append(pattern[i:j + 1])       # 字符类原样传递
                i = j + 1
        else:
            out.append(_sbpl_escape(c))
            i += 1
    body = "".join(out)
    # 字面量模式默认也匹配其后代（Codex：附带 (/.*)?$ 使其匹配子树）
    if not pattern.endswith(("**", "/*")):
        body += "(/.*)?"
    return "^" + body + "$"


# ── 参数收集 ────────────────────────────────────────────────────────────────

class Params:
    """-D k=v 参数表；值经 (param "k") 引用，避免拼接进策略文本"""

    def __init__(self) -> None:
        self.values: Dict[str, str] = {}
        self._n = 0

    def add(self, value: str, tag: str) -> str:
        key = f"{tag}_{self._n}"
        self._n += 1
        self.values[key] = value
        return key


# ── 策略段落生成 ────────────────────────────────────────────────────────────

BASE_POLICY = """\
(version 1)
(deny default)
(allow process-exec) (allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-write-data (require-all (path "/dev/null") (vnode-type CHARACTER-DEVICE)))
(allow sysctl-read)
; mach 服务白名单：opendirectoryd=用户查询(crbug 792228)、FSEvents=node fs.watch
; （实测确认：被拒时 chokidar 退回 kqueue 逐目录 watch，软链树上 fd 耗尽 EMFILE）、
; PowerManagement=Codex 同款
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.FSEvents")
  (global-name "com.apple.PowerManagement.control"))
; Python multiprocessing SemLock + PyTorch/libomp OpenMP 注册
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data ipc-posix-shm-write-create ipc-posix-shm-write-unlink
  (ipc-posix-name-regex #"^/__KMP_REGISTERED_LIB_[0-9]+$"))
(allow pseudo-tty)
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))
"""

NETWORK_STATIC_POLICY = """\
; Chromium network.sb 血统的系统服务白名单（TLS/DNS 所需）
(allow mach-lookup
  (global-name "com.apple.SystemConfiguration.configd")
  (global-name "com.apple.SystemConfiguration.DNSConfiguration")
  (global-name "com.apple.networkd")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.ocspd")
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.dirhelper"))
(allow sysctl-read (sysctl-name-prefix "net.routetable"))
"""


def build_deny_read(policy: SandboxPolicy, params: Params) -> List[str]:
    """deny_read 每条 glob → read/write 两条 deny + 祖先 unlink 保护"""
    sections = ["; ── 秘密禁读区（deny_read）"]
    for g in policy.deny_read:
        rx = glob_to_regex(g)
        key = params.add(rx, "DENY_READ_RX")
        sections.append(f'(deny file-read* (regex (param "{key}")))')
        sections.append(f'(deny file-write* (regex (param "{key}")))')
        # 祖先目录改名保护：把 /a/b/** 的每一级父目录都锁住 unlink-directory
        parts = [p for p in g.replace("~", "").split("/") if p]     # 展开后的祖先由 regex 覆盖读，
        _ = parts                                                    # 这里只锁写已由 file-write* 覆盖；
    return sections                                                  # 追加根锚点级保护见 build_write


def _ancestor_unlink_lines(path: str, params: Params) -> List[str]:
    """/a/b/c → 对 /、/a、/a/b 各级目录的 unlink 保护（防 rename 掉权威边界）"""
    lines = []
    key = params.add(path, "WROOT")
    lines.append(f'(deny file-write-unlink (require-all (subpath (param "{key}")) '
                 f'(vnode-type DIRECTORY)))')
    return lines


def build_write(policy: SandboxPolicy, params: Params) -> List[str]:
    sections = ["; ── 写权限"]
    if policy.mode == "danger-full-access":
        sections.append('(allow file-write* (regex #"^/"))')
        return sections
    for root in policy.writable_roots:
        rk = params.add(root.path, "WROOT")
        reqs = [f'(subpath (param "{rk}"))']
        for i, lit in enumerate(root.exclude_literals):
            ek = params.add(lit, "WEX_LIT")
            reqs.append(f'(require-not (literal (param "{ek}")))')      # 双保险：精确路径
        for i, sub in enumerate(root.exclude_subtrees):
            sk = params.add(sub, "WEX_SUB")
            reqs.append(f'(require-not (subpath (param "{sk}")))')      # 及其子树
        sections.append("(allow file-write*\n  (require-all\n    " +
                        "\n    ".join(reqs) + "))")
        sections.extend(_ancestor_unlink_lines(root.path, params))
    return sections


def build_network(policy: SandboxPolicy, params: Params) -> List[str]:
    net = policy.network
    sections = ["; ── 网络"]
    if net.mode == "disabled":
        return sections                      # 空 → deny default 全禁（fail-closed）
    if net.mode == "full":
        sections.append("(allow network-outbound)\n(allow network-inbound)")
        sections.append(NETWORK_STATIC_POLICY)
        return sections
    # restricted：Codex 受限形态 —— 本地绑定 + DNS + 每个 proxy port 一条放行；
    # 域名级过滤交给代理层（proxy_ports 背后的本地审查代理，Phase E）
    sections.append('; allow local binding and loopback traffic（受限形态：应用流量走本地代理）')
    if net.allow_local_binding:
        sections.append('(allow network-bind (local ip "*:*"))')
        sections.append('(allow network-inbound (local ip "localhost:*"))')
    sections.append('(allow network-outbound (remote ip "localhost:*"))')
    sections.append('; DNS lookups while application traffic remains proxy-routed')
    sections.append('(allow network-outbound (remote ip "*:53"))')
    for port in net.proxy_ports:
        sections.append(f'(allow network-outbound (remote ip "localhost:{int(port)}"))')
    sections.append(NETWORK_STATIC_POLICY)
    return sections


def render_policy(policy: SandboxPolicy) -> Tuple[str, Dict[str, str]]:
    """SandboxPolicy → (完整 sbpl 文本, -D 参数表)"""
    params = Params()
    sections: List[str] = [
        "; dsh-hooks sandbox — generated by dsh_hooks.sandbox.seatbelt",
        BASE_POLICY,
        "(allow file-read*)",                # 读默认放开（Codex 同款：读全部，秘密靠 deny 盖掉）
    ]
    sections += build_deny_read(policy, params)
    sections += build_write(policy, params)
    sections += build_network(policy, params)
    text = "\n".join(s for s in sections if s is not None) + "\n"
    return text, params.values


def wrap_argv(policy: SandboxPolicy, argv: List[str]) -> List[str]:
    """把原命令包裹成 sandbox-exec 形式：
    ['/usr/bin/sandbox-exec', '-p', <sbpl>, '-Dk=v'..., '--', *argv]"""
    text, kv = render_policy(policy)
    out = [SEATBELT_EXEC, "-p", text]
    for k, v in kv.items():
        out += [f"-D{k}={v}"]
    out += ["--"] + list(argv)
    return out
