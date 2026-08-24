#!/usr/bin/env python3
"""linux_bwrap.py — Linux bubblewrap 两阶段包裹（实验性，未真机验证）

对齐 Codex linux-sandbox 的分层思路（report-sandboxing.md §2）：
  外层 bwrap：
    - --ro-bind / /          新只读根（或 --tmpfs / 更激进，此处取保守形态）
    - 分层 bind 重开可写根（writable_roots）
    - deny_read 命中的文件 → --tmpfs perms 000 盖住原路径（秘密不可读不可见）
      （bwrap 无 glob，逐条展开：glob 仅支持目录/** 形态与字面量）
    - --unshare-net          network.mode=disabled 时切断网络栈
    - --die-with-parent      父死子亡，防孤儿沙箱
  内层 seccomp（恒禁 ptrace 等）暂不实现——标注 TODO，先交付外层文件/网络边界。

fail-closed：bwrap 不存在、内核无用户命名空间时抛错而不是裸跑。
"""
import os
import shutil
import subprocess
from pathlib import Path

from .policy import SandboxPolicy


def _expand_glob_literal(pattern: str) -> list:
    """deny_read 条目 → 具体存在的路径列表（bwrap 需要具体路径做 tmpfs mask）"""
    base = pattern
    hits = []
    if "**" in base or "*" in base or "?" in base:
        root = base.split("*")[0].rstrip("/")
        root_dir = os.path.dirname(root) or "/"
        if os.path.isdir(root_dir):
            for p in Path(root_dir).rglob("*"):
                import fnmatch
                if fnmatch.fnmatch(str(p), base):
                    hits.append(str(p))
                    if len(hits) >= 256:                 # 上限防爆炸
                        break
    elif os.path.exists(base):
        hits.append(base)
    return hits


def build_bwrap_argv(policy: SandboxPolicy, argv: list, bwrap: str = "bwrap") -> list:
    out = [bwrap,
           "--ro-bind", "/", "/",
           "--dev", "/dev",
           "--proc", "/proc",
           "--die-with-parent",
           "--new-session"]

    # 可写根分层重开
    for r in policy.writable_roots:
        out += ["--bind", r.path, r.path]
        for e in r.exclude_literals:
            out += ["--ro-bind", e, e]                   # 排除项回盖为只读
        for e in r.exclude_subtrees:
            e = e.rstrip("/")
            if os.path.exists(e):
                out += ["--ro-bind", e, e]

    # 秘密 mask：deny_read 命中的路径用只读空文件盖住（读为空、写无效）；
    # 顶层专属秘密目录（如 ~/.ssh）整体 tmpfs 换成空盘（存在性都抹掉）
    for g in policy.deny_read:
        p = os.path.expanduser(g.replace("/**", "").rstrip("/"))
        if "*" in p or "?" in p:
            # 复杂 glob 展开成具体路径后逐个盖
            for hit in _expand_glob_literal(g):
                if os.path.isdir(hit):
                    out += ["--tmpfs", hit]
                else:
                    out += ["--ro-bind", "/dev/null", hit]
            continue
        if os.path.isdir(p):
            out += ["--tmpfs", p]
        elif os.path.isfile(p):
            out += ["--ro-bind", "/dev/null", p]

    if policy.network.mode == "disabled":
        out += ["--unshare-net"]
    elif policy.network.mode == "restricted":
        # Phase E ProxyOnly:unshare-net 物理断网;宿主代理的 UDS socket 文件
        # 经 bind-mount 递入(UDS 走文件系统,跨 netns 有效);沙箱内 forwarder
        # (dsh_hooks.netproxy forwarder)拉起 lo、把 127.0.0.1:<port> 的 TCP
        # 流量转进 UDS 地道后 exec 真实命令 —— Codex TCP→UDS→TCP 桥的 stdlib 等价物。
        uds_path = os.environ.get(
            "DSH_HOOKS_NETPROXY_UDS",
            str(Path(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh")))
                / "hooks" / "netproxy.sock"))
        if not os.path.exists(uds_path):
            raise RuntimeError(
                f"找不到代理 UDS {uds_path};请先启动审查代理:"
                "python3 -m dsh_hooks.netproxy --uds <path> --policy <policy>")
        out += ["--unshare-net", "--ro-bind", uds_path, uds_path]
        port = policy.network.proxy_ports[0] if policy.network.proxy_ports else 8888
        py = shutil.which("python3") or "/usr/bin/python3"
        fwd = [py, "-m", "dsh_hooks.netproxy", "forwarder",
               "--tcp", str(port), "--uds", uds_path, "--"]
        # PYTHONPATH 需让沙箱内 python 找到 dsh_hooks 包
        pkg_parent = str(Path(__file__).resolve().parent.parent.parent)
        out += ["--setenv", "PYTHONPATH",
                os.environ.get("PYTHONPATH", pkg_parent)]
        out += ["--"] + fwd + list(argv)
        return out

    out += ["--"] + list(argv)
    return out


def wrap_argv(policy: SandboxPolicy, argv: list) -> list:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError(
            "找不到 bubblewrap(bwrap)；fail-closed 原则下拒绝裸跑。安装: apt install bubblewrap")
    return build_bwrap_argv(policy, argv, bwrap)


def run(policy: SandboxPolicy, argv: list, timeout: float = None) -> int:
    return subprocess.run(wrap_argv(policy, argv), timeout=timeout).returncode


def describe(policy: SandboxPolicy) -> str:
    """调试输出将要执行的完整 argv"""
    return "\n".join(wrap_argv(policy, ["<command...>"]))
