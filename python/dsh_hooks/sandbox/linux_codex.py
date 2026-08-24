#!/usr/bin/env python3
"""linux_codex.py — 复用 Codex 官方 codex-linux-sandbox 二进制的强制层(Phase E/B5)

为什么: codex-linux-sandbox(Apache-2.0,上游 openai/codex)自带我们 Python 无法
实现的内核级强制 —— seccomp syscall 白名单、capget 能力自检、NO_NEW_PRIVS、
fd mount 认证、ptrace/io_uring 恒禁。复用它 = Linux 强制层直接拉满到 Codex 同款。

CLI 契约(rust-v0.149.1):
    codex-linux-sandbox --permission-profile <JSON> --sandbox-policy-cwd <dir>
                        --command-cwd <dir> [--allow-network-for-proxy] -- <cmd...>
    permission-profile 由 dsh_hooks.sandbox.codex_profile.to_permission_profile() 生成

与域名白名单的关系(诚实声明):
    本后端的 network 只有 restricted(断网)/enabled(全开)两档;
    「域名级白名单」由 bwrap+UDS 地道方案(linux_bwrap.py)承担。
    两能力当前互斥,可用 policy.network.mode 选择:
      full        → codex(enabled)     # seccomp 强制 + 全网
      restricted  → bwrap+forwarder    # 域名白名单(实验性)
      disabled    → codex(restricted)  # seccomp 强制 + 断网
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

from .codex_profile import to_permission_profile
from .policy import SandboxPolicy


def find_sandbox_bin(explicit: str = None) -> str:
    """定位 codex-linux-sandbox 二进制: 显式路径 > env > 常见安装位"""
    candidates = [
        explicit or os.environ.get("DSH_CODEX_LINUX_SANDBOX", ""),
        "/usr/local/bin/codex-linux-sandbox",
        "/usr/bin/codex-linux-sandbox",
        str(Path.home() / ".local" / "bin" / "codex-linux-sandbox"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise RuntimeError(
        "找不到 codex-linux-sandbox 二进制。"
        "请从 GitHub Actions(build-codex-components)下载并放到 "
        "~/.local/bin/,或设 DSH_CODEX_LINUX_SANDBOX 环境变量")


def wrap_argv(policy: SandboxPolicy, argv: list, sandbox_bin: str = None,
              cwd: str = None) -> list:
    bin_path = find_sandbox_bin(sandbox_bin)
    cwd = cwd or os.getcwd()
    profile = json.dumps(to_permission_profile(policy), ensure_ascii=False)
    out = [bin_path,
           "--permission-profile", profile,
           "--sandbox-policy-cwd", cwd,
           "--command-cwd", cwd]
    if policy.network.mode == "full":
        pass                                    # 默认 enabled 语义
    elif policy.network.mode == "disabled":
        pass                                    # profile.network="restricted" 已表达
    else:                                       # restricted: 域名白名单不在本后端能力域
        raise RuntimeError(
            "codex-linux-sandbox 后端不支持 restricted 域名白名单;"
            "如需域名过滤请改用 bwrap+forwarder 方案,或接受 disabled/enabled 二档")
    out += ["--"] + list(argv)
    return out


def run(policy: SandboxPolicy, argv: list, timeout: float = None,
        cwd: str = None) -> int:
    return subprocess.run(wrap_argv(policy, argv, cwd=cwd),
                          timeout=timeout, cwd=cwd).returncode
