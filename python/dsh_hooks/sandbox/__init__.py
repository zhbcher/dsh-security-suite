#!/usr/bin/env python3
"""dsh_hooks.sandbox — OS 级沙箱包裹（codex-parity-design.md M1/M2，Phase B）

平台路由：
  macOS  → seatbelt.py   /usr/bin/sandbox-exec 动态 sbpl（本方案主战场，已实测）
  Linux  → linux_bwrap.py bubblewrap 两阶段（实验性，未在真机验证）
  Windows→ win_stub.py   fail-closed：需要 deny_read 的任务直接拒绝执行

对外入口：
    from dsh_hooks.sandbox import load_policy, wrap_argv
    argv = wrap_argv(load_policy("~/.dsh/hooks-sandbox.json"), ["git", "push"])

CLI：
    dsh-hooks sandbox run [--policy P] -- <command...>
    dsh-hooks sandbox emit-policy [--policy P]     # 调试：打印生成的策略文本
"""
import os
import platform
import socket
import subprocess
import sys

from .policy import SandboxPolicy, load_policy          # noqa: F401


def _backend_for(policy: SandboxPolicy):
    system = platform.system()
    if system == "Darwin":
        from .seatbelt import wrap_argv as wrap
        return wrap
    if system == "Linux":
        from .linux_bwrap import wrap_argv as wrap
        return wrap
    # Windows / 其他：fail-closed —— 无法表达 deny_read 就拒绝裸跑
    if policy.deny_read:
        raise RuntimeError(
            f"Windows/未知平台({system})无法强制 deny_read 秘密禁读；"
            "按 fail-closed 原则拒绝沙箱化执行。如确认无秘密风险请去掉 deny_read 或手动运行。")
    raise RuntimeError(f"平台 {system} 暂不支持沙箱包裹（fail-closed）")


def wrap_argv(policy: SandboxPolicy, argv) -> list:
    return _backend_for(policy)(policy, list(argv))


# ── Phase E: 域名白名单审查代理的生命周期管理 ────────────────────────────────

_PROXY_PROC = None          # 本进程内复用;跨进程由 --tcp 端口幂等性保证


def proxy_env(policy: SandboxPolicy) -> dict:
    """restricted 模式的代理环境变量(HTTP_PROXY 等,大小写各一份)"""
    if policy.network.mode != "restricted" or not policy.network.proxy_ports:
        return {}
    p = policy.network.proxy_ports[0]
    url = f"http://127.0.0.1:{p}"
    out = {}
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        out[k] = url
        out[k.lower()] = url
    out["NO_PROXY"] = "localhost,127.0.0.1"
    out["no_proxy"] = "localhost,127.0.0.1"
    return out


def _port_listening(port: int) -> bool:
    """127.0.0.1:port 是否已有监听者(代理幂等复用的判据)"""
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ensure_proxy(policy: SandboxPolicy):
    """restricted+proxy_ports 时确保审查代理可用(幂等:端口已有监听则直接复用,
    这让每次独立的 CLI/任务进程都能安全调用)。返回 Popen 或 None(复用/不适用)。"""
    global _PROXY_PROC
    if policy.network.mode != "restricted" or not policy.network.proxy_ports:
        return None
    import time as _time
    port = policy.network.proxy_ports[0]
    if _port_listening(port):
        return _PROXY_PROC                     # 已有实例(可能来自其他进程),复用
    if _PROXY_PROC is not None and _PROXY_PROC.poll() is None:
        return _PROXY_PROC
    cmd = [sys.executable, "-m", "dsh_hooks.netproxy",
           "--tcp", f"127.0.0.1:{port}",
           "--policy", policy.source or ""]
    log_path = os.path.join(os.environ.get("DSH_HOME", os.path.expanduser("~/.dsh")),
                            "hooks", "netproxy.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as log:
        _PROXY_PROC = subprocess.Popen(cmd, stdout=log, stderr=log)
    for _ in range(20):                        # 最多等 4s 就绪
        _time.sleep(0.2)
        if _port_listening(port):
            return _PROXY_PROC
    raise RuntimeError("netproxy 启动失败,详见 ~/.dsh/hooks/netproxy.log")


def run(policy: SandboxPolicy, argv, timeout: float = None,
        env_extra: dict = None) -> int:
    """包裹并同步执行,返回子进程退出码。
    restricted 模式自动拉起审查代理并把 HTTP(S)_PROXY 注入子进程环境;
    Seatbelt 侧仅放行 localhost:<proxy_port> + DNS —— 物理上只有代理一条出网路。"""
    wrapped = wrap_argv(policy, argv)
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    pe = proxy_env(policy)
    if pe:
        ensure_proxy(policy)
        env.update(pe)
    return subprocess.run(wrapped, timeout=timeout, env=env).returncode


def emit_policy_text(policy: SandboxPolicy) -> str:
    """调试用：输出当前后端将使用的策略文本与参数表"""
    system = platform.system()
    if system == "Darwin":
        from .seatbelt import render_policy
        text, kv = render_policy(policy)
        for k, v in sorted(kv.items()):
            text += f"\n; -D{k}={v}"
        return text
    if system == "Linux":
        from .linux_bwrap import describe
        return describe(policy)
    return f"; 平台 {system}: fail-closed（无可渲染策略）"


if __name__ == "__main__":                       # python3 -m dsh_hooks.sandbox
    cli_main = None
    try:
        from .cli import main as cli_main
    except Exception:
        pass
    if cli_main is None:
        print("请通过 `dsh-hooks sandbox ...` 使用", file=sys.stderr)
        sys.exit(1)
