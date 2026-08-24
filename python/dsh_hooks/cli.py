#!/usr/bin/env python3
"""dsh-hooks 命令行入口"""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from .bus import HookBus, EVENTS
from .config import load_config


def cmd_emit(args):
    # M7 信任门：配置被篡改（modified）一律拒绝执行；untracked 放行但警告
    from . import trust as _trust
    from .config import load_options
    opts = load_options(args.config)
    cfg_path = args.config or opts.get("_path")
    if cfg_path and Path(cfg_path).exists():
        gate = _trust.enforce(cfg_path, require_trust=opts.get("require_trust", False))
        if not gate["allowed"]:
            print(f"✗ 配置信任门拦截: {gate['warning']}", file=sys.stderr)
            return 4
        if gate["warning"]:
            print(f"[dsh-hooks] {gate['warning']}", file=sys.stderr)

    bus = HookBus.from_config(args.config)
    raw = open(args.input).read() if args.input else sys.stdin.read()
    incoming = json.loads(raw) if raw.strip() else {}

    # 兼容两种输入：完整信封 {"event","data"} 或纯 data
    if isinstance(incoming, dict) and "data" in incoming:
        envelope = {"event": args.event,
                    "session": incoming.get("session") or {},
                    "data": incoming["data"]}
    else:
        envelope = {"event": args.event, "session": {}, "data": incoming}

    result = bus.emit(args.event, envelope["data"], envelope["session"])
    print(json.dumps({"allowed": result.allowed,
                      "reason": result.reason,
                      "data": result.data,
                      "trace": result.trace},
                     ensure_ascii=False, indent=2))
    if result.reason is None and not result.allowed:
        pass
    if not result.allowed:
        return 2
    return 0


def cmd_install_sentinels(args):
    """通用出口哨兵：按 hooks-egress.json 为所有渠道生成拦截 shim。"""
    from . import egress
    written = egress.generate_shims(args.config)
    sdir = egress.shim_dir_for()
    print(f"✓ 已生成 {len(written)} 个渠道出口哨兵（目录 {sdir}）：")
    for w in written:
        print(f"  {w}")
    print("\n生效方式：将 shim 目录前置到 Agent 进程的 PATH，")
    print("例如在网关/启动脚本中加入：")
    print(f'  export PATH="{sdir}:$PATH"')
    print("\n接入新聊天工具：编辑 hooks-egress.json 加一个渠道条目，"
          "重跑本命令即可。")
    return 0


def cmd_autodiscover(args):
    """自学习出口发现：扫描近期会话日志，自动为新外发渠道生成哨兵。"""
    from .autodiscover import discover_in_file
    from . import egress

    ws_dir = Path(args.sessions_dir)
    if not ws_dir.exists():
        print(f"✗ 会话目录不存在: {ws_dir}")
        return 1
    cutoff = time.time() - args.hours * 3600
    existing = {c["name"] for c in egress.load_channels()}
    found_all = {}
    scanned = 0
    for sess in ws_dir.glob("session-*/session.jsonl*"):
        if sess.stat().st_mtime < cutoff:
            continue
        try:
            found = discover_in_file(sess, known_channels=existing)
        except Exception as e:
            print(f"  (跳过 {sess.parent.name[:20]}: {e})")
            continue
        scanned += 1
        for binary, info in found.items():
            cur = found_all.setdefault(binary, {"file_flags": set(), "count": 0})
            cur["file_flags"].update(info["file_flags"])
            cur["count"] += info["count"]

    if not found_all:
        print(f"✓ 已扫描 {scanned} 个近期会话：未发现新的外发渠道")
        return 0
    print(f"⚠️ 发现 {len(found_all)} 个未受保护的外发渠道：")
    for name, info in sorted(found_all.items()):
        print(f"  {name:24} 出现{info['count']}次  flags={sorted(info['file_flags'])}")

    if not args.apply:
        print("\n（预览模式。加 --apply 自动纳管并生成哨兵）")
        return 0
    cfg_path = egress.egress_config_path()
    cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() \
        else {"channels": []}
    for name, info in found_all.items():
        cfg["channels"].append({"name": name, "real_path": "auto",
                                "file_flags": sorted(info["file_flags"])})
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    written = egress.generate_shims(str(cfg_path))
    print(f"\n✅ 已自动纳管并生成 {len(written)} 个出口哨兵，即刻生效。")
    return 0


def cmd_check(args):
    try:
        specs = load_config(args.config)
    except Exception as e:
        print(f"✗ 配置无效: {e}")
        return 1
    bus = HookBus.from_config(args.config)
    print(f"✓ 配置有效，共 {len(specs)} 个钩子注册：")
    for h in bus.describe():
        matcher = f" matcher={h['matcher']}" if h["matcher"] else ""
        print(f"  [{h['event']}] {h['name'] or '(unnamed)'}"
              f"{matcher} priority={h['priority']} ← {h['source']}")
    return 0


def cmd_self_test(_):
    """不依赖配置文件的内置演示：验证总线核心语义。"""
    from .bus import FuncHandler
    bus = HookBus()
    order = []
    bus.add_func("PreToolUse", lambda p: order.append("first") or {}, priority=10)
    bus.add_func("PreToolUse", lambda p: {"decision": "deny", "reason": "演示拦截"},
                 name="guard", priority=20)
    bus.add_func("PreToolUse", lambda p: order.append("never"), priority=30)
    r = bus.emit("PreToolUse", {"tool_name": "Bash"})
    assert not r.allowed and r.reason == "演示拦截" and order == ["first"]
    # 改写链
    bus2 = HookBus()
    bus2.add_func("UserPromptSubmit",
                  lambda p: {"decision": "rewrite",
                             "data": {**p["data"], "text": p["data"]["text"] + "✓"}})
    r2 = bus2.emit("UserPromptSubmit", {"text": "hello"})
    assert r2.data["text"] == "hello✓"
    print("✓ 自测通过：短路拦截 / 链式改写语义正常")
    return 0


def cmd_sandbox(args):
    """OS 沙箱子命令：run / emit-policy"""
    from . import sandbox
    if args.scmd == "emit-policy":
        pol = sandbox.load_policy(getattr(args, "policy", None))
        print(sandbox.emit_policy_text(pol))
        return 0
    cmd = [c for c in getattr(args, "command", []) if c != "--"]
    if not cmd:
        print("sandbox run 需要命令：dsh-hooks sandbox run -- <command...>", file=sys.stderr)
        return 1
    pol = sandbox.load_policy(args.policy)
    return sandbox.run(pol, cmd, timeout=args.timeout)


def cmd_trust(args):
    """M7: 显式信任当前 hooks 配置版本（sha256 指纹入库）"""
    from . import trust
    from .config import default_config_path
    path = args.config or str(default_config_path())
    st = status_out = None
    before = trust.status_of(path)
    r = trust.confirm(path)
    print(f"✓ 已信任 {path}")
    print(f"  指纹 {r['fingerprint'][:16]}…  （此前状态: {before['state']}）")
    return 0


def main(argv=None):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [dsh-hooks] %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="dsh-hooks",
                                 description="Agent 生命周期钩子总线")
    ap.add_argument("--config", help="hooks.json 路径（默认 $DSH_HOME/hooks.json）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("emit", help="触发一次事件（stdin 或 --input 提供 JSON）")
    p.add_argument("event", choices=EVENTS)
    p.add_argument("--input", help="载荷 JSON 文件（默认读 stdin）")

    p = sub.add_parser("check", help="校验 hooks.json 并列出钩子")

    p = sub.add_parser("install-sentinels",
                       help="为所有已配置渠道生成出口哨兵 shim")
    p.add_argument("--config", help="hooks-egress.json 路径（默认 $DSH_HOME/hooks-egress.json）")

    p = sub.add_parser("autodiscover",
                       help="扫描近期会话，自动发现未保护的外发渠道")
    p.add_argument("--hours", type=int, default=48, help="回看窗口（小时）")
    p.add_argument("--apply", action="store_true", help="自动纳管（默认仅预览）")
    p.add_argument("--sessions-dir",
                   default=str(Path(os.environ.get(
                       "DSH_HOME", os.path.expanduser("~/.dsh")))
                       / "sessions" / "--Users-zhoubo-deepseek--"),
                   help="会话日志目录")

    sub.add_parser("self-test", help="内置语义自测")

    p = sub.add_parser("sandbox", help="OS 沙箱包裹（macOS Seatbelt / Linux bwrap / 其他 fail-closed）")
    sp = p.add_subparsers(dest="scmd", required=True)
    pr = sp.add_parser("run", help="沙箱内执行命令")
    pr.add_argument("--policy", help="沙箱策略 JSON（默认 $DSH_HOME/hooks-sandbox.json）")
    pr.add_argument("--timeout", type=float, default=None, help="超时秒数")
    pr.add_argument("command", nargs=argparse.REMAINDER, help="-- 之后的原命令")
    pp = sp.add_parser("emit-policy", help="打印当前平台将使用的策略文本（调试）")
    pp.add_argument("--policy", help="沙箱策略 JSON")

    p = sub.add_parser("trust", help="显式信任当前 hooks.json（sha256 指纹，防篡改门）")
    p.add_argument("--config", help="hooks.json 路径（默认 $DSH_HOME/hooks.json）")

    args = ap.parse_args(argv)
    handlers = {"emit": cmd_emit, "check": cmd_check, "self-test": cmd_self_test,
                "install-sentinels": cmd_install_sentinels,
                "autodiscover": cmd_autodiscover,
                "sandbox": cmd_sandbox,
                "trust": cmd_trust}
    sys.exit(handlers[args.cmd](args))


if __name__ == "__main__":
    main()
